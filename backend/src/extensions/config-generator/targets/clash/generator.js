import YAML from '@/utils/yaml';
import {
    ConfigGeneratorValidationError,
    validateProject,
} from '@/extensions/config-generator/validation';
import { resolvePolicyGroupCapability } from '@/extensions/config-generator/core/target-capabilities';
import {
    policyGroupCapabilityDiagnostics,
    projectIncludedPolicyGroups,
} from '@/extensions/config-generator/core/policy-group-projection';
import {
    createRemoteProxySourceContext,
    projectGroupRemoteProxySource,
    remoteProxySourceOutputUrl,
    remoteProxySourceWarning,
} from '@/extensions/config-generator/core/remote-proxy-source';
import { resolveRuleSetSource } from '@/extensions/config-generator/core/rule-set-source-resolver';
import { resolveRuleBindingResourceName } from '@/extensions/config-generator/core/rule-binding-name';
import { mergeNamedEntries } from '@/extensions/config-generator/core/named-entry-merge';
import { parseSurgeCsv } from '@/extensions/config-generator/targets/surge/serializer';

// Clash for Windows commonly uses one day when a provider does not declare
// its own refresh cadence. Keep the default explicit so generated profiles do
// not depend on client-version-specific behavior.
const DEFAULT_PROVIDER_INTERVAL = 86400;
const DEFAULT_HEALTH_CHECK_INTERVAL = 600;
const DEFAULT_TEST_URL = 'http://www.gstatic.com/generate_204';
const MANAGED_KEYS = new Set(['proxies', 'rule-providers', 'rules']);
const CLASH_RULE_TYPES = new Set([
    'DOMAIN',
    'DOMAIN-SUFFIX',
    'DOMAIN-KEYWORD',
    'IP-CIDR',
    'IP-CIDR6',
    'GEOIP',
    'PROCESS-NAME',
]);
const NO_RESOLVE_RULE_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'GEOIP']);
const CLASSIC_PROXY_TYPES = new Set([
    'ss',
    'ssr',
    'vmess',
    'vless',
    'socks5',
    'http',
    'snell',
    'trojan',
    'wireguard',
]);

function isObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function parseIndependentConfig(content, warnings) {
    if (typeof content !== 'string' || !content.trim()) return {};
    try {
        const parsed = YAML.safeLoad(content);
        if (parsed === null || parsed === undefined) return {};
        if (!isObject(parsed)) {
            warnings.push({
                path: 'outputs.clash.independentConfig',
                message:
                    'Clash independent configuration must be a YAML mapping; the invalid value was omitted.',
            });
            return {};
        }
        return parsed;
    } catch (error) {
        warnings.push({
            path: 'outputs.clash.independentConfig',
            message: `Clash independent configuration could not be parsed and was omitted: ${
                error.message || error
            }`,
        });
        return {};
    }
}

function safePathSegment(value, fallback) {
    const segment = `${value || ''}`
        .trim()
        .replace(/[\\/:*?"<>|\s]+/g, '-')
        .replace(/^\.+|\.+$/g, '')
        .replace(/-+/g, '-');
    return segment || fallback;
}

function allocateUnique(value, used, fallback) {
    const base = safePathSegment(value, fallback);
    let candidate = base;
    let index = 2;
    while (used.has(candidate.toLowerCase())) {
        candidate = `${base}-${index++}`;
    }
    used.add(candidate.toLowerCase());
    return candidate;
}

function compileRegex(value, path, warnings) {
    if (!value) return null;
    try {
        return new RegExp(value);
    } catch (_) {
        warnings.push({
            path,
            message:
                'The node-name regular expression is invalid and was omitted from Clash output.',
        });
        return null;
    }
}

function dedupe(values) {
    const seen = new Set();
    return values.filter((value) => {
        const key = `${value}`;
        if (!key || seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function warnClassicProxyCompatibility(proxies, path, warnings) {
    proxies.forEach((proxy, index) => {
        if (!isObject(proxy)) return;
        const type = `${proxy.type || ''}`.toLowerCase();
        if (!CLASSIC_PROXY_TYPES.has(type)) {
            warnings.push({
                path: `${path}[${index}].type`,
                message: `The ${
                    type || '(missing)'
                } proxy type may require Mihomo and is not portable to classic Clash; it was kept unchanged.`,
            });
        } else if (
            type === 'vless' &&
            (proxy.flow !== undefined || proxy['reality-opts'] !== undefined)
        ) {
            warnings.push({
                path: `${path}[${index}]`,
                message:
                    'VLESS flow/reality options require Mihomo and are not portable to classic Clash; the proxy was kept unchanged.',
            });
        }
    });
}

async function embeddedProxies(project, produceBuiltinArtifact, warnings) {
    if (!project.embeddedSource) return [];
    const proxies = await produceBuiltinArtifact({
        type: project.embeddedSource.type,
        name: project.embeddedSource.name,
        platform: 'Clash',
        produceType: 'internal',
        produceOpts: { 'delete-underscore-fields': true },
    });
    if (!Array.isArray(proxies)) {
        warnings.push({
            path: 'embeddedSource',
            message:
                'The embedded source did not produce an internal Clash proxy array and was omitted.',
        });
        return [];
    }
    return proxies.filter((proxy, index) => {
        if (isObject(proxy) && `${proxy.name || ''}`.trim()) return true;
        warnings.push({
            path: `embeddedSource.proxies[${index}]`,
            message:
                'An embedded Clash proxy without a valid name was omitted.',
        });
        return false;
    });
}

function warnUnsupportedGroupFields(group, warnings) {
    if (
        group.iconUrl ||
        group.targetOptions?.surge?.iconUrl ||
        group.targetOptions?.qx?.iconUrl
    ) {
        warnings.push({
            path: `groups.${group.name}.iconUrl`,
            message:
                'Classic Clash policy groups do not support group icons; the icon was omitted.',
        });
    }
    if (group.timeout !== undefined) {
        warnings.push({
            path: `groups.${group.name}.timeout`,
            message:
                'Classic Clash policy groups do not support the Surge timeout option; it was omitted.',
        });
    }
    if (group.targetOptions?.qx?.aliveChecking !== undefined) {
        warnings.push({
            path: `groups.${group.name}.targetOptions.qx.aliveChecking`,
            message:
                'Quantumult X alive-checking has no independent Clash equivalent; it was omitted.',
        });
    }
    if (group.targetOptions?.qx?.resourceTagRegex) {
        warnings.push({
            path: `groups.${group.name}.targetOptions.qx.resourceTagRegex`,
            message:
                'The raw Quantumult X resource-tag-regex cannot be represented by Clash and was omitted.',
        });
    }
    ['hidden', 'noAlert', 'evaluateBeforeUse', 'persistent'].forEach(
        (field) => {
            if (group.targetOptions?.surge?.[field] === undefined) return;
            warnings.push({
                path: `groups.${group.name}.targetOptions.surge.${field}`,
                message: `The Surge ${field} option has no Clash equivalent and was omitted.`,
            });
        },
    );
}

function generateGroups(project, localProxyNames, sourceContext, warnings) {
    const proxyProviders = {};
    const proxyGroups = [];
    const usedProviderNames = new Set();
    const usedProviderPaths = new Set();
    const providerVariants = new Map();
    const warnedSourceOptions = new Set();

    (project.groups || [])
        .filter((group) => !group.disabled)
        .forEach((group) => {
            const capability = resolvePolicyGroupCapability(
                'clash',
                group.type,
            );
            if (!capability) {
                warnings.push({
                    path: `groups.${group.name}`,
                    message: `Clash does not support the ${group.type} policy group type; the group was omitted.`,
                });
                return;
            }
            warnings.push(
                ...policyGroupCapabilityDiagnostics(group, capability),
            );

            const values = (group.members || []).map((member) => member.value);
            const includedGroups = projectIncludedPolicyGroups(
                group,
                capability,
                'clash',
            );
            values.push(...includedGroups.members);
            warnings.push(...includedGroups.diagnostics);

            const regex = compileRegex(
                group.nodeNameRegex,
                `groups.${group.name}.nodeNameRegex`,
                warnings,
            );
            if (group.includeAllProxies) {
                if (localProxyNames.length) {
                    values.push(
                        ...localProxyNames.filter(
                            (name) => !regex || regex.test(name),
                        ),
                    );
                } else {
                    warnings.push({
                        path: `groups.${group.name}.includeAllProxies`,
                        message:
                            'No embedded or preserved inline Clash proxies were available, so includeAllProxies added no members.',
                    });
                }
            }

            const use = [];
            const sourceProjection = projectGroupRemoteProxySource(
                group,
                'clash',
                sourceContext,
            );
            if (sourceProjection.status !== 'none') {
                if (sourceProjection.status === 'unsupported-field') {
                    warnings.push({
                        path: sourceProjection.path,
                        message: `Clash ${capability.outputType} does not support a remote proxy provider; it was omitted.`,
                    });
                } else if (
                    sourceProjection.status === 'missing' ||
                    sourceProjection.status === 'incompatible'
                ) {
                    warnings.push({
                        path: sourceProjection.path,
                        message: remoteProxySourceWarning(
                            sourceProjection,
                            'clash',
                        ),
                    });
                } else if (sourceProjection.status === 'disabled') {
                    warnings.push({
                        path: sourceProjection.path,
                        message:
                            'The Clash remote proxy source is disabled and was omitted.',
                    });
                } else if (sourceProjection.status === 'ready') {
                    if (
                        sourceProjection.source.targetOptions?.qx &&
                        !warnedSourceOptions.has(sourceProjection.source.name)
                    ) {
                        warnedSourceOptions.add(sourceProjection.source.name);
                        warnings.push({
                            path: `remoteProxySources.${sourceProjection.source.name}.targetOptions.qx`,
                            message:
                                'Quantumult X remote-source tag and parser options have no Clash equivalent and were omitted.',
                        });
                    }
                    const interval =
                        sourceProjection.source.targetOptions?.clash
                            ?.updateInterval ??
                        group.policyUpdateInterval ??
                        DEFAULT_PROVIDER_INTERVAL;
                    const providerDefinition = {
                        type: 'http',
                        url: remoteProxySourceOutputUrl(
                            sourceProjection.source,
                            'clash',
                            sourceContext,
                        ),
                        interval,
                        'health-check': {
                            enable: true,
                            url: group.testUrl || DEFAULT_TEST_URL,
                            interval:
                                group.interval ?? DEFAULT_HEALTH_CHECK_INTERVAL,
                        },
                    };
                    if (regex) {
                        providerDefinition.filter = group.nodeNameRegex;
                    }
                    const variantKey = JSON.stringify({
                        source: sourceProjection.source.name,
                        ...providerDefinition,
                    });
                    let providerName = providerVariants.get(variantKey);
                    if (!providerName) {
                        providerName = allocateUnique(
                            `${sourceProjection.source.name}-${group.name}`,
                            usedProviderNames,
                            'proxy-provider',
                        );
                        const providerPath = allocateUnique(
                            sourceProjection.source.name,
                            usedProviderPaths,
                            'proxy-provider',
                        );
                        proxyProviders[providerName] = {
                            ...providerDefinition,
                            path: `./providers/${providerPath}.yaml`,
                        };
                        providerVariants.set(variantKey, providerName);
                    }
                    use.push(providerName);
                }
            }
            if (!use.length && group.policyUpdateInterval !== undefined) {
                warnings.push({
                    path: `groups.${group.name}.policyUpdateInterval`,
                    message:
                        'Clash policyUpdateInterval only applies to a remote proxy provider; it was omitted because no compatible provider was emitted.',
                });
            }

            const output = {
                name: group.name,
                type: capability.outputType,
            };
            const proxies = dedupe(values);
            if (proxies.length) output.proxies = proxies;
            if (use.length) output.use = use;
            if (!proxies.length && !use.length) {
                throw new ConfigGeneratorValidationError([
                    {
                        path: `groups.${group.name}.members`,
                        message: `Clash ${capability.outputType} has no usable policy members or providers after target projection`,
                    },
                ]);
            }
            if (capability.outputType !== 'select') {
                output.url = group.testUrl || DEFAULT_TEST_URL;
                output.interval =
                    group.interval ?? DEFAULT_HEALTH_CHECK_INTERVAL;
            }
            if (
                capability.outputType === 'url-test' &&
                group.tolerance !== undefined
            ) {
                output.tolerance = group.tolerance;
            } else if (group.tolerance !== undefined) {
                warnings.push({
                    path: `groups.${group.name}.tolerance`,
                    message:
                        'Classic Clash tolerance is only supported by url-test groups; it was omitted.',
                });
            }
            const strategy = capability.targetDefaults?.strategy;
            if (strategy) output.strategy = strategy;
            warnUnsupportedGroupFields(group, warnings);
            proxyGroups.push(output);
        });

    return { proxyProviders, proxyGroups };
}

function ruleLine(type, value, policy, noResolve) {
    return [type, value, policy, ...(noResolve ? ['no-resolve'] : [])].join(
        ',',
    );
}

function parseSurgeRuleList(content, path, warnings) {
    const rules = [];
    `${content || ''}`.split(/\r?\n/).forEach((line, lineIndex) => {
        const trimmed = line.trim();
        if (
            !trimmed ||
            trimmed.startsWith('#') ||
            trimmed.startsWith(';') ||
            trimmed.startsWith('//') ||
            /^\[[^\]]+\]$/.test(trimmed)
        )
            return;

        let values;
        try {
            values = parseSurgeCsv(trimmed);
        } catch (error) {
            warnings.push({
                path: `${path}.lines[${lineIndex}]`,
                message: `The Surge rule-list line could not be parsed and was omitted: ${
                    error.message || error
                }`,
            });
            return;
        }

        const type = `${values[0] || ''}`.trim().toUpperCase();
        const value = `${values[1] || ''}`.trim();
        if (!CLASH_RULE_TYPES.has(type) || !value) {
            warnings.push({
                path: `${path}.lines[${lineIndex}]`,
                message: `Classic Clash cannot represent the Surge rule-list entry ${
                    type || '(empty)'
                }; it was omitted from the inline fallback.`,
            });
            return;
        }

        const requestedNoResolve = values
            .slice(2)
            .some((value) => `${value}`.trim().toLowerCase() === 'no-resolve');
        const noResolve = requestedNoResolve && NO_RESOLVE_RULE_TYPES.has(type);
        if (requestedNoResolve && !noResolve) {
            warnings.push({
                path: `${path}.lines[${lineIndex}]`,
                message: `Clash no-resolve is not valid for ${type}; it was omitted.`,
            });
        }
        rules.push({ type, value, noResolve });
    });
    return rules;
}

async function generateRules(project, ruleSets, warnings, downloadRuleSet) {
    const byName = new Map(ruleSets.map((item) => [item.name, item]));
    const ruleProviders = {};
    const rules = [];
    const providersByRuleSet = new Map();
    const convertedRuleSets = new Map();
    const usedProviderNames = new Set();
    const usedProviderPaths = new Set();

    const projectRules = project.rules || [];
    for (let index = 0; index < projectRules.length; index++) {
        const rule = projectRules[index];
        if (rule.disabled) continue;
        if (rule.kind === 'comment' || rule.kind === 'blank') {
            warnings.push({
                path: `rules[${index}]`,
                message:
                    'Clash YAML cannot preserve this shared comment or blank rule position safely; it was omitted.',
            });
            continue;
        }
        if (rule.kind === 'final') {
            rules.push(`MATCH,${rule.policy}`);
            continue;
        }
        if (rule.kind === 'inline') {
            if (!CLASH_RULE_TYPES.has(rule.type)) {
                warnings.push({
                    path: `rules.${rule.type}`,
                    message: `Classic Clash does not support the portable ${rule.type} rule type; it was omitted.`,
                });
                continue;
            }
            const noResolve = Boolean(
                rule.noResolve && NO_RESOLVE_RULE_TYPES.has(rule.type),
            );
            if (rule.noResolve && !noResolve) {
                warnings.push({
                    path: `rules[${index}].noResolve`,
                    message: `Clash no-resolve is not valid for ${rule.type}; it was omitted.`,
                });
            }
            rules.push(ruleLine(rule.type, rule.value, rule.policy, noResolve));
            continue;
        }
        if (rule.kind !== 'remote') continue;
        const ruleSet = byName.get(rule.ruleSet);
        if (!ruleSet || ruleSet.enabled === false) continue;
        const resolution = resolveRuleSetSource(ruleSet, 'clash');
        if (resolution.kind === 'unsupported') {
            warnings.push({
                path: `rules.${rule.ruleSet}`,
                message:
                    resolution.warning?.message ||
                    'Clash cannot represent this rule-set source.',
            });
            continue;
        }
        if (resolution.warning) {
            warnings.push({
                path:
                    resolution.kind === 'remote-url'
                        ? `rules.${rule.ruleSet}.source.url`
                        : `rules.${rule.ruleSet}`,
                message: resolution.warning.message,
            });
        }
        if (resolution.kind === 'inline-rules') {
            resolution.rules.forEach((item) => {
                if (!CLASH_RULE_TYPES.has(item.type)) return;
                rules.push(
                    ruleLine(
                        item.type,
                        item.value,
                        rule.policy,
                        Boolean(item.noResolve),
                    ),
                );
            });
            continue;
        }
        if (resolution.kind !== 'remote-url' || !resolution.url) continue;

        if (resolution.inlineConversion === 'surge-rule-list') {
            let converted = convertedRuleSets.get(ruleSet.name);
            if (!converted) {
                if (typeof downloadRuleSet !== 'function') {
                    throw new ConfigGeneratorValidationError([
                        {
                            path: `rules[${index}].ruleSet`,
                            message:
                                'The custom Surge rule list requires the Sub-Store cached downloader before it can be converted for Clash.',
                        },
                    ]);
                }
                let content;
                try {
                    content = await downloadRuleSet(resolution.url);
                } catch (error) {
                    throw new ConfigGeneratorValidationError([
                        {
                            path: `rules[${index}].ruleSet`,
                            message: `The custom Surge rule list could not be downloaded for Clash conversion: ${
                                error.message || error
                            }`,
                        },
                    ]);
                }
                converted = parseSurgeRuleList(
                    content,
                    `rules.${rule.ruleSet}.source.url`,
                    warnings,
                );
                if (!converted.length) {
                    throw new ConfigGeneratorValidationError([
                        {
                            path: `rules[${index}].ruleSet`,
                            message:
                                'The custom Surge rule list did not contain any rules that classic Clash can represent.',
                        },
                    ]);
                }
                convertedRuleSets.set(ruleSet.name, converted);
            }
            converted.forEach((item) => {
                rules.push(
                    ruleLine(
                        item.type,
                        item.value,
                        rule.policy,
                        item.noResolve,
                    ),
                );
            });
            if (rule.noResolve) {
                warnings.push({
                    path: `rules[${index}].noResolve`,
                    message:
                        'The shared RULE-SET no-resolve option was omitted; no-resolve flags declared inside the downloaded rule list were preserved where Clash supports them.',
                });
            }
            continue;
        }

        if (ruleSet.targetOptions?.qx?.optParser !== undefined) {
            warnings.push({
                path: `rules.${rule.ruleSet}.targetOptions.qx.optParser`,
                message:
                    'Quantumult X opt-parser has no Clash rule-provider equivalent and was omitted.',
            });
        }

        let providerName = providersByRuleSet.get(ruleSet.name);
        if (!providerName) {
            providerName = allocateUnique(
                resolveRuleBindingResourceName(rule, ruleSet),
                usedProviderNames,
                'rule-provider',
            );
            const providerPath = allocateUnique(
                ruleSet.name,
                usedProviderPaths,
                'rule-provider',
            );
            ruleProviders[providerName] = {
                type: 'http',
                behavior: 'classical',
                url: resolution.url,
                path: `./rules/${providerPath}.yaml`,
                interval: ruleSet.updateInterval ?? DEFAULT_PROVIDER_INTERVAL,
            };
            providersByRuleSet.set(ruleSet.name, providerName);
        }
        if (rule.noResolve) {
            warnings.push({
                path: `rules[${index}].noResolve`,
                message:
                    'Clash RULE-SET rules do not support the shared no-resolve option; it was omitted.',
            });
        }
        rules.push(`RULE-SET,${providerName},${rule.policy}`);
    }

    return { ruleProviders, rules };
}

function mergeConfig(
    independentConfig,
    generatedProxies,
    proxyProviders,
    proxyGroups,
    ruleProviders,
    rules,
    hasEmbeddedSource,
    warnings,
) {
    const base = { ...independentConfig };
    const preservedProxies = Array.isArray(base.proxies) ? base.proxies : [];
    if (base.proxies !== undefined && !Array.isArray(base.proxies)) {
        warnings.push({
            path: 'outputs.clash.independentConfig.proxies',
            message:
                'The independent Clash proxies field was not an array and was omitted.',
        });
    }
    if (hasEmbeddedSource && preservedProxies.length) {
        warnings.push({
            path: 'outputs.clash.independentConfig.proxies',
            message:
                'Embedded proxies replace independent Clash proxies to avoid duplicate node definitions.',
        });
    }
    const preservedProxyGroups = Array.isArray(base['proxy-groups'])
        ? base['proxy-groups']
        : [];
    if (
        base['proxy-groups'] !== undefined &&
        !Array.isArray(base['proxy-groups'])
    ) {
        warnings.push({
            path: 'outputs.clash.independentConfig.proxy-groups',
            message:
                'The independent Clash proxy-groups field was not an array and was omitted.',
        });
    }
    const preservedProxyProviders = isObject(base['proxy-providers'])
        ? base['proxy-providers']
        : {};
    if (
        base['proxy-providers'] !== undefined &&
        !isObject(base['proxy-providers'])
    ) {
        warnings.push({
            path: 'outputs.clash.independentConfig.proxy-providers',
            message:
                'The independent Clash proxy-providers field was not a mapping and was omitted.',
        });
    }
    for (const key of MANAGED_KEYS) {
        if (key !== 'proxies' && base[key] !== undefined) {
            warnings.push({
                path: `outputs.clash.independentConfig.${key}`,
                message: `The independent Clash ${key} field is managed by the configuration generator and was replaced.`,
            });
        }
        delete base[key];
    }
    const mergedProxyGroups = mergeNamedEntries(
        preservedProxyGroups,
        proxyGroups,
        (group) =>
            isObject(group) && typeof group.name === 'string' && group.name
                ? group.name
                : undefined,
    );
    // Keep provider definitions used by retained hand-authored groups. A
    // generated provider with the same key intentionally wins while unrelated
    // independent providers retain their original order and configuration.
    const mergedProxyProviders = {
        ...preservedProxyProviders,
        ...proxyProviders,
    };
    return {
        ...base,
        proxies: hasEmbeddedSource ? generatedProxies : preservedProxies,
        'proxy-providers': mergedProxyProviders,
        'proxy-groups': mergedProxyGroups,
        'rule-providers': ruleProviders,
        rules,
    };
}

export async function generateClashConfig({
    project,
    ruleSets,
    produceBuiltinArtifact,
    downloadRuleSet,
}) {
    validateProject(project, ruleSets, 'clash');
    const warnings = [];
    const clash = project.outputs?.clash || {};
    const independent = parseIndependentConfig(
        clash.independentConfig,
        warnings,
    );
    const generatedProxies = await embeddedProxies(
        project,
        produceBuiltinArtifact,
        warnings,
    );
    const preservedProxies = Array.isArray(independent.proxies)
        ? independent.proxies.filter((proxy) => isObject(proxy) && proxy.name)
        : [];
    const outputProxies = project.embeddedSource
        ? generatedProxies
        : preservedProxies;
    if (!project.embeddedSource) {
        warnClassicProxyCompatibility(
            outputProxies,
            'outputs.clash.independentConfig.proxies',
            warnings,
        );
    }
    const localProxyNames = outputProxies.map((proxy) => `${proxy.name}`);
    const sourceContext = createRemoteProxySourceContext(project);
    const { proxyProviders, proxyGroups } = generateGroups(
        project,
        localProxyNames,
        sourceContext,
        warnings,
    );
    const { ruleProviders, rules } = await generateRules(
        project,
        ruleSets,
        warnings,
        downloadRuleSet,
    );
    const config = mergeConfig(
        independent,
        generatedProxies,
        proxyProviders,
        proxyGroups,
        ruleProviders,
        rules,
        Boolean(project.embeddedSource),
        warnings,
    );

    return {
        body: YAML.safeDump(config, { lineWidth: 0, noRefs: true }),
        sourceRevision: project.revision,
        stats: {
            nodeCount: config.proxies.length,
            groupCount: proxyGroups.length,
            ruleCount: rules.length,
        },
        warnings,
        errors: [],
    };
}

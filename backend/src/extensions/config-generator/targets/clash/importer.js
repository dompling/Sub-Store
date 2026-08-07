import YAML from '@/utils/yaml';
import {
    createTargetOutputs,
    getSharedPolicyGroupType,
} from '../../core/target-capabilities';
import { matchingSubStoreSource } from '../../core/sub-store-source';

const MANAGED_KEYS = new Set([
    'proxy-providers',
    'proxy-groups',
    'rule-providers',
    'rules',
]);
const PORTABLE_RULE_TYPES = new Set([
    'DOMAIN',
    'DOMAIN-SUFFIX',
    'DOMAIN-KEYWORD',
    'IP-CIDR',
    'IP-CIDR6',
    'GEOIP',
    'PROCESS-NAME',
]);
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
const GROUP_FIELDS = new Set([
    'name',
    'type',
    'proxies',
    'use',
    'url',
    'interval',
    'tolerance',
    'strategy',
]);
const PROXY_PROVIDER_FIELDS = new Set([
    'type',
    'url',
    'interval',
    'path',
    'filter',
    'health-check',
]);
const RULE_PROVIDER_FIELDS = new Set([
    'type',
    'behavior',
    'url',
    'path',
    'interval',
    'format',
]);

function isObject(value) {
    return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function isHttpUrl(value) {
    try {
        const url = new URL(value);
        return ['http:', 'https:'].includes(url.protocol);
    } catch (_) {
        return false;
    }
}

function uniqueName(base, used) {
    let name = `${base || ''}`.trim() || `item-${used.size + 1}`;
    let index = 2;
    const original = name;
    while (used.has(name)) name = `${original}-${index++}`;
    used.add(name);
    return name;
}

function parseConfig(content) {
    const parsed = YAML.safeLoad(`${content || ''}`);
    if (parsed === null || parsed === undefined) return {};
    if (!isObject(parsed)) {
        throw new Error('Clash configuration must be a YAML mapping');
    }
    return parsed;
}

function importProxyProviders(config, warnings, sourceContext) {
    const sources = [];
    const providers = new Map();
    const usedNames = new Set();
    const rawProviders = config['proxy-providers'];
    if (rawProviders === undefined) return { sources, providers };
    if (!isObject(rawProviders)) {
        warnings.push({
            path: 'proxy-providers',
            message:
                'Clash proxy-providers must be a mapping and were omitted.',
        });
        return { sources, providers };
    }

    Object.entries(rawProviders).forEach(([providerName, provider]) => {
        if (
            !isObject(provider) ||
            `${provider.type || ''}`.toLowerCase() !== 'http' ||
            !isHttpUrl(provider.url)
        ) {
            warnings.push({
                path: `proxy-providers.${providerName}`,
                message:
                    'Only Clash HTTP proxy providers with an HTTP(S) URL can be imported; this provider was omitted.',
            });
            return;
        }
        const sourceName = uniqueName(providerName, usedNames);
        const native = matchingSubStoreSource(provider.url, sourceContext);
        const source = native
            ? { ...native, name: sourceName, source: { ...native.source } }
            : {
                  name: sourceName,
                  source: {
                      kind: 'url',
                      url: provider.url,
                      mode: 'passthrough',
                      target: 'clash',
                  },
              };
        if (Number.isInteger(provider.interval) && provider.interval > 0) {
            source.targetOptions = {
                ...(source.targetOptions || {}),
                clash: {
                    ...(source.targetOptions?.clash || {}),
                    updateInterval: provider.interval,
                },
            };
        } else if (provider.interval !== undefined) {
            warnings.push({
                path: `proxy-providers.${providerName}.interval`,
                message:
                    'The Clash proxy provider interval must be a positive integer and was omitted.',
            });
        }
        if (!native) {
            warnings.push({
                path: `proxy-providers.${providerName}.url`,
                message:
                    'This proxy provider URL is bound to Clash. Select a Sub-Store source to reuse it for another target.',
            });
        }
        const healthCheck = isObject(provider['health-check'])
            ? provider['health-check']
            : {};
        if (
            provider['health-check'] !== undefined &&
            !isObject(provider['health-check'])
        ) {
            warnings.push({
                path: `proxy-providers.${providerName}.health-check`,
                message:
                    'The Clash provider health-check field was not a mapping and was omitted.',
            });
        }
        if (healthCheck.enable === false) {
            warnings.push({
                path: `proxy-providers.${providerName}.health-check.enable`,
                message:
                    'Disabled Clash provider health checks have no shared-model equivalent; generation will enable the health check.',
            });
        }
        if (
            healthCheck.interval !== undefined &&
            (!Number.isInteger(healthCheck.interval) ||
                healthCheck.interval <= 0)
        ) {
            warnings.push({
                path: `proxy-providers.${providerName}.health-check.interval`,
                message:
                    'The Clash provider health-check interval must be a positive integer and was omitted.',
            });
        }
        Object.keys(provider).forEach((field) => {
            if (PROXY_PROVIDER_FIELDS.has(field)) return;
            warnings.push({
                path: `proxy-providers.${providerName}.${field}`,
                message: `The Clash ${field} proxy-provider option is target-specific and was omitted from the shared model.`,
            });
        });
        sources.push(source);
        providers.set(providerName, {
            sourceName,
            filter:
                typeof provider.filter === 'string'
                    ? provider.filter
                    : undefined,
            testUrl:
                typeof healthCheck.url === 'string' && healthCheck.url.trim()
                    ? healthCheck.url
                    : undefined,
            healthCheckInterval:
                Number.isInteger(healthCheck.interval) &&
                healthCheck.interval > 0
                    ? healthCheck.interval
                    : undefined,
        });
    });
    return { sources, providers };
}

function sharedGroupType(group) {
    const outputType = `${group.type || ''}`.toLowerCase();
    if (outputType !== 'load-balance') {
        return getSharedPolicyGroupType('clash', outputType);
    }
    const strategy = `${group.strategy || ''}`.toLowerCase();
    if (strategy === 'round-robin') return 'round-robin';
    if (strategy === 'consistent-hashing') return 'dest-hash';
    return 'load-balance';
}

function importGroups(config, providers, proxyNames, warnings) {
    const rawGroups = config['proxy-groups'];
    if (rawGroups === undefined) return [];
    if (!Array.isArray(rawGroups)) {
        warnings.push({
            path: 'proxy-groups',
            message: 'Clash proxy-groups must be an array and were omitted.',
        });
        return [];
    }

    const groups = [];
    const usedNames = new Set();
    rawGroups.forEach((rawGroup, index) => {
        if (!isObject(rawGroup) || !`${rawGroup.name || ''}`.trim()) {
            warnings.push({
                path: `proxy-groups[${index}]`,
                message:
                    'A Clash proxy group without a valid name was omitted.',
            });
            return;
        }
        const name = uniqueName(rawGroup.name, usedNames);
        const type = sharedGroupType(rawGroup);
        if (!type) {
            warnings.push({
                path: `proxy-groups.${name}.type`,
                message: `Unsupported Clash proxy group type: ${
                    rawGroup.type || '(missing)'
                }`,
            });
            return;
        }
        if (`${rawGroup.type || ''}`.toLowerCase() === 'load-balance') {
            const strategy = `${rawGroup.strategy || ''}`.toLowerCase();
            if (strategy === 'round-robin') {
                warnings.push({
                    path: `proxy-groups.${name}.strategy`,
                    message:
                        'Clash round-robin load-balance was mapped to the shared round-robin type; targets without strict rotation may approximate it.',
                });
            } else if (strategy === 'consistent-hashing') {
                warnings.push({
                    path: `proxy-groups.${name}.strategy`,
                    message:
                        'Clash consistent-hashing was mapped to the shared dest-hash type; exact hashing details may differ across targets.',
                });
            } else if (strategy) {
                warnings.push({
                    path: `proxy-groups.${name}.strategy`,
                    message: `The Clash ${strategy} load-balance strategy has no shared equivalent; it was approximated as consistent-hashing.`,
                });
            } else {
                warnings.push({
                    path: `proxy-groups.${name}.type`,
                    message:
                        'Classic Clash load-balance was mapped to shared load-balance as an approximation; generation makes consistent-hashing explicit.',
                });
            }
        }
        const rawMembers = Array.isArray(rawGroup.proxies)
            ? rawGroup.proxies
            : [];
        if (
            rawGroup.proxies !== undefined &&
            !Array.isArray(rawGroup.proxies)
        ) {
            warnings.push({
                path: `proxy-groups.${name}.proxies`,
                message:
                    'The Clash proxy group proxies field was not an array and was omitted.',
            });
        }
        const group = {
            name,
            type,
            members: rawMembers
                .filter((value) => typeof value === 'string' && value.trim())
                .map((value) => ({ kind: 'proxy', value })),
        };
        const uses = Array.isArray(rawGroup.use)
            ? rawGroup.use.filter(
                  (value) => typeof value === 'string' && value.trim(),
              )
            : [];
        if (rawGroup.use !== undefined && !Array.isArray(rawGroup.use)) {
            warnings.push({
                path: `proxy-groups.${name}.use`,
                message:
                    'The Clash proxy group use field was not an array and was omitted.',
            });
        }
        const knownUses = uses.filter((provider) => providers.has(provider));
        uses.filter((provider) => !providers.has(provider)).forEach(
            (provider) => {
                warnings.push({
                    path: `proxy-groups.${name}.use`,
                    message: `The referenced Clash proxy provider ${provider} could not be imported and was omitted.`,
                });
            },
        );
        if (knownUses.length) {
            const provider = providers.get(knownUses[0]);
            group.remoteProxySource = provider.sourceName;
            if (provider.filter) group.nodeNameRegex = provider.filter;
            if (provider.testUrl) group.testUrl = provider.testUrl;
            if (provider.healthCheckInterval) {
                group.interval = provider.healthCheckInterval;
            }
            if (knownUses.length > 1) {
                warnings.push({
                    path: `proxy-groups.${name}.use`,
                    message:
                        'The shared project model supports one remote proxy source per group; only the first Clash provider was imported.',
                });
            }
        }
        if (!group.members.length && !knownUses.length) {
            warnings.push({
                path: `proxy-groups.${name}`,
                message:
                    'The Clash policy group has no imported proxies or providers and must be completed before generation.',
            });
        }
        if (typeof rawGroup.url === 'string' && rawGroup.url.trim()) {
            group.testUrl = rawGroup.url;
        }
        if (Number.isInteger(rawGroup.interval) && rawGroup.interval > 0) {
            group.interval = rawGroup.interval;
        } else if (rawGroup.interval !== undefined) {
            warnings.push({
                path: `proxy-groups.${name}.interval`,
                message:
                    'The Clash policy group interval must be a positive integer and was omitted.',
            });
        }
        if (Number.isInteger(rawGroup.tolerance) && rawGroup.tolerance >= 0) {
            group.tolerance = rawGroup.tolerance;
        } else if (rawGroup.tolerance !== undefined) {
            warnings.push({
                path: `proxy-groups.${name}.tolerance`,
                message:
                    'The Clash url-test tolerance must be a non-negative integer and was omitted.',
            });
        }
        Object.keys(rawGroup).forEach((field) => {
            if (GROUP_FIELDS.has(field)) return;
            warnings.push({
                path: `proxy-groups.${name}.${field}`,
                message: `The Clash ${field} policy-group option is target-specific and was omitted from the shared model.`,
            });
        });
        groups.push(group);
    });

    const groupNames = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    groups.forEach((group) => {
        group.members = group.members.map((member) => {
            const value = `${member.value}`;
            const builtin = value.toUpperCase();
            if (['DIRECT', 'REJECT'].includes(builtin)) {
                return { kind: 'builtin', value: builtin };
            }
            const referencedGroup = groupNames.get(value.toLowerCase());
            if (referencedGroup) {
                return { kind: 'group', value: referencedGroup };
            }
            return {
                kind: 'proxy',
                value: proxyNames.get(value.toLowerCase()) || value,
            };
        });
    });
    return groups;
}

function importRuleProviders(config, warnings) {
    const ruleSets = [];
    const providers = new Map();
    const usedNames = new Set();
    const rawProviders = config['rule-providers'];
    if (rawProviders === undefined) return { ruleSets, providers };
    if (!isObject(rawProviders)) {
        warnings.push({
            path: 'rule-providers',
            message: 'Clash rule-providers must be a mapping and were omitted.',
        });
        return { ruleSets, providers };
    }

    Object.entries(rawProviders).forEach(([providerName, provider]) => {
        if (
            !isObject(provider) ||
            `${provider.type || ''}`.toLowerCase() !== 'http' ||
            !isHttpUrl(provider.url)
        ) {
            warnings.push({
                path: `rule-providers.${providerName}`,
                message:
                    'Only Clash HTTP rule providers with an HTTP(S) URL can be imported; this provider was omitted.',
            });
            return;
        }
        if (
            provider.behavior !== undefined &&
            `${provider.behavior}`.toLowerCase() !== 'classical'
        ) {
            warnings.push({
                path: `rule-providers.${providerName}.behavior`,
                message:
                    'Only classical Clash rule providers map safely to the shared rule-set model; this provider was omitted.',
            });
            return;
        }
        const name = uniqueName(providerName, usedNames);
        const ruleSet = {
            name,
            source: { kind: 'url', url: provider.url, target: 'clash' },
        };
        if (Number.isInteger(provider.interval) && provider.interval > 0) {
            ruleSet.updateInterval = provider.interval;
        } else if (provider.interval !== undefined) {
            warnings.push({
                path: `rule-providers.${providerName}.interval`,
                message:
                    'The Clash rule provider interval must be a positive integer and was omitted.',
            });
        }
        if (
            provider.format !== undefined &&
            `${provider.format}`.toLowerCase() !== 'yaml'
        ) {
            warnings.push({
                path: `rule-providers.${providerName}.format`,
                message:
                    'The Clash rule provider format is target-specific; generation will use classical YAML.',
            });
        }
        Object.keys(provider).forEach((field) => {
            if (RULE_PROVIDER_FIELDS.has(field)) return;
            warnings.push({
                path: `rule-providers.${providerName}.${field}`,
                message: `The Clash ${field} rule-provider option is target-specific and was omitted from the shared model.`,
            });
        });
        ruleSets.push(ruleSet);
        providers.set(providerName, name);
    });
    return { ruleSets, providers };
}

function normalizePolicy(policy, groupNames) {
    const value = `${policy || ''}`.trim();
    const builtin = value.toUpperCase();
    if (['DIRECT', 'REJECT'].includes(builtin)) return builtin;
    return groupNames.get(value.toLowerCase()) || value;
}

function importedPolicy(policy, groupNames, path, warnings) {
    const normalized = normalizePolicy(policy, groupNames);
    if (
        ['DIRECT', 'REJECT'].includes(normalized) ||
        groupNames.has(`${normalized}`.toLowerCase())
    ) {
        return normalized;
    }
    warnings.push({
        path,
        message: `The Clash policy ${
            normalized || '(missing)'
        } is not an imported policy group or portable built-in; the rule was omitted.`,
    });
    return null;
}

function importRules(config, providers, groups, warnings) {
    const rawRules = config.rules;
    if (rawRules === undefined) return [];
    if (!Array.isArray(rawRules)) {
        warnings.push({
            path: 'rules',
            message: 'Clash rules must be an array and were omitted.',
        });
        return [];
    }
    const groupNames = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    let finalSeen = false;
    return rawRules.flatMap((rawRule, index) => {
        if (finalSeen) {
            warnings.push({
                path: `rules[${index}]`,
                message:
                    'This Clash rule follows MATCH and is unreachable; it was omitted to keep the shared rule model valid.',
            });
            return [];
        }
        if (typeof rawRule !== 'string' || !rawRule.trim()) {
            warnings.push({
                path: `rules[${index}]`,
                message: 'A non-string Clash rule was omitted.',
            });
            return [];
        }
        const values = rawRule.split(',').map((value) => value.trim());
        const type = `${values.shift() || ''}`.toUpperCase();
        if (['MATCH', 'FINAL'].includes(type) && values[0]) {
            const policy = importedPolicy(
                values[0],
                groupNames,
                `rules[${index}]`,
                warnings,
            );
            if (!policy) return [];
            finalSeen = true;
            return [
                {
                    kind: 'final',
                    policy,
                },
            ];
        }
        if (type === 'RULE-SET' && values[0] && values[1]) {
            const ruleSet = providers.get(values[0]);
            if (!ruleSet) {
                warnings.push({
                    path: `rules[${index}]`,
                    message: `The Clash rule provider ${values[0]} could not be imported; the rule was omitted.`,
                });
                return [];
            }
            const policy = importedPolicy(
                values[1],
                groupNames,
                `rules[${index}]`,
                warnings,
            );
            if (!policy) return [];
            return [
                {
                    kind: 'remote',
                    name: values[0],
                    ruleSet,
                    policy,
                    ...(values.includes('no-resolve')
                        ? { noResolve: true }
                        : {}),
                },
            ];
        }
        if (PORTABLE_RULE_TYPES.has(type) && values[0] && values[1]) {
            const policy = importedPolicy(
                values[1],
                groupNames,
                `rules[${index}]`,
                warnings,
            );
            if (!policy) return [];
            return [
                {
                    kind: 'inline',
                    type,
                    value: values[0],
                    policy,
                    ...(values.includes('no-resolve')
                        ? { noResolve: true }
                        : {}),
                },
            ];
        }
        warnings.push({
            path: `rules[${index}]`,
            message: `Unsupported Clash rule: ${rawRule}`,
        });
        return [];
    });
}

function independentConfig(config, warnings) {
    const independent = { ...config };
    MANAGED_KEYS.forEach((key) => delete independent[key]);
    if (
        independent.proxies !== undefined &&
        !Array.isArray(independent.proxies)
    ) {
        warnings.push({
            path: 'proxies',
            message:
                'The Clash proxies field was not an array; it was preserved in target-specific configuration but cannot be managed as embedded nodes.',
        });
    }
    return YAML.safeDump(independent, { lineWidth: 0, noRefs: true });
}

export function importClashConfig(content, sourceContext = {}) {
    const config = parseConfig(content);
    const warnings = [];
    const inlineProxies = Array.isArray(config.proxies)
        ? config.proxies.filter((proxy, index) => {
              if (isObject(proxy) && `${proxy.name || ''}`.trim()) return true;
              warnings.push({
                  path: `proxies[${index}]`,
                  message:
                      'An inline Clash proxy without a valid name was preserved in independent configuration but cannot be selected in the shared group editor.',
              });
              return false;
          })
        : [];
    const proxyNames = new Map(
        inlineProxies.map((proxy) => [
            `${proxy.name}`.toLowerCase(),
            `${proxy.name}`,
        ]),
    );
    inlineProxies.forEach((proxy, index) => {
        const type = `${proxy.type || ''}`.toLowerCase();
        if (!CLASSIC_PROXY_TYPES.has(type)) {
            warnings.push({
                path: `proxies[${index}].type`,
                message: `The ${
                    type || '(missing)'
                } proxy type may require Mihomo and is not portable to classic Clash; the inline definition was preserved unchanged.`,
            });
        } else if (
            type === 'vless' &&
            (proxy.flow !== undefined || proxy['reality-opts'] !== undefined)
        ) {
            warnings.push({
                path: `proxies[${index}]`,
                message:
                    'VLESS flow/reality options require Mihomo and are not portable to classic Clash; the inline definition was preserved unchanged.',
            });
        }
    });
    const { sources, providers: proxyProviders } = importProxyProviders(
        config,
        warnings,
        sourceContext,
    );
    const groups = importGroups(config, proxyProviders, proxyNames, warnings);
    const { ruleSets, providers: ruleProviders } = importRuleProviders(
        config,
        warnings,
    );
    const rules = importRules(config, ruleProviders, groups, warnings);

    return {
        project: {
            remoteProxySources: sources,
            groups,
            rules,
            outputs: createTargetOutputs('clash', {
                independentConfig: independentConfig(config, warnings),
            }),
        },
        ruleSets,
        detected: {
            groupCount: groups.length,
            ruleCount: rules.length,
            remoteProxySources: sources.length,
            proxyCount: inlineProxies.length,
        },
        warnings,
    };
}

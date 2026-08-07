import {
    ConfigGeneratorValidationError,
    validateProject,
} from '@/extensions/config-generator/validation';
import {
    parseProfileSections,
    serializeProfileSections,
} from '@/extensions/config-generator/core/profile-sections';
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
import { getExplicitRuleBindingName } from '@/extensions/config-generator/core/rule-binding-name';
import { mergeNamedLines } from '@/extensions/config-generator/core/named-entry-merge';
import { separateSectionBlocks } from '@/extensions/config-generator/core/section-lines';
import {
    serializeSurgeCsv,
    serializeSurgeCsvValue,
} from '@/extensions/config-generator/targets/surge/serializer';

const DEFAULT_LOON_INDEPENDENT_CONFIG =
    '[General]\n\n[Proxy]\n\n[Proxy Group]\n\n[Rule]\n';
const DEFAULT_TEST_URL = 'http://www.gstatic.com/generate_204';
const LOON_MANAGED_SECTION_ORDER = [
    'proxy',
    'remote proxy',
    'remote filter',
    'proxy group',
    'rule',
    'remote rule',
];
const LOON_RULE_TYPES = new Set([
    'DOMAIN',
    'DOMAIN-SUFFIX',
    'DOMAIN-KEYWORD',
    'IP-CIDR',
    'IP-CIDR6',
    'GEOIP',
    'IP-ASN',
    'USER-AGENT',
    'URL-REGEX',
]);
const NO_RESOLVE_RULE_TYPES = new Set(['IP-CIDR', 'IP-CIDR6', 'GEOIP']);

function namedAssignment(line) {
    const trimmed = `${line || ''}`.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';'))
        return undefined;
    const separator = line.indexOf('=');
    if (separator <= 0) return undefined;
    const name = line.slice(0, separator).trim();
    return name || undefined;
}

function uniqueName(value, used, fallback) {
    const base =
        `${value || ''}`
            .trim()
            .replace(/[=,\r\n]+/g, '-')
            .replace(/\s+/g, ' ')
            .replace(/^-+|-+$/g, '') || fallback;
    let candidate = base;
    let index = 2;
    while (used.has(candidate.toLowerCase())) {
        candidate = `${base}-${index++}`;
    }
    used.add(candidate.toLowerCase());
    return candidate;
}

function proxyNames(lines = []) {
    return lines.flatMap((line) => {
        const name = namedAssignment(line);
        return name ? [name] : [];
    });
}

function dedupe(values) {
    const seen = new Set();
    return values.filter((value) => {
        const key = `${value || ''}`.trim();
        if (!key || seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

function compileRegex(value, path, warnings) {
    if (!value) return null;
    try {
        return new RegExp(value);
    } catch (_) {
        warnings.push({
            path,
            message:
                'The node-name regular expression is invalid. Loon kept the unfiltered source instead.',
        });
        return null;
    }
}

function normalizedAlgorithm(value) {
    const normalized = `${value || ''}`.trim().toLowerCase().replace(/_/g, '-');
    if (normalized === 'random') return 'Random';
    if (normalized === 'pcc' || normalized === 'consistent-hashing')
        return 'PCC';
    if (normalized === 'round-robin' || normalized === 'roundrobin')
        return 'Round-Robin';
    return null;
}

function warnUnsupportedGroupFields(group, capability, warnings) {
    const outputType = capability.outputType;
    const supportsTest = ['url-test', 'fallback', 'load-balance'].includes(
        outputType,
    );
    if (group.testUrl && !supportsTest) {
        warnings.push({
            path: `groups.${group.name}.testUrl`,
            message: `Loon ${outputType} does not use a per-group test URL; it was omitted.`,
        });
    }
    if (group.interval !== undefined && !supportsTest) {
        warnings.push({
            path: `groups.${group.name}.interval`,
            message: `Loon ${outputType} does not use a test interval; it was omitted.`,
        });
    }
    if (group.tolerance !== undefined && outputType !== 'url-test') {
        warnings.push({
            path: `groups.${group.name}.tolerance`,
            message:
                'Loon tolerance is only valid for url-test groups; it was omitted.',
        });
    }
    if (
        group.timeout !== undefined &&
        !['fallback', 'load-balance'].includes(outputType)
    ) {
        warnings.push({
            path: `groups.${group.name}.timeout`,
            message:
                'Loon max-timeout is only emitted for fallback and load-balance groups; it was omitted.',
        });
    }
    if (group.policyUpdateInterval !== undefined) {
        warnings.push({
            path: `groups.${group.name}.policyUpdateInterval`,
            message:
                'The official Loon profile syntax does not define a per-group remote-proxy update interval; it was omitted.',
        });
    }
    if (
        group.iconUrl ||
        group.targetOptions?.surge?.iconUrl ||
        group.targetOptions?.qx?.iconUrl
    ) {
        warnings.push({
            path: `groups.${group.name}.iconUrl`,
            message:
                'A portable Loon policy-group icon option is not documented by the official profile manual; the icon was omitted.',
        });
    }
    if (group.targetOptions?.qx?.aliveChecking !== undefined) {
        warnings.push({
            path: `groups.${group.name}.targetOptions.qx.aliveChecking`,
            message:
                'Quantumult X alive-checking has no independent Loon equivalent and was omitted.',
        });
    }
    if (group.targetOptions?.qx?.resourceTagRegex) {
        warnings.push({
            path: `groups.${group.name}.targetOptions.qx.resourceTagRegex`,
            message:
                'A raw Quantumult X resource-tag-regex cannot be represented by Loon and was omitted.',
        });
    }
    ['hidden', 'noAlert', 'evaluateBeforeUse', 'persistent'].forEach(
        (field) => {
            if (group.targetOptions?.surge?.[field] === undefined) return;
            warnings.push({
                path: `groups.${group.name}.targetOptions.surge.${field}`,
                message: `The Surge ${field} option has no documented Loon policy-group equivalent and was omitted.`,
            });
        },
    );
}

function generateRemoteSources(project, sourceContext, warnings) {
    const remoteProxyLines = [];
    const remoteFilterLines = [];
    const memberByGroup = new Map();
    const sourceAliases = new Map();
    const usedAliases = new Set(
        (project.groups || []).map((group) => group.name.toLowerCase()),
    );
    const usedFilterVariants = new Map();

    (project.groups || [])
        .filter((group) => !group.disabled)
        .forEach((group) => {
            const projection = projectGroupRemoteProxySource(
                group,
                'loon',
                sourceContext,
            );
            if (projection.status === 'none') return;
            if (projection.status === 'unsupported-field') {
                warnings.push({
                    path: projection.path,
                    message: `Loon ${
                        projection.capability?.outputType || group.type
                    } cannot use a Remote Proxy source; it was omitted.`,
                });
                return;
            }
            if (
                projection.status === 'missing' ||
                projection.status === 'incompatible'
            ) {
                warnings.push({
                    path: projection.path,
                    message: remoteProxySourceWarning(projection, 'loon'),
                });
                return;
            }
            if (projection.status === 'disabled') {
                warnings.push({
                    path: projection.path,
                    message:
                        'The Loon remote proxy source is disabled and was omitted.',
                });
                return;
            }
            if (projection.status !== 'ready') return;

            let sourceAlias = sourceAliases.get(projection.source.name);
            if (!sourceAlias) {
                sourceAlias = uniqueName(
                    projection.source.name,
                    usedAliases,
                    'Remote',
                );
                const url = remoteProxySourceOutputUrl(
                    projection.source,
                    'loon',
                    sourceContext,
                );
                if (!url) {
                    warnings.push({
                        path: projection.path,
                        message:
                            'The remote proxy source has no usable Loon output URL and was omitted.',
                    });
                    return;
                }
                sourceAliases.set(projection.source.name, sourceAlias);
                remoteProxyLines.push(`${sourceAlias} = ${url}`);
            }

            const regex = compileRegex(
                group.nodeNameRegex,
                `groups.${group.name}.nodeNameRegex`,
                warnings,
            );
            if (!regex) {
                memberByGroup.set(group.name, sourceAlias);
                return;
            }

            const filterKey = `${sourceAlias}\u0000${group.nodeNameRegex}`;
            let filterAlias = usedFilterVariants.get(filterKey);
            if (!filterAlias) {
                filterAlias = uniqueName(
                    `${sourceAlias}-${group.name}`,
                    usedAliases,
                    'Remote-Filter',
                );
                usedFilterVariants.set(filterKey, filterAlias);
                remoteFilterLines.push(
                    `${filterAlias} = ${serializeSurgeCsv([
                        'NameRegex',
                        sourceAlias,
                        `FilterKey = ${group.nodeNameRegex}`,
                    ])}`,
                );
            }
            memberByGroup.set(group.name, filterAlias);
        });

    return { remoteProxyLines, remoteFilterLines, memberByGroup };
}

function conditionalParts(member) {
    const value = `${member?.value || ''}`.trim();
    const policy = `${member?.policy || ''}`.trim();
    if (!value || !policy) return null;
    const suffix = `:${policy}`;
    const condition = value.endsWith(suffix)
        ? value.slice(0, -suffix.length).trim()
        : value;
    return condition ? { condition, policy } : null;
}

function generateGroups(
    project,
    localProxyNames,
    remoteSourceProjection,
    warnings,
) {
    const blocks = [];

    (project.groups || [])
        .filter((group) => !group.disabled)
        .forEach((group) => {
            const capability = resolvePolicyGroupCapability('loon', group.type);
            if (!capability) {
                warnings.push({
                    path: `groups.${group.name}`,
                    message: `Loon does not support the ${group.type} policy group type; the group was omitted.`,
                });
                return;
            }
            warnings.push(
                ...policyGroupCapabilityDiagnostics(group, capability),
            );

            const members = [];
            const conditionals = [];
            (group.members || []).forEach((member) => {
                if (member.kind === 'conditional') {
                    const parsed = conditionalParts(member);
                    if (parsed) conditionals.push(parsed);
                    return;
                }
                members.push(member.value);
            });

            const includedGroups = projectIncludedPolicyGroups(
                group,
                capability,
                'loon',
            );
            members.push(...includedGroups.members);
            warnings.push(...includedGroups.diagnostics);

            const remoteMember = remoteSourceProjection.memberByGroup.get(
                group.name,
            );
            if (remoteMember) members.push(remoteMember);

            const regex = compileRegex(
                group.nodeNameRegex,
                `groups.${group.name}.nodeNameRegex`,
                warnings,
            );
            if (group.includeAllProxies) {
                const matched = localProxyNames.filter(
                    (name) => !regex || regex.test(name),
                );
                members.push(...matched);
                if (!matched.length && !remoteMember) {
                    warnings.push({
                        path: `groups.${group.name}.includeAllProxies`,
                        message:
                            'No embedded or independent Loon proxy matched includeAllProxies, so it added no members.',
                    });
                }
            } else if (group.nodeNameRegex && !remoteMember) {
                warnings.push({
                    path: `groups.${group.name}.nodeNameRegex`,
                    message:
                        'Loon can apply this node filter only to a Remote Proxy source or includeAllProxies; the filter was omitted.',
                });
            }

            const values = [capability.outputType];
            dedupe(members).forEach((member) =>
                values.push(serializeSurgeCsvValue(member)),
            );

            if (capability.outputType === 'ssid') {
                conditionals.forEach(({ condition, policy }) => {
                    values.push(
                        `${serializeSurgeCsvValue(
                            condition,
                        )} = ${serializeSurgeCsvValue(policy)}`,
                    );
                });
            } else if (conditionals.length) {
                warnings.push({
                    path: `groups.${group.name}.members`,
                    message:
                        'Conditional policy members are only valid for Loon ssid groups; they were omitted.',
                });
            }

            const outputType = capability.outputType;
            if (['url-test', 'fallback', 'load-balance'].includes(outputType)) {
                values.push(
                    `url = ${serializeSurgeCsvValue(
                        group.testUrl || DEFAULT_TEST_URL,
                    )}`,
                );
                if (group.interval !== undefined)
                    values.push(`interval = ${group.interval}`);
            }
            if (outputType === 'url-test' && group.tolerance !== undefined)
                values.push(`tolerance = ${group.tolerance}`);
            if (
                ['fallback', 'load-balance'].includes(outputType) &&
                group.timeout !== undefined
            ) {
                values.push(`max-timeout = ${group.timeout * 1000}`);
            }
            if (outputType === 'load-balance') {
                const requestedAlgorithm =
                    group.targetOptions?.loon?.algorithm ||
                    capability.targetDefaults?.algorithm ||
                    capability.targetDefaults?.strategy;
                const algorithm = normalizedAlgorithm(requestedAlgorithm);
                if (requestedAlgorithm && !algorithm) {
                    warnings.push({
                        path: `groups.${group.name}.targetOptions.loon.algorithm`,
                        message:
                            'Loon load-balance only supports Random, PCC, or Round-Robin; the invalid algorithm was omitted.',
                    });
                } else if (algorithm) {
                    values.push(`algorithm = ${algorithm}`);
                }
            }

            warnUnsupportedGroupFields(group, capability, warnings);

            const candidateCount =
                dedupe(members).length +
                (capability.outputType === 'ssid' ? conditionals.length : 0);
            if (!candidateCount) {
                throw new ConfigGeneratorValidationError([
                    {
                        path: `groups.${group.name}.members`,
                        message: `Loon ${capability.outputType} has no usable policy members or remote sources after target projection`,
                    },
                ]);
            }

            const lines = [];
            if (group.remark) lines.push(`# ${group.remark}`);
            lines.push(`${group.name} = ${values.join(', ')}`);
            blocks.push(lines);
        });

    return separateSectionBlocks(blocks);
}

function localRuleLine(rule, warnings, index) {
    if (rule.kind === 'final') return `FINAL, ${rule.policy}`;
    if (rule.kind !== 'inline') return null;
    if (!LOON_RULE_TYPES.has(rule.type)) {
        warnings.push({
            path: `rules[${index}].type`,
            message: `Loon does not support the portable ${rule.type} rule type; it was omitted.`,
        });
        return null;
    }
    const noResolve = Boolean(
        rule.noResolve && NO_RESOLVE_RULE_TYPES.has(rule.type),
    );
    if (rule.noResolve && !noResolve) {
        warnings.push({
            path: `rules[${index}].noResolve`,
            message: `Loon no-resolve is not valid for ${rule.type}; it was omitted.`,
        });
    }
    return serializeSurgeCsv([
        rule.type,
        rule.value,
        rule.policy,
        ...(noResolve ? ['no-resolve'] : []),
    ]);
}

function generateRules(project, ruleSets, warnings) {
    const byName = new Map((ruleSets || []).map((item) => [item.name, item]));
    const local = [];
    const remoteBlocks = [];
    let currentRemotePolicy;
    let currentRemoteBlock = [];

    const finishRemoteBlock = () => {
        if (!currentRemoteBlock.length) return;
        remoteBlocks.push(currentRemoteBlock);
        currentRemoteBlock = [];
    };

    (project.rules || []).forEach((rule, index) => {
        if (rule.disabled) return;
        if (rule.kind === 'comment') {
            const text = `${rule.text || ''}`.trim();
            local.push(
                text.startsWith('#') ? text : `#${text ? ` ${text}` : ''}`,
            );
            return;
        }
        if (rule.kind === 'blank') {
            local.push('');
            return;
        }
        if (rule.kind !== 'remote') {
            const line = localRuleLine(rule, warnings, index);
            if (line) local.push(line);
            return;
        }

        const ruleSet = byName.get(rule.ruleSet);
        if (!ruleSet || ruleSet.enabled === false) return;
        const resolution = resolveRuleSetSource(ruleSet, 'loon');
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
                if (!LOON_RULE_TYPES.has(item.type)) return;
                local.push(
                    serializeSurgeCsv([
                        item.type,
                        item.value,
                        rule.policy,
                        ...(item.noResolve ? ['no-resolve'] : []),
                    ]),
                );
            });
            return;
        }
        if (resolution.kind !== 'remote-url' || !resolution.url) {
            if (resolution.kind === 'unsupported') {
                warnings.push({
                    path: `rules.${rule.ruleSet}`,
                    message:
                        resolution.warning?.message ||
                        'Loon cannot represent this remote rule-set source.',
                });
            }
            return;
        }
        if (!/^https?:\/\//i.test(resolution.url)) {
            warnings.push({
                path: `rules.${rule.ruleSet}.source.url`,
                message:
                    'Loon Remote Rule entries require an absolute HTTP(S) rule-set URL; the entry was omitted.',
            });
            return;
        }
        if (rule.noResolve) {
            warnings.push({
                path: `rules[${index}].noResolve`,
                message:
                    'Loon Remote Rule bindings do not support the shared no-resolve option; it was omitted.',
            });
        }
        if (ruleSet.updateInterval !== undefined) {
            warnings.push({
                path: `ruleSets.${ruleSet.name}.updateInterval`,
                message:
                    'The official Loon Remote Rule example does not define a per-entry update interval; it was omitted.',
            });
        }

        if (currentRemotePolicy !== rule.policy) {
            finishRemoteBlock();
            currentRemotePolicy = rule.policy;
            currentRemoteBlock.push(
                `# ==================== ${rule.policy} ====================`,
            );
        }
        const bindingName = getExplicitRuleBindingName(rule);
        if (bindingName) currentRemoteBlock.push(`# ${bindingName}`);
        currentRemoteBlock.push(
            `${resolution.url}, policy=${rule.policy}, enabled=true`,
        );
    });
    finishRemoteBlock();

    return {
        local,
        remote: separateSectionBlocks(remoteBlocks),
    };
}

function appendGeneratedLines(existing, generated) {
    const next = [...existing];
    const generatedLines = generated.filter(
        (line, index) =>
            line === '' ||
            !next.includes(line) ||
            generated.indexOf(line) !== index,
    );
    if (
        next.length &&
        generatedLines.length &&
        next[next.length - 1] !== '' &&
        generatedLines[0] !== ''
    ) {
        next.push('');
    }
    next.push(...generatedLines);
    return next;
}

function sectionTitle(name) {
    return `[${name
        .split(' ')
        .map((part) => part[0].toUpperCase() + part.slice(1))
        .join(' ')}]`;
}

function mergeIndependentConfig(content, replacements, replaceProxy) {
    const ast = parseProfileSections(content);
    const byName = new Map(
        ast.sections.map((section) => [section.name, section]),
    );

    LOON_MANAGED_SECTION_ORDER.forEach((name) => {
        const generated = replacements[name] || [];
        const existing = byName.get(name);
        if (existing) {
            if (name === 'proxy') {
                if (replaceProxy) existing.body = generated;
            } else if (
                ['remote proxy', 'remote filter', 'proxy group'].includes(name)
            ) {
                const existingBody = existing.body.some((line) => line.trim())
                    ? existing.body
                    : [];
                existing.body = mergeNamedLines(
                    existingBody,
                    generated,
                    namedAssignment,
                );
            } else if (generated.length) {
                existing.body = appendGeneratedLines(existing.body, generated);
            }
            return;
        }
        if (!generated.length) return;
        const section = {
            title: sectionTitle(name),
            name,
            body: generated,
        };
        const currentOrder = LOON_MANAGED_SECTION_ORDER.indexOf(name);
        let insertAt = ast.sections.findIndex(
            (candidate) =>
                LOON_MANAGED_SECTION_ORDER.includes(candidate.name) &&
                LOON_MANAGED_SECTION_ORDER.indexOf(candidate.name) >
                    currentOrder,
        );
        if (insertAt < 0) insertAt = ast.sections.length;
        ast.sections.splice(insertAt, 0, section);
        byName.set(name, section);
    });

    return serializeProfileSections(ast);
}

export async function generateLoonConfig({
    project,
    ruleSets,
    produceBuiltinArtifact,
}) {
    validateProject(project, ruleSets, 'loon');
    const warnings = [];
    const loon = project.outputs?.loon || {};
    const independentConfig =
        typeof loon.independentConfig === 'string'
            ? loon.independentConfig
            : DEFAULT_LOON_INDEPENDENT_CONFIG;
    const independentAst = parseProfileSections(independentConfig);
    const preservedProxyLines =
        independentAst.sections.find((section) => section.name === 'proxy')
            ?.body || [];

    let generatedProxyLines = [];
    if (project.embeddedSource) {
        const body = await produceBuiltinArtifact({
            type: project.embeddedSource.type,
            name: project.embeddedSource.name,
            platform: 'Loon',
            produceOpts: {
                'include-unsupported-proxy': loon.includeUnsupportedProxy,
            },
        });
        generatedProxyLines = `${body || ''}`
            .split(/\r?\n/)
            .filter((line) => line.trim());
        if (!generatedProxyLines.length) {
            warnings.push({
                path: 'embeddedSource',
                message:
                    'The embedded source did not produce any usable Loon proxy lines.',
            });
        }
    }
    const effectiveProxyLines = project.embeddedSource
        ? generatedProxyLines
        : preservedProxyLines;
    const sourceContext = createRemoteProxySourceContext(project);
    const remoteProjection = generateRemoteSources(
        project,
        sourceContext,
        warnings,
    );
    const groups = generateGroups(
        project,
        proxyNames(effectiveProxyLines),
        remoteProjection,
        warnings,
    );
    const rules = generateRules(project, ruleSets, warnings);
    const body = mergeIndependentConfig(
        independentConfig,
        {
            proxy: generatedProxyLines,
            'remote proxy': remoteProjection.remoteProxyLines,
            'remote filter': remoteProjection.remoteFilterLines,
            'proxy group': groups,
            rule: rules.local,
            'remote rule': rules.remote,
        },
        Boolean(project.embeddedSource),
    );

    return {
        body,
        sourceRevision: project.revision,
        stats: {
            nodeCount: proxyNames(effectiveProxyLines).length,
            groupCount: (project.groups || []).filter(
                (group) =>
                    !group.disabled &&
                    resolvePolicyGroupCapability('loon', group.type),
            ).length,
            ruleCount: (project.rules || []).filter(
                (rule) =>
                    !rule.disabled && !['comment', 'blank'].includes(rule.kind),
            ).length,
        },
        warnings,
        errors: [],
    };
}

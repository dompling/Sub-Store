import {
    ConfigGeneratorValidationError,
    validateProject,
} from '@/extensions/config-generator/validation';
import {
    parseProfileSections,
    serializeProfileSections,
} from '@/extensions/config-generator/core/profile-sections';
import {
    normalizeTargetId,
    resolvePolicyGroupCapability,
    resolvedPolicyGroupSupportsField,
} from '@/extensions/config-generator/core/target-capabilities';
import {
    policyGroupCapabilityDiagnostics,
    projectIncludedPolicyGroups,
} from '@/extensions/config-generator/core/policy-group-projection';
import { resolveRuleSetSource } from '@/extensions/config-generator/core/rule-set-source-resolver';
import { resolveRuleBindingResourceName } from '@/extensions/config-generator/core/rule-binding-name';
import { separateSectionBlocks } from '@/extensions/config-generator/core/section-lines';
import { mergeNamedLines } from '@/extensions/config-generator/core/named-entry-merge';
import {
    createRemoteProxySourceContext,
    isAutomaticRemoteProxySource,
    projectGroupRemoteProxySource,
    remoteProxySourceFallbackWarning,
    remoteProxySourceOutputUrl,
    remoteProxySourceWarning,
} from '@/extensions/config-generator/core/remote-proxy-source';

const DEFAULT_QX_INDEPENDENT_CONFIG =
    '[general]\nresource_parser_url=https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/resource-parser.js\n\n[dns]\n\n[mitm]\n';
const QX_MANAGED_SECTIONS = new Set([
    'server_local',
    'server_remote',
    'policy',
    'filter_local',
    'filter_remote',
]);

const QX_RULE_TYPES = {
    DOMAIN: 'host',
    'DOMAIN-SUFFIX': 'host-suffix',
    'DOMAIN-KEYWORD': 'host-keyword',
    'IP-CIDR': 'ip-cidr',
    'IP-CIDR6': 'ip6-cidr',
    GEOIP: 'geoip',
    'USER-AGENT': 'user-agent',
    'URL-REGEX': 'url-regex',
};

function escapeRegex(value) {
    return `${value}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function qxRulePolicy(policy) {
    if (policy === 'DIRECT') return 'direct';
    if (policy === 'REJECT') return 'reject';
    return policy;
}

function qxPolicyGroupName(line) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';'))
        return undefined;
    const separator = trimmed.indexOf('=');
    if (separator <= 0) return undefined;
    const name = trimmed
        .slice(separator + 1)
        .split(',')[0]
        .trim();
    return name || undefined;
}

function groupOptions(group, sourceContext, warnings) {
    const capability = resolvePolicyGroupCapability('qx', group.type);
    if (!capability) {
        warnings.push({
            path: `groups.${group.name}`,
            message: `Quantumult X does not support the ${group.type} policy group type`,
        });
        return null;
    }
    warnings.push(...policyGroupCapabilityDiagnostics(group, capability));

    const values = [`${capability.outputType}=${group.name}`];
    const memberValues = new Set();
    if (capability.members === 'ordered') {
        (group.members || []).forEach((member) => {
            if (memberValues.has(member.value)) return;
            memberValues.add(member.value);
            values.push(member.value);
        });
    }
    const includedGroups = projectIncludedPolicyGroups(group, capability, 'qx');
    includedGroups.members.forEach((name) => {
        if (memberValues.has(name)) return;
        memberValues.add(name);
        values.push(name);
    });
    warnings.push(...includedGroups.diagnostics);
    let hasCandidates = memberValues.size > 0;

    const sourceProjection = projectGroupRemoteProxySource(
        group,
        'qx',
        sourceContext,
    );
    const qxOptions = group.targetOptions?.qx || {};
    if (sourceProjection.status !== 'none') {
        if (sourceProjection.status === 'unsupported-field') {
            warnings.push({
                path: sourceProjection.path,
                message: `Quantumult X ${capability.outputType} does not support resource-tag-regex; the remote proxy source was omitted.`,
            });
        } else if (
            sourceProjection.status === 'missing' ||
            sourceProjection.status === 'incompatible'
        ) {
            warnings.push({
                path: sourceProjection.path,
                message: remoteProxySourceWarning(sourceProjection, 'qx'),
            });
        } else if (sourceProjection.status === 'disabled') {
            warnings.push({
                path: sourceProjection.path,
                message:
                    'The Quantumult X remote proxy source is disabled and was omitted.',
            });
        } else if (sourceProjection.status === 'ready') {
            const tag =
                sourceProjection.source.targetOptions?.qx?.tag ||
                sourceProjection.source.name;
            values.push(`resource-tag-regex=^${escapeRegex(tag)}$`);
            hasCandidates = true;
            const fallbackWarning =
                remoteProxySourceFallbackWarning(sourceProjection);
            if (fallbackWarning) {
                warnings.push({
                    path: sourceProjection.path,
                    message: fallbackWarning,
                });
            }
        }
    } else if (qxOptions.resourceTagRegex) {
        if (capability.fields?.resourceTagRegex) {
            values.push(`resource-tag-regex=${qxOptions.resourceTagRegex}`);
            hasCandidates = true;
        } else {
            warnings.push({
                path: `groups.${group.name}.targetOptions.qx.resourceTagRegex`,
                message: `Quantumult X ${capability.outputType} does not support resource-tag-regex; it was omitted.`,
            });
        }
    }
    if (group.includeAllProxies) {
        if (capability.fields?.includeAllProxies) {
            values.push(`server-tag-regex=${group.nodeNameRegex || '.*'}`);
            hasCandidates = true;
        } else {
            warnings.push({
                path: `groups.${group.name}.includeAllProxies`,
                message: `Quantumult X ${capability.outputType} does not support including all proxies; it was omitted.`,
            });
        }
    } else if (group.nodeNameRegex) {
        if (capability.fields?.nodeNameRegex) {
            values.push(`server-tag-regex=${group.nodeNameRegex}`);
            hasCandidates = true;
        } else {
            warnings.push({
                path: `groups.${group.name}.nodeNameRegex`,
                message: `Quantumult X ${capability.outputType} does not support server-tag-regex; it was omitted.`,
            });
        }
    }
    if (group.interval !== undefined) {
        if (capability.fields?.interval) {
            values.push(`check-interval=${group.interval}`);
        } else {
            warnings.push({
                path: `groups.${group.name}.interval`,
                message:
                    'Quantumult X check-interval is only supported by url-latency-benchmark groups; it was omitted.',
            });
        }
    }
    if (group.tolerance !== undefined) {
        if (capability.fields?.tolerance) {
            values.push(`tolerance=${group.tolerance}`);
        } else {
            warnings.push({
                path: `groups.${group.name}.tolerance`,
                message:
                    'Quantumult X tolerance is only supported by url-latency-benchmark groups; it was omitted.',
            });
        }
    }
    if (qxOptions.aliveChecking !== undefined) {
        if (capability.fields?.aliveChecking) {
            values.push(
                `alive-checking=${qxOptions.aliveChecking ? 'true' : 'false'}`,
            );
        } else {
            warnings.push({
                path: `groups.${group.name}.targetOptions.qx.aliveChecking`,
                message:
                    'Quantumult X alive-checking is only supported by url-latency-benchmark groups; it was omitted.',
            });
        }
    }
    if (group.timeout !== undefined) {
        warnings.push({
            path: `groups.${group.name}.timeout`,
            message:
                'Quantumult X policy groups do not support the Surge timeout option; it was omitted.',
        });
    }
    const iconUrl =
        group.iconUrl ||
        group.targetOptions?.qx?.iconUrl ||
        group.targetOptions?.surge?.iconUrl;
    if (iconUrl) values.push(`img-url=${iconUrl}`);
    if (group.testUrl) {
        warnings.push({
            path: `groups.${group.name}.testUrl`,
            message:
                'Quantumult X policy groups use the client server-check URL; a per-group test URL was omitted',
        });
    }
    if (group.targetOptions?.surge?.evaluateBeforeUse !== undefined) {
        warnings.push({
            path: `groups.${group.name}.targetOptions.surge.evaluateBeforeUse`,
            message:
                'Quantumult X policy groups do not support Surge evaluate-before-use; it was omitted.',
        });
    }
    if (!hasCandidates) {
        throw new ConfigGeneratorValidationError([
            {
                path: `groups.${group.name}.members`,
                message: `Quantumult X ${capability.outputType} has no usable policy members after target projection`,
            },
        ]);
    }
    return values.join(', ');
}

function remoteSources(project, sourceContext, warnings) {
    const { sourceMap } = sourceContext;
    const groupsBySource = new Map();
    const enabledGroups = (project.groups || []).filter(
        (group) => !group.disabled,
    );
    enabledGroups.forEach((group) => {
        const sourceProjection = projectGroupRemoteProxySource(
            group,
            'qx',
            sourceContext,
        );
        if (
            sourceProjection.status === 'ready' &&
            groupsBySource.has(sourceProjection.name)
        ) {
            groupsBySource.get(sourceProjection.name).groups.push(group);
        } else if (sourceProjection.status === 'ready') {
            groupsBySource.set(sourceProjection.name, {
                groups: [group],
                sourceBinding: sourceProjection,
            });
        }
    });

    const needsRawResourceSources = enabledGroups.some(
        (group) =>
            resolvedPolicyGroupSupportsField(
                'qx',
                group.type,
                'resourceTagRegex',
            ) && group.targetOptions?.qx?.resourceTagRegex,
    );
    if (needsRawResourceSources) {
        sourceMap.forEach((source, name) => {
            const compatible =
                source?.source?.kind === 'sub-store' ||
                (isAutomaticRemoteProxySource(source) &&
                    Boolean(
                        remoteProxySourceOutputUrl(source, 'qx', sourceContext),
                    )) ||
                (source?.source?.kind === 'url' &&
                    !isAutomaticRemoteProxySource(source) &&
                    normalizeTargetId(source.source.target) === 'qx');
            if (
                compatible &&
                source.enabled !== false &&
                !groupsBySource.has(name)
            ) {
                groupsBySource.set(name, {
                    groups: [],
                    sourceBinding: null,
                });
            }
        });
    }

    return [...groupsBySource.keys()]
        .map((name) => sourceMap.get(name))
        .filter((source) => source && source.enabled !== false)
        .map((source) => {
            const values = [
                remoteProxySourceOutputUrl(source, 'qx', sourceContext),
            ];
            const qx = source.targetOptions?.qx || {};
            const tag = qx.tag || source.name;
            values.push(`tag=${tag}`);
            const sourceUsage = groupsBySource.get(source.name);
            const groupIntervals = [
                ...new Set(
                    (sourceUsage?.groups || [])
                        .map((group) => group.policyUpdateInterval)
                        .filter((interval) => interval !== undefined),
                ),
            ].sort((left, right) => left - right);
            if (qx.updateInterval === undefined && groupIntervals.length > 1) {
                warnings.push({
                    path: `remoteProxySources.${source.name}.targetOptions.qx.updateInterval`,
                    message: `Multiple Quantumult X groups use remote proxy source ${
                        source.name
                    } with conflicting policyUpdateInterval values (${groupIntervals.join(
                        ', ',
                    )}); the smallest value ${
                        groupIntervals[0]
                    } was used because Quantumult X supports one update interval per remote source. Align the group intervals or set remoteProxySources.${
                        source.name
                    }.targetOptions.qx.updateInterval to override it.`,
                });
            }
            const interval =
                qx.updateInterval ??
                (groupIntervals.length ? groupIntervals[0] : undefined);
            if (interval !== undefined)
                values.push(`update-interval=${interval}`);
            const forceOptParser = Boolean(
                sourceUsage?.sourceBinding?.fallback?.forceOptParser,
            );
            if (forceOptParser || qx.optParser !== undefined)
                values.push(
                    `opt-parser=${
                        forceOptParser || qx.optParser ? 'true' : 'false'
                    }`,
                );
            return values.join(', ');
        });
}

function remoteRules(project, ruleSets, warnings) {
    const byName = new Map(ruleSets.map((item) => [item.name, item]));
    return (project.rules || []).flatMap((rule) => {
        if (rule.kind !== 'remote' || rule.disabled) return [];
        const ruleSet = byName.get(rule.ruleSet);
        if (!ruleSet || ruleSet.enabled === false) return [];
        const resolution = resolveRuleSetSource(ruleSet, 'qx');
        if (resolution.kind === 'inline-rules') return [];
        if (resolution.kind === 'unsupported') {
            warnings.push({
                path: `rules.${rule.ruleSet}`,
                message:
                    resolution.warning?.message ||
                    'Quantumult X cannot represent this rule-set source.',
            });
            return [];
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
        if (resolution.kind === 'qx-inserted') {
            const name = resolveRuleBindingResourceName(rule, ruleSet);
            return [
                [
                    resolution.value,
                    `tag=${name}`,
                    `force-policy=${qxRulePolicy(rule.policy)}`,
                    'inserted-resource=true',
                    'enabled=true',
                ].join(', '),
            ];
        }
        if (resolution.kind !== 'remote-url' || !resolution.url) return [];
        const name = resolveRuleBindingResourceName(rule, ruleSet);
        const values = [
            resolution.url,
            `tag=${name}`,
            `force-policy=${qxRulePolicy(rule.policy)}`,
        ];
        if (ruleSet.updateInterval !== undefined)
            values.push(`update-interval=${ruleSet.updateInterval}`);
        const qx = ruleSet.targetOptions?.qx || {};
        if (resolution.forceOptParser || qx.optParser !== undefined) {
            values.push(
                `opt-parser=${
                    resolution.forceOptParser || qx.optParser ? 'true' : 'false'
                }`,
            );
        } else if (!resolution.provider) {
            // Known providers resolve to a native Quantumult X rule format and
            // do not need the client-side resource parser. Preserve the legacy
            // parser default only for unclassified URLs.
            values.push('opt-parser=true');
        }
        values.push('enabled=true');
        return [values.join(', ')];
    });
}

function localRules(project, ruleSets, warnings) {
    const byName = new Map(ruleSets.map((item) => [item.name, item]));
    return (project.rules || []).flatMap((rule, index) => {
        if (rule.disabled) return [];
        if (rule.kind === 'comment' || rule.kind === 'blank') {
            warnings.push({
                path: `rules[${index}]`,
                message:
                    'Quantumult X separates local and remote filters, so this shared comment or blank rule could not be positioned safely and was omitted.',
            });
            return [];
        }
        if (rule.kind === 'final')
            return [`final, ${qxRulePolicy(rule.policy)}`];
        if (rule.kind === 'inline') {
            const type = QX_RULE_TYPES[rule.type];
            if (!type) {
                warnings.push({
                    path: `rules.${rule.type}`,
                    message: `Quantumult X does not support ${rule.type} as a local filter`,
                });
                return [];
            }
            if (rule.noResolve) {
                warnings.push({
                    path: `rules.${rule.type}.noResolve`,
                    message:
                        'Quantumult X does not support Surge no-resolve on local filters',
                });
            }
            return [`${type}, ${rule.value}, ${qxRulePolicy(rule.policy)}`];
        }
        if (rule.kind === 'remote') {
            const ruleSet = byName.get(rule.ruleSet);
            if (!ruleSet || ruleSet.enabled === false) return [];
            const resolution = resolveRuleSetSource(ruleSet, 'qx');
            if (resolution.kind !== 'inline-rules') return [];
            if (resolution.warning) {
                warnings.push({
                    path: `rules.${rule.ruleSet}`,
                    message: resolution.warning.message,
                });
            }
            return resolution.rules.flatMap((item) => {
                const type = QX_RULE_TYPES[item.type];
                if (!type) return [];
                return [`${type}, ${item.value}, ${qxRulePolicy(rule.policy)}`];
            });
        }
        return [];
    });
}

function mergeIndependentConfig(content, sections) {
    const ast = parseProfileSections(content);
    const generatedSections = sections.map(([name, lines]) => ({
        title: `[${name}]`,
        name,
        body: lines,
    }));
    const existingPolicy = ast.sections.find(
        (section) => section.name === 'policy',
    );
    const generatedPolicy = generatedSections.find(
        (section) => section.name === 'policy',
    );
    if (existingPolicy && generatedPolicy) {
        existingPolicy.body = mergeNamedLines(
            existingPolicy.body,
            generatedPolicy.body,
            qxPolicyGroupName,
        );
    }
    ast.sections = ast.sections.filter(
        (section) =>
            !QX_MANAGED_SECTIONS.has(section.name) || section.name === 'policy',
    );
    const generated = existingPolicy
        ? generatedSections.filter((section) => section.name !== 'policy')
        : generatedSections;
    const mitmIndex = ast.sections.findIndex(
        (section) => section.name === 'mitm',
    );
    ast.sections.splice(
        mitmIndex < 0 ? ast.sections.length : mitmIndex,
        0,
        ...generated,
    );
    return serializeProfileSections(ast);
}

export async function generateQXConfig({
    project,
    ruleSets,
    produceBuiltinArtifact,
}) {
    validateProject(project, ruleSets, 'qx');
    const warnings = [];
    const sourceContext = createRemoteProxySourceContext(project);
    const sections = [];
    if (project.embeddedSource) {
        const body = await produceBuiltinArtifact({
            type: project.embeddedSource.type,
            name: project.embeddedSource.name,
            platform: 'QX',
            produceOpts: {},
        });
        const lines = `${body || ''}`.split(/\r?\n/).filter(Boolean);
        if (lines.length) sections.push(['server_local', lines]);
    }

    const policies = (project.groups || [])
        .filter((group) => !group.disabled)
        .map((group) => groupOptions(group, sourceContext, warnings))
        .filter(Boolean);
    if (policies.length)
        sections.push(['policy', separateSectionBlocks(policies)]);

    const servers = remoteSources(project, sourceContext, warnings);
    if (servers.length) sections.push(['server_remote', servers]);

    const local = localRules(project, ruleSets, warnings);
    if (local.length) sections.push(['filter_local', local]);

    const remote = remoteRules(project, ruleSets, warnings);
    if (remote.length) sections.push(['filter_remote', remote]);

    const qx = project.outputs?.qx || {};
    const independentConfig =
        typeof qx.independentConfig === 'string'
            ? qx.independentConfig
            : DEFAULT_QX_INDEPENDENT_CONFIG;
    return {
        body: mergeIndependentConfig(independentConfig, sections),
        sourceRevision: project.revision,
        stats: {
            nodeCount:
                sections.find(([name]) => name === 'server_local')?.[1]
                    .length || 0,
            groupCount: policies.length,
            ruleCount:
                local.filter((line) => line && !line.startsWith('#')).length +
                remote.length,
        },
        warnings,
        errors: [],
    };
}

import {
    getKnownPolicyGroupTypes,
    getTargetDisplayName,
    getTargetIds,
    normalizeTargetId,
    resolvePolicyGroupCapability,
} from './core/target-capabilities';
import {
    createRemoteProxySourceContext,
    projectGroupRemoteProxySource,
} from './core/remote-proxy-source';
import { projectIncludedPolicyGroups } from './core/policy-group-projection';
import { resolveRuleSetSource } from './core/rule-set-source-resolver';

const GROUP_TYPES = getKnownPolicyGroupTypes();
const RULE_TYPES = [
    'DOMAIN',
    'DOMAIN-SUFFIX',
    'DOMAIN-KEYWORD',
    'IP-CIDR',
    'IP-CIDR6',
    'GEOIP',
    'IP-ASN',
    'USER-AGENT',
    'URL-REGEX',
    // Kept for validating legacy projects. New entries are edited in the
    // independent Surge [Rule] configuration because QX cannot represent it.
    'PROCESS-NAME',
];

export class ConfigGeneratorValidationError extends Error {
    constructor(issues) {
        super('Config generator validation failed');
        this.code = 'CONFIG_GENERATOR_VALIDATION_FAILED';
        this.type = 'RequestInvalidError';
        this.details = issues;
        this.issues = issues;
    }
}

function issue(path, message) {
    return { path, message };
}

function requiredString(value, path, issues) {
    if (typeof value !== 'string' || !value.trim()) {
        issues.push(issue(path, 'must be a non-empty string'));
    }
}

function memberPolicyReference(member) {
    if (member?.kind === 'group') return member.value;
    if (member?.kind === 'conditional') return member.policy;
    return undefined;
}

function hasTargetPolicyCandidates(group, capability, target) {
    if ((group.members || []).length) return true;
    if (group.includeAllProxies) return true;
    const included = projectIncludedPolicyGroups(group, capability, target);
    if (included.members.length || included.dependencies.length) return true;
    if (target === 'surge' && group.type === 'subnet') {
        return Boolean(group.targetOptions?.surge?.subnetDefault);
    }
    return false;
}

function findGroupReferenceCycle(groups) {
    const graph = new Map(
        groups.map((group) => [
            group.name,
            [
                ...(group.members || [])
                    .map(memberPolicyReference)
                    .filter(Boolean),
                ...(group.includeOtherGroups || []),
            ],
        ]),
    );
    const visiting = new Set();
    const visited = new Set();
    function visit(name) {
        if (visiting.has(name)) return true;
        if (visited.has(name)) return false;
        visiting.add(name);
        for (const next of graph.get(name) || []) {
            if (graph.has(next) && visit(next)) return true;
        }
        visiting.delete(name);
        visited.add(name);
        return false;
    }
    return [...graph.keys()].some(visit);
}

function validateTargetPolicyReferences(project, ruleSets, target, issues) {
    const targetId = normalizeTargetId(target);
    if (!targetId) return;
    const groups = project?.groups || [];
    const groupByName = new Map(
        groups.map((group, index) => [group.name, { group, index }]),
    );
    const targetName = getTargetDisplayName(targetId);
    const sourceContext = createRemoteProxySourceContext(project);
    const ruleSetByName = new Map(
        (ruleSets || []).map((ruleSet) => [ruleSet.name, ruleSet]),
    );

    const validatePolicy = (policy, path) => {
        if (['DIRECT', 'REJECT'].includes(policy)) return;
        const entry = groupByName.get(policy);
        if (!entry) return;
        if (entry.group.disabled) {
            issues.push(
                issue(
                    path,
                    `references policy group ${policy}, which is disabled for ${targetName}`,
                ),
            );
        } else if (!resolvePolicyGroupCapability(targetId, entry.group.type)) {
            issues.push(
                issue(
                    path,
                    `references policy group ${policy}, whose ${entry.group.type} type is unsupported by ${targetName}`,
                ),
            );
        }
    };

    groups.forEach((group, index) => {
        const capability = resolvePolicyGroupCapability(targetId, group.type);
        if (group.disabled || !capability) return;
        (group.members || []).forEach((member, memberIndex) => {
            const policy = memberPolicyReference(member);
            if (policy) {
                validatePolicy(
                    policy,
                    `groups[${index}].members[${memberIndex}].${
                        member.kind === 'conditional' ? 'policy' : 'value'
                    }`,
                );
            }
        });
        const includedGroups = projectIncludedPolicyGroups(
            group,
            capability,
            targetId,
        );
        includedGroups.dependencies.forEach((name, memberIndex) => {
            validatePolicy(
                name,
                `groups[${index}].includeOtherGroups[${memberIndex}]`,
            );
        });
        if (targetId === 'surge') {
            if (group.type === 'subnet') {
                const surgeOptions = group.targetOptions?.surge || {};
                validatePolicy(
                    surgeOptions.subnetDefault,
                    `groups[${index}].targetOptions.surge.subnetDefault`,
                );
                (surgeOptions.subnetRules || []).forEach((rule, ruleIndex) => {
                    validatePolicy(
                        rule.policy,
                        `groups[${index}].targetOptions.surge.subnetRules[${ruleIndex}].policy`,
                    );
                });
            }
        }
    });

    (project?.rules || []).forEach((rule, index) => {
        if (rule.disabled || !['inline', 'remote', 'final'].includes(rule.kind))
            return;
        validatePolicy(rule.policy, `rules[${index}].policy`);
    });

    const requiredGroups = new Set();
    const pendingGroups = (project?.rules || [])
        .filter(
            (rule) =>
                !rule.disabled &&
                ['inline', 'remote', 'final'].includes(rule.kind) &&
                groupByName.has(rule.policy),
        )
        .map((rule) => rule.policy);
    while (pendingGroups.length) {
        const name = pendingGroups.shift();
        if (requiredGroups.has(name)) continue;
        requiredGroups.add(name);
        const entry = groupByName.get(name);
        if (
            !entry ||
            entry.group.disabled ||
            !resolvePolicyGroupCapability(targetId, entry.group.type)
        )
            continue;
        (entry.group.members || []).forEach((member) => {
            const policy = memberPolicyReference(member);
            if (
                policy &&
                groupByName.has(policy) &&
                !requiredGroups.has(policy)
            ) {
                pendingGroups.push(policy);
            }
        });
        const capability = resolvePolicyGroupCapability(
            targetId,
            entry.group.type,
        );
        const includedGroups = projectIncludedPolicyGroups(
            entry.group,
            capability,
            targetId,
        );
        includedGroups.dependencies.forEach((groupName) => {
            if (groupByName.has(groupName) && !requiredGroups.has(groupName)) {
                pendingGroups.push(groupName);
            }
        });
        if (targetId === 'surge') {
            if (entry.group.type === 'subnet') {
                const surgeOptions = entry.group.targetOptions?.surge || {};
                [
                    surgeOptions.subnetDefault,
                    ...(surgeOptions.subnetRules || []).map(
                        (rule) => rule.policy,
                    ),
                ].forEach((groupName) => {
                    if (
                        groupByName.has(groupName) &&
                        !requiredGroups.has(groupName)
                    ) {
                        pendingGroups.push(groupName);
                    }
                });
            }
        }
    }

    requiredGroups.forEach((name) => {
        const entry = groupByName.get(name);
        if (
            !entry ||
            entry.group.disabled ||
            !resolvePolicyGroupCapability(targetId, entry.group.type)
        )
            return;
        const sourceProjection = projectGroupRemoteProxySource(
            entry.group,
            targetId,
            sourceContext,
        );
        if (
            targetId === 'surge' &&
            entry.group.targetOptions?.qx?.resourceTagRegex &&
            sourceProjection.status === 'none'
        ) {
            issues.push(
                issue(
                    `groups[${entry.index}].targetOptions.qx.resourceTagRegex`,
                    'uses a Quantumult X resource-tag-regex that cannot be represented by Surge; bind a Surge-compatible remote proxy source or remove the raw expression',
                ),
            );
            return;
        }
        if (sourceProjection.status === 'none') return;
        const hasStaticCandidates = hasTargetPolicyCandidates(
            entry.group,
            sourceProjection.capability,
            targetId,
        );
        if (sourceProjection.status === 'unsupported-field') {
            if (!hasStaticCandidates) {
                issues.push(
                    issue(
                        sourceProjection.path,
                        `${targetName} does not support a remote proxy source for ${entry.group.type} groups`,
                    ),
                );
            }
            return;
        } else if (sourceProjection.status === 'missing') {
            issues.push(
                issue(
                    sourceProjection.path,
                    'references a missing remote proxy source',
                ),
            );
        } else if (
            sourceProjection.status === 'incompatible' ||
            sourceProjection.status === 'disabled'
        ) {
            if (hasStaticCandidates) return;
            if (sourceProjection.status === 'disabled') {
                issues.push(
                    issue(
                        sourceProjection.path,
                        `references a remote proxy source that is disabled for ${targetName}`,
                    ),
                );
                return;
            }
            const legacyTargets = sourceProjection.legacyTargets || [];
            const candidateSourceNames =
                sourceProjection.candidateSourceNames || [];
            const isLegacySurgeQXPair =
                legacyTargets.length === 2 &&
                legacyTargets.includes('surge') &&
                legacyTargets.includes('qx');
            const legacyTargetNames = legacyTargets
                .map((legacyTarget) => getTargetDisplayName(legacyTarget))
                .join(', ');
            issues.push(
                issue(
                    sourceProjection.path,
                    sourceProjection.reason ===
                        'ambiguous-dual-target-legacy-url'
                        ? isLegacySurgeQXPair
                            ? 'uses the same target-less URL in both legacy Surge and Quantumult X bindings; select explicit target ownership'
                            : `uses the same target-less URL in multiple legacy target bindings (${legacyTargetNames}); select explicit target ownership`
                        : sourceProjection.reason ===
                          'ambiguous-multiple-legacy-sources'
                        ? `has multiple compatible legacy remote proxy sources (${candidateSourceNames.join(
                              ', ',
                          )}) for ${targetName}; select one shared remote proxy source explicitly`
                        : `references a remote proxy source that is not compatible with ${targetName}`,
                ),
            );
        }
    });

    (project?.rules || []).forEach((rule, index) => {
        if (rule.disabled || rule.kind !== 'remote') return;
        const ruleSet = ruleSetByName.get(rule.ruleSet);
        if (!ruleSet) return;
        if (ruleSet.enabled === false) {
            issues.push(
                issue(
                    `rules[${index}].ruleSet`,
                    `references rule set ${rule.ruleSet}, which is disabled for ${targetName}`,
                ),
            );
            return;
        }
        const resolution = resolveRuleSetSource(ruleSet, targetId);
        if (resolution.kind === 'unsupported') {
            issues.push(
                issue(
                    `rules[${index}].ruleSet`,
                    resolution.warning?.message ||
                        `rule set ${rule.ruleSet} cannot be emitted for ${targetName}`,
                ),
            );
        }
    });
}

export function validateRuleSet(ruleSet) {
    const issues = [];
    requiredString(ruleSet?.name, 'name', issues);
    if (!['url', 'builtin'].includes(ruleSet?.source?.kind)) {
        issues.push(issue('source.kind', 'must be url or builtin'));
    } else if (ruleSet.source.kind === 'url') {
        try {
            const url = new URL(ruleSet.source.url);
            if (!['http:', 'https:'].includes(url.protocol)) throw new Error();
        } catch (_) {
            issues.push(issue('source.url', 'must be an absolute HTTP(S) URL'));
        }
        if (
            ruleSet.source.target !== undefined &&
            !normalizeTargetId(ruleSet.source.target)
        ) {
            issues.push(
                issue('source.target', `must be ${getTargetIds().join(', ')}`),
            );
        }
    } else if (!['SYSTEM', 'LAN'].includes(ruleSet.source.value)) {
        issues.push(issue('source.value', 'must be SYSTEM or LAN'));
    }
    if (
        ruleSet?.targetOptions?.qx?.optParser !== undefined &&
        typeof ruleSet.targetOptions.qx.optParser !== 'boolean'
    ) {
        issues.push(issue('targetOptions.qx.optParser', 'must be a boolean'));
    }
    if (issues.length) throw new ConfigGeneratorValidationError(issues);
    return ruleSet;
}

export function validateProject(project, ruleSets = [], target) {
    const issues = [];
    requiredString(project?.name, 'name', issues);
    (ruleSets || []).forEach((ruleSet, index) => {
        try {
            validateRuleSet(ruleSet);
        } catch (error) {
            if (!(error instanceof ConfigGeneratorValidationError)) throw error;
            error.issues.forEach((item) => {
                issues.push(
                    issue(`ruleSets[${index}].${item.path}`, item.message),
                );
            });
        }
    });
    if (project?.embeddedSource) {
        if (
            !['subscription', 'collection'].includes(
                project.embeddedSource.type,
            )
        ) {
            issues.push(
                issue(
                    'embeddedSource.type',
                    'must be subscription or collection',
                ),
            );
        }
        requiredString(
            project.embeddedSource.name,
            'embeddedSource.name',
            issues,
        );
    }
    const remoteNames = new Set();
    (project?.remoteProxySources || []).forEach((source, index) => {
        requiredString(
            source.name,
            `remoteProxySources[${index}].name`,
            issues,
        );
        if (remoteNames.has(source.name)) {
            issues.push(
                issue(`remoteProxySources[${index}].name`, 'must be unique'),
            );
        }
        remoteNames.add(source.name);
        if (source.source?.kind === 'url') {
            if (
                source.source.mode !== undefined &&
                !['auto', 'passthrough'].includes(source.source.mode)
            ) {
                issues.push(
                    issue(
                        `remoteProxySources[${index}].source.mode`,
                        'must be auto or passthrough',
                    ),
                );
            }
            try {
                const url = new URL(source.source.url);
                if (!['http:', 'https:'].includes(url.protocol))
                    throw new Error();
            } catch (_) {
                issues.push(
                    issue(
                        `remoteProxySources[${index}].source.url`,
                        'must be an absolute HTTP(S) URL',
                    ),
                );
            }
            if (
                source.source.target !== undefined &&
                !normalizeTargetId(source.source.target)
            ) {
                issues.push(
                    issue(
                        `remoteProxySources[${index}].source.target`,
                        `must be ${getTargetIds().join(', ')}`,
                    ),
                );
            }
            if (source.source.mode === 'passthrough' && !source.source.target) {
                issues.push(
                    issue(
                        `remoteProxySources[${index}].source.target`,
                        `must be ${getTargetIds().join(
                            ', ',
                        )} when mode is passthrough`,
                    ),
                );
            }
            if (
                source.source.mode === 'auto' ||
                source.source.publicBaseUrl !== undefined
            ) {
                try {
                    const publicBaseUrl = new URL(source.source.publicBaseUrl);
                    if (!['http:', 'https:'].includes(publicBaseUrl.protocol))
                        throw new Error();
                } catch (_) {
                    issues.push(
                        issue(
                            `remoteProxySources[${index}].source.publicBaseUrl`,
                            'must be an absolute HTTP(S) URL for automatic conversion',
                        ),
                    );
                }
            }
        } else if (source.source?.kind === 'sub-store') {
            if (!['subscription', 'collection'].includes(source.source.type)) {
                issues.push(
                    issue(
                        `remoteProxySources[${index}].source.type`,
                        'must be subscription or collection',
                    ),
                );
            }
            requiredString(
                source.source.name,
                `remoteProxySources[${index}].source.name`,
                issues,
            );
            try {
                new URL(source.source.publicBaseUrl);
            } catch (_) {
                issues.push(
                    issue(
                        `remoteProxySources[${index}].source.publicBaseUrl`,
                        'must be an absolute URL',
                    ),
                );
            }
        } else {
            issues.push(
                issue(
                    `remoteProxySources[${index}].source.kind`,
                    'must be url or sub-store',
                ),
            );
        }
        const qx = source.targetOptions?.qx;
        if (
            qx?.updateInterval !== undefined &&
            (!Number.isInteger(qx.updateInterval) || qx.updateInterval === 0)
        ) {
            issues.push(
                issue(
                    `remoteProxySources[${index}].targetOptions.qx.updateInterval`,
                    'must be a non-zero integer',
                ),
            );
        }
        const clash = source.targetOptions?.clash;
        if (
            clash?.updateInterval !== undefined &&
            (!Number.isInteger(clash.updateInterval) ||
                clash.updateInterval <= 0)
        ) {
            issues.push(
                issue(
                    `remoteProxySources[${index}].targetOptions.clash.updateInterval`,
                    'must be a positive integer',
                ),
            );
        }
    });
    const groupNames = new Set();
    (project?.groups || []).forEach((group, index) => {
        requiredString(group.name, `groups[${index}].name`, issues);
        if (groupNames.has(group.name))
            issues.push(issue(`groups[${index}].name`, 'must be unique'));
        groupNames.add(group.name);
        if (!GROUP_TYPES.includes(group.type))
            issues.push(issue(`groups[${index}].type`, 'is unsupported'));
        const surgeOptions = group.targetOptions?.surge || {};
        const qxOptions = group.targetOptions?.qx || {};
        const clashOptions = group.targetOptions?.clash || {};
        const loonOptions = group.targetOptions?.loon || {};
        if (group.remoteProxySource !== undefined) {
            requiredString(
                group.remoteProxySource,
                `groups[${index}].remoteProxySource`,
                issues,
            );
            if (
                group.remoteProxySource &&
                !remoteNames.has(group.remoteProxySource)
            ) {
                issues.push(
                    issue(
                        `groups[${index}].remoteProxySource`,
                        'references a missing remote proxy source',
                    ),
                );
            }
        }
        [
            ['surge', surgeOptions],
            ['qx', qxOptions],
            ['clash', clashOptions],
            ['loon', loonOptions],
        ].forEach(([target, options]) => {
            if (
                Object.prototype.hasOwnProperty.call(
                    options,
                    'remoteProxySource',
                )
            ) {
                const remote = options.remoteProxySource;
                requiredString(
                    remote,
                    `groups[${index}].targetOptions.${target}.remoteProxySource`,
                    issues,
                );
                if (remote && !remoteNames.has(remote))
                    issues.push(
                        issue(
                            `groups[${index}].targetOptions.${target}.remoteProxySource`,
                            'references a missing remote proxy source',
                        ),
                    );
            }
        });
        ['interval', 'timeout', 'policyUpdateInterval'].forEach((key) => {
            if (
                group[key] !== undefined &&
                (!Number.isInteger(group[key]) || group[key] <= 0)
            ) {
                issues.push(
                    issue(
                        `groups[${index}].${key}`,
                        'must be a positive integer',
                    ),
                );
            }
        });
        if (
            group.tolerance !== undefined &&
            (!Number.isInteger(group.tolerance) || group.tolerance < 0)
        ) {
            issues.push(
                issue(
                    `groups[${index}].tolerance`,
                    'must be a non-negative integer',
                ),
            );
        }
        if (group.iconUrl !== undefined) {
            requiredString(group.iconUrl, `groups[${index}].iconUrl`, issues);
        }
        if (
            qxOptions.aliveChecking !== undefined &&
            typeof qxOptions.aliveChecking !== 'boolean'
        ) {
            issues.push(
                issue(
                    `groups[${index}].targetOptions.qx.aliveChecking`,
                    'must be a boolean',
                ),
            );
        }
        if (qxOptions.resourceTagRegex !== undefined) {
            requiredString(
                qxOptions.resourceTagRegex,
                `groups[${index}].targetOptions.qx.resourceTagRegex`,
                issues,
            );
        }
        if (loonOptions.algorithm !== undefined) {
            requiredString(
                loonOptions.algorithm,
                `groups[${index}].targetOptions.loon.algorithm`,
                issues,
            );
            const algorithm = `${loonOptions.algorithm || ''}`
                .trim()
                .toLowerCase()
                .replace(/_/g, '-');
            if (
                algorithm &&
                !['random', 'pcc', 'round-robin'].includes(algorithm)
            ) {
                issues.push(
                    issue(
                        `groups[${index}].targetOptions.loon.algorithm`,
                        'must be Random, PCC, or Round-Robin',
                    ),
                );
            }
        }
        if (
            normalizeTargetId(target) === 'qx' &&
            group.remoteProxySource &&
            qxOptions.resourceTagRegex
        ) {
            issues.push(
                issue(
                    `groups[${index}].targetOptions.qx.resourceTagRegex`,
                    'cannot be combined with remoteProxySource',
                ),
            );
        }
        if (group.type === 'subnet') {
            requiredString(
                surgeOptions.subnetDefault,
                `groups[${index}].targetOptions.surge.subnetDefault`,
                issues,
            );
            (surgeOptions.subnetRules || []).forEach((rule, ruleIndex) => {
                requiredString(
                    rule?.expression,
                    `groups[${index}].targetOptions.surge.subnetRules[${ruleIndex}].expression`,
                    issues,
                );
                requiredString(
                    rule?.policy,
                    `groups[${index}].targetOptions.surge.subnetRules[${ruleIndex}].policy`,
                    issues,
                );
            });
        }
    });
    const knownPolicies = new Set(['DIRECT', 'REJECT', ...groupNames]);
    (project?.groups || []).forEach((group, index) => {
        (group.members || []).forEach((member, memberIndex) => {
            if (
                !['builtin', 'group', 'conditional', 'proxy'].includes(
                    member.kind,
                )
            ) {
                issues.push(
                    issue(
                        `groups[${index}].members[${memberIndex}].kind`,
                        'must be builtin, group, conditional, or proxy',
                    ),
                );
            } else if (
                member.kind === 'builtin' &&
                !['DIRECT', 'REJECT'].includes(member.value)
            ) {
                issues.push(
                    issue(
                        `groups[${index}].members[${memberIndex}].value`,
                        'must be DIRECT or REJECT',
                    ),
                );
            } else if (
                member.kind === 'group' &&
                !groupNames.has(member.value)
            ) {
                issues.push(
                    issue(
                        `groups[${index}].members[${memberIndex}].value`,
                        'references a missing policy group',
                    ),
                );
            } else if (member.kind === 'conditional') {
                if (group.type !== 'ssid') {
                    issues.push(
                        issue(
                            `groups[${index}].members[${memberIndex}].kind`,
                            'conditional policy references are only supported by ssid groups',
                        ),
                    );
                }
                requiredString(
                    member.value,
                    `groups[${index}].members[${memberIndex}].value`,
                    issues,
                );
                requiredString(
                    member.policy,
                    `groups[${index}].members[${memberIndex}].policy`,
                    issues,
                );
                const separator =
                    typeof member.value === 'string'
                        ? member.value.lastIndexOf(':')
                        : -1;
                const valuePolicy =
                    separator > 0
                        ? member.value.slice(separator + 1).trim()
                        : '';
                if (!valuePolicy) {
                    issues.push(
                        issue(
                            `groups[${index}].members[${memberIndex}].value`,
                            'must contain a condition and policy separated by a colon',
                        ),
                    );
                } else if (member.policy && valuePolicy !== member.policy) {
                    issues.push(
                        issue(
                            `groups[${index}].members[${memberIndex}].value`,
                            'must end with the referenced policy',
                        ),
                    );
                }
                if (member.policy && !knownPolicies.has(member.policy)) {
                    issues.push(
                        issue(
                            `groups[${index}].members[${memberIndex}].policy`,
                            'references a missing policy group',
                        ),
                    );
                }
            }
        });
        (group.includeOtherGroups || []).forEach((name, memberIndex) => {
            if (!groupNames.has(name)) {
                issues.push(
                    issue(
                        `groups[${index}].includeOtherGroups[${memberIndex}]`,
                        'references a missing policy group',
                    ),
                );
            }
        });
        const surgeOptions = group.targetOptions?.surge || {};
        if (group.type === 'subnet') {
            if (!knownPolicies.has(surgeOptions.subnetDefault)) {
                issues.push(
                    issue(
                        `groups[${index}].targetOptions.surge.subnetDefault`,
                        'references a missing policy group',
                    ),
                );
            }
            (surgeOptions.subnetRules || []).forEach((rule, ruleIndex) => {
                if (!knownPolicies.has(rule.policy)) {
                    issues.push(
                        issue(
                            `groups[${index}].targetOptions.surge.subnetRules[${ruleIndex}].policy`,
                            'references a missing policy group',
                        ),
                    );
                }
            });
        }
    });
    const knownRuleSets = new Set(ruleSets.map((item) => item.name));
    let finalSeen = false;
    (project?.rules || []).forEach((rule, index) => {
        if (finalSeen && rule.kind !== 'blank')
            issues.push(
                issue(`rules[${index}]`, 'only blank rules may follow FINAL'),
            );
        if (rule.kind === 'final') finalSeen = true;
        if (rule.kind === 'inline' && !RULE_TYPES.includes(rule.type))
            issues.push(issue(`rules[${index}].type`, 'is unsupported'));
        if (rule.kind === 'remote' && !knownRuleSets.has(rule.ruleSet))
            issues.push(
                issue(
                    `rules[${index}].ruleSet`,
                    'references a missing rule set',
                ),
            );
        if (rule.kind === 'remote' && rule.name !== undefined) {
            requiredString(rule.name, `rules[${index}].name`, issues);
            if (typeof rule.name === 'string' && /[,\r\n]/.test(rule.name)) {
                issues.push(
                    issue(
                        `rules[${index}].name`,
                        'must not contain commas or line breaks',
                    ),
                );
            }
        }
        if (
            ['inline', 'remote', 'final'].includes(rule.kind) &&
            !knownPolicies.has(rule.policy)
        )
            issues.push(
                issue(
                    `rules[${index}].policy`,
                    'references a missing policy group',
                ),
            );
    });
    if (findGroupReferenceCycle(project?.groups || [])) {
        issues.push(issue('groups', 'group references must be acyclic'));
    }
    if (project?.process !== undefined && !Array.isArray(project.process)) {
        issues.push(issue('process', 'must be an array'));
    }
    (project?.process || []).forEach((item, index) => {
        if (item?.type !== 'Response Transformer') {
            issues.push(
                issue(`process[${index}].type`, 'must be Response Transformer'),
            );
        }
        requiredString(item?.id, `process[${index}].id`, issues);
        if (!item?.args || typeof item.args !== 'object') {
            issues.push(issue(`process[${index}].args`, 'must be an object'));
        }
    });
    if (!getTargetIds().some((targetId) => project?.outputs?.[targetId])) {
        issues.push(
            issue(
                'outputs',
                `must contain ${getTargetIds()
                    .map((targetId) => getTargetDisplayName(targetId))
                    .join(', ')} output`,
            ),
        );
    }
    getTargetIds().forEach((target) => {
        const content = project?.outputs?.[target]?.independentConfig;
        if (content !== undefined && typeof content !== 'string') {
            issues.push(
                issue(
                    `outputs.${target}.independentConfig`,
                    'must be a string',
                ),
            );
        }
    });
    validateTargetPolicyReferences(project, ruleSets, target, issues);
    if (issues.length) throw new ConfigGeneratorValidationError(issues);
    return project;
}

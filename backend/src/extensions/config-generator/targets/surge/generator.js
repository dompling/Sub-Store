import {
    parseProfileSections,
    replaceManagedSections,
    serializeProfileSections,
} from '@/extensions/config-generator/core/profile-sections';
import { resolvePolicyGroupCapability } from '@/extensions/config-generator/core/target-capabilities';
import { policyGroupCapabilityDiagnostics } from '@/extensions/config-generator/core/policy-group-projection';
import { resolveRuleSetUrl } from '@/extensions/config-generator/core/rule-set-source-resolver';
import { separateSectionBlocks } from '@/extensions/config-generator/core/section-lines';
import { mergeNamedLines } from '@/extensions/config-generator/core/named-entry-merge';
import { ConfigGeneratorValidationError } from '@/extensions/config-generator/validation';
import {
    createRemoteProxySourceContext,
    projectGroupRemoteProxySource,
    remoteProxySourceOutputUrl,
    remoteProxySourceWarning,
} from '@/extensions/config-generator/core/remote-proxy-source';
import { serializeSurgeCsv, serializeSurgeCsvValue } from './serializer';
import { validateProject } from '@/extensions/config-generator/validation';

const DEFAULT_SURGE_INDEPENDENT_CONFIG =
    '[General]\n\n[Host]\n\n[Rule]\n\n[MITM]\n';

function bool(value) {
    return value === undefined ? null : value ? '1' : '0';
}

function surgePolicyGroupName(line) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';'))
        return undefined;
    const separator = line.indexOf('=');
    if (separator <= 0) return undefined;
    const name = line.slice(0, separator).trim();
    return name || undefined;
}

function generateGroups(project, warnings) {
    const sourceContext = createRemoteProxySourceContext(project);
    const blocks = (project.groups || [])
        .filter((group) => !group.disabled)
        .map((group) => {
            const capability = resolvePolicyGroupCapability(
                'surge',
                group.type,
            );
            if (!capability) {
                warnings.push({
                    path: `groups.${group.name}`,
                    message: `Surge does not support the ${group.type} policy group type`,
                });
                return [];
            }
            warnings.push(
                ...policyGroupCapabilityDiagnostics(group, capability),
            );
            const values = [capability.outputType];
            let hasCandidates = false;
            if (capability.members === 'ordered') {
                (group.members || []).forEach((member) => {
                    values.push(serializeSurgeCsvValue(member.value));
                    hasCandidates = true;
                });
            }
            if (group.includeAllProxies !== undefined) {
                values.push(
                    `include-all-proxies=${bool(group.includeAllProxies)}`,
                );
                if (group.includeAllProxies) hasCandidates = true;
            }
            (group.includeOtherGroups || []).forEach((name) => {
                values.push(
                    `include-other-group=${serializeSurgeCsvValue(name)}`,
                );
                hasCandidates = true;
            });
            if (group.nodeNameRegex)
                values.push(
                    `policy-regex-filter=${serializeSurgeCsvValue(
                        group.nodeNameRegex,
                    )}`,
                );
            if (group.testUrl)
                values.push(`url=${serializeSurgeCsvValue(group.testUrl)}`);
            if (group.interval !== undefined)
                values.push(`interval=${group.interval}`);
            if (group.tolerance !== undefined)
                values.push(`tolerance=${group.tolerance}`);
            if (group.timeout !== undefined)
                values.push(`timeout=${group.timeout}`);
            const options = group.targetOptions?.surge || {};
            const sourceProjection = projectGroupRemoteProxySource(
                group,
                'surge',
                sourceContext,
            );
            if (
                group.targetOptions?.qx?.resourceTagRegex &&
                sourceProjection.status === 'none'
            ) {
                warnings.push({
                    path: `groups.${group.name}.targetOptions.qx.resourceTagRegex`,
                    message:
                        'Surge cannot represent the raw Quantumult X resource-tag-regex; it was omitted.',
                });
            }
            if (sourceProjection.status !== 'none') {
                if (sourceProjection.status === 'unsupported-field') {
                    warnings.push({
                        path: sourceProjection.path,
                        message: `Surge ${capability.outputType} does not support policy-path; the remote proxy source was omitted.`,
                    });
                } else if (
                    sourceProjection.status === 'missing' ||
                    sourceProjection.status === 'incompatible'
                ) {
                    warnings.push({
                        path: sourceProjection.path,
                        message: remoteProxySourceWarning(
                            sourceProjection,
                            'surge',
                        ),
                    });
                } else if (sourceProjection.status === 'ready') {
                    values.push(
                        `policy-path=${serializeSurgeCsvValue(
                            remoteProxySourceOutputUrl(
                                sourceProjection.source,
                                'surge',
                                sourceContext,
                            ),
                        )}`,
                    );
                    hasCandidates = true;
                } else if (sourceProjection.status === 'disabled') {
                    warnings.push({
                        path: sourceProjection.path,
                        message:
                            'The Surge remote proxy source is disabled and was omitted.',
                    });
                }
            }
            if (group.policyUpdateInterval !== undefined)
                values.push(`update-interval=${group.policyUpdateInterval}`);
            if (options.hidden !== undefined)
                values.push(`hidden=${bool(options.hidden)}`);
            if (options.noAlert !== undefined)
                values.push(`no-alert=${bool(options.noAlert)}`);
            if (options.evaluateBeforeUse !== undefined)
                values.push(
                    `evaluate-before-use=${bool(options.evaluateBeforeUse)}`,
                );
            const persistent =
                options.persistent ?? capability.targetDefaults?.persistent;
            if (persistent !== undefined)
                values.push(`persistent=${bool(persistent)}`);
            if (group.type === 'subnet') {
                hasCandidates = Boolean(options.subnetDefault);
                values.push(
                    `default=${serializeSurgeCsvValue(options.subnetDefault)}`,
                );
                (options.subnetRules || []).forEach((rule) => {
                    values.push(
                        `${rule.expression.trim()} = ${serializeSurgeCsvValue(
                            rule.policy,
                        )}`,
                    );
                });
            }
            if (!hasCandidates && sourceProjection.status !== 'none') {
                throw new ConfigGeneratorValidationError([
                    {
                        path: `groups.${group.name}.members`,
                        message: `Surge ${capability.outputType} has no usable policy members or remote sources after target projection`,
                    },
                ]);
            }
            const iconUrl = group.iconUrl || options.iconUrl;
            if (iconUrl)
                values.push(`icon-url=${serializeSurgeCsvValue(iconUrl)}`);
            const lines = [];
            if (group.remark) lines.push(`# ${group.remark}`);
            lines.push(`${group.name} = ${values.join(', ')}`);
            return lines;
        });
    return separateSectionBlocks(blocks);
}

function generateRuleLine(rule, byName, warnings) {
    if (rule.disabled) return null;
    if (rule.kind === 'blank' || rule.kind === 'comment') return null;
    if (rule.kind === 'final')
        return serializeSurgeCsv([
            'FINAL',
            rule.policy,
            ...(rule.dnsFailed ? ['dns-failed'] : []),
        ]);
    if (rule.kind === 'inline') {
        if (rule.type === 'PROCESS-NAME') return null;
        return serializeSurgeCsv([
            rule.type,
            rule.value,
            rule.policy,
            ...(rule.noResolve ? ['no-resolve'] : []),
        ]);
    }
    const ruleSet = byName.get(rule.ruleSet);
    if (!ruleSet || ruleSet.enabled === false) return null;
    let source = ruleSet.source.value;
    if (ruleSet.source.kind === 'url') {
        const resolution = resolveRuleSetUrl(ruleSet, 'surge');
        if (resolution.warning) {
            warnings.push({
                path: `rules.${rule.ruleSet}.source.url`,
                message: resolution.warning.message,
            });
        }
        if (!resolution.url) return null;
        source = resolution.url;
    }
    const options = [];
    if (ruleSet.updateInterval !== undefined && ruleSet.source.kind === 'url')
        options.push(`update-interval=${ruleSet.updateInterval}`);
    if (rule.noResolve) options.push('no-resolve');
    return serializeSurgeCsv(['RULE-SET', source, rule.policy, ...options]);
}

function generateLegacyIndependentRules(project) {
    return (project.rules || [])
        .filter(
            (rule) =>
                !rule.disabled &&
                rule.kind === 'inline' &&
                rule.type === 'PROCESS-NAME',
        )
        .map((rule) =>
            serializeSurgeCsv([
                'PROCESS-NAME',
                rule.value,
                rule.policy,
                ...(rule.noResolve ? ['no-resolve'] : []),
            ]),
        );
}

function generateRules(project, ruleSets, warnings) {
    const byName = new Map(ruleSets.map((item) => [item.name, item]));
    const lines = [];
    let currentRemotePolicy;
    let structuralBoundary = false;
    const separateBlock = () => {
        if (lines.length && lines[lines.length - 1] !== '') lines.push('');
    };
    (project.rules || []).forEach((rule) => {
        if (rule.disabled) return;
        if (rule.kind === 'comment') {
            if (currentRemotePolicy !== undefined) {
                separateBlock();
                currentRemotePolicy = undefined;
            }
            const text = `${rule.text || ''}`.trim();
            lines.push(
                text.startsWith('#') ? text : `#${text ? ` ${text}` : ''}`,
            );
            structuralBoundary = true;
            return;
        }
        if (rule.kind === 'blank') {
            if (currentRemotePolicy !== undefined) {
                separateBlock();
                currentRemotePolicy = undefined;
            } else {
                lines.push('');
            }
            structuralBoundary = true;
            return;
        }
        const line = generateRuleLine(rule, byName, warnings);
        if (!line) return;

        if (rule.kind === 'remote') {
            const policy = `${rule.policy || 'DIRECT'}`.trim() || 'DIRECT';
            if (policy !== currentRemotePolicy) {
                if (!structuralBoundary) separateBlock();
                lines.push(
                    `# ==================== ${policy} ====================`,
                );
                currentRemotePolicy = policy;
            }
            lines.push(line);
            structuralBoundary = false;
            return;
        }

        if (currentRemotePolicy !== undefined) {
            separateBlock();
            currentRemotePolicy = undefined;
        }
        lines.push(line);
        structuralBoundary = false;
    });
    if (currentRemotePolicy !== undefined) separateBlock();
    return lines;
}

export async function generateSurgeConfig({
    project,
    ruleSets,
    produceBuiltinArtifact,
}) {
    validateProject(project, ruleSets, 'surge');
    const surge = project.outputs.surge || {};
    const warnings = [];
    const independentConfig =
        typeof surge.independentConfig === 'string'
            ? surge.independentConfig
            : DEFAULT_SURGE_INDEPENDENT_CONFIG;
    const independentAst = parseProfileSections(independentConfig);
    const generatedGroups = generateGroups(project, warnings);
    const existingGroups =
        independentAst.sections.find(
            (section) => section.name === 'proxy group',
        )?.body || [];
    const replacements = {
        'proxy group': mergeNamedLines(
            existingGroups,
            generatedGroups,
            surgePolicyGroupName,
        ),
        rule: [],
    };
    let nodeCount = 0;
    if (project.embeddedSource) {
        const proxyBody = await produceBuiltinArtifact({
            type: project.embeddedSource.type,
            name: project.embeddedSource.name,
            platform: 'Surge',
            produceOpts: {
                'include-unsupported-proxy': surge.includeUnsupportedProxy,
            },
        });
        replacements.proxy = `${proxyBody || ''}`
            .split(/\r?\n/)
            .filter(Boolean);
        nodeCount = replacements.proxy.length;
    }
    const independentRules = (
        independentAst.sections.find((section) => section.name === 'rule')
            ?.body || []
    ).filter((line) => line.trim());
    const preservedRules = [
        ...independentRules,
        ...generateLegacyIndependentRules(project).filter(
            (line) => !independentRules.includes(line),
        ),
    ];
    const generatedRules = generateRules(project, ruleSets, warnings);
    replacements.rule = [
        ...preservedRules,
        ...(preservedRules.length && generatedRules.length ? [''] : []),
        ...generatedRules,
    ];
    const ast = replaceManagedSections(independentAst, replacements);
    return {
        body: serializeProfileSections(ast),
        sourceRevision: project.revision,
        stats: {
            nodeCount,
            groupCount: project.groups.length,
            ruleCount: project.rules.filter(
                (rule) =>
                    !rule.disabled && !['comment', 'blank'].includes(rule.kind),
            ).length,
        },
        warnings,
        errors: [],
    };
}

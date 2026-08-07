import {
    parseProfileSections,
    serializeProfileSections,
} from '../../core/profile-sections';
import {
    createTargetOutputs,
    getSharedPolicyGroupType,
} from '../../core/target-capabilities';
import { matchingSubStoreSource } from '../../core/sub-store-source';
import { inferRuleBindingName } from '../../core/rule-binding-name';
import { parseSurgeCsv } from './serializer';

const INLINE_RULE_TYPES = new Set([
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

function parseBoolean(value) {
    if (value === undefined) return undefined;
    return !['0', 'false', 'no'].includes(`${value}`.toLowerCase());
}

function optionValue(value) {
    const index = value.indexOf('=');
    return index < 0
        ? null
        : [value.slice(0, index).trim(), value.slice(index + 1).trim()];
}

function importGroups(section, remoteProxySources, warnings, sourceContext) {
    const groups = [];
    let remark;
    for (const [index, rawLine] of (section?.body || []).entries()) {
        const line = rawLine.trim();
        if (!line) continue;
        if (line.startsWith('#')) {
            remark = line.replace(/^#+\s*/, '');
            continue;
        }
        const separator = line.indexOf('=');
        if (separator < 0) {
            warnings.push({
                path: 'groups',
                line: index + 1,
                message: `Unsupported proxy group line: ${line}`,
            });
            continue;
        }
        const name = line.slice(0, separator).trim();
        const values = parseSurgeCsv(line.slice(separator + 1).trim());
        const outputType = values.shift();
        const type = getSharedPolicyGroupType('surge', outputType);
        if (!type) {
            warnings.push({
                path: `groups.${name}`,
                line: index + 1,
                message: `Unsupported proxy group type: ${outputType}`,
            });
            continue;
        }
        const group = {
            name,
            type,
            members: [],
        };
        if (remark) group.remark = remark;
        remark = undefined;
        for (const value of values) {
            const option = optionValue(value);
            if (!option) {
                group.members.push(
                    ['DIRECT', 'REJECT'].includes(value)
                        ? { kind: 'builtin', value }
                        : { kind: 'group', value },
                );
                continue;
            }
            const [key, optionContent] = option;
            if (key === 'include-all-proxies') {
                group.includeAllProxies = parseBoolean(optionContent);
            } else if (key === 'include-other-group') {
                group.includeOtherGroups = group.includeOtherGroups || [];
                group.includeOtherGroups.push(optionContent);
            } else if (key === 'policy-regex-filter') {
                group.nodeNameRegex = optionContent;
            } else if (key === 'url') {
                group.testUrl = optionContent;
            } else if (key === 'interval') {
                group.interval = Number(optionContent);
            } else if (key === 'tolerance') {
                group.tolerance = Number(optionContent);
            } else if (key === 'timeout') {
                group.timeout = Number(optionContent);
            } else if (key === 'update-interval') {
                group.policyUpdateInterval = Number(optionContent);
            } else if (key === 'policy-path') {
                const sourceName = `remote-${remoteProxySources.length + 1}`;
                const native = matchingSubStoreSource(
                    optionContent,
                    sourceContext,
                );
                remoteProxySources.push(
                    native
                        ? {
                              ...native,
                              name: sourceName,
                              source: { ...native.source },
                          }
                        : {
                              name: sourceName,
                              source: {
                                  kind: 'url',
                                  url: optionContent,
                                  mode: 'passthrough',
                                  target: 'surge',
                              },
                          },
                );
                group.remoteProxySource = sourceName;
            } else if (key === 'icon-url') {
                group.iconUrl = optionContent;
            } else {
                group.targetOptions = group.targetOptions || { surge: {} };
                group.targetOptions.surge = group.targetOptions.surge || {};
                if (key === 'hidden') {
                    group.targetOptions.surge.hidden =
                        parseBoolean(optionContent);
                } else if (key === 'no-alert') {
                    group.targetOptions.surge.noAlert =
                        parseBoolean(optionContent);
                } else if (key === 'evaluate-before-use') {
                    group.targetOptions.surge.evaluateBeforeUse =
                        parseBoolean(optionContent);
                } else if (key === 'persistent') {
                    group.targetOptions.surge.persistent =
                        parseBoolean(optionContent);
                } else if (type === 'subnet' && key === 'default') {
                    group.targetOptions.surge.subnetDefault = optionContent;
                } else if (type === 'subnet' && key === 'cellular') {
                    group.targetOptions.surge.subnetRules =
                        group.targetOptions.surge.subnetRules || [];
                    group.targetOptions.surge.subnetRules.push({
                        expression: 'TYPE:CELLULAR',
                        policy: optionContent,
                    });
                } else if (type === 'subnet' && key) {
                    group.targetOptions.surge.subnetRules =
                        group.targetOptions.surge.subnetRules || [];
                    group.targetOptions.surge.subnetRules.push({
                        expression: key.trim(),
                        policy: optionContent,
                    });
                }
            }
        }
        groups.push(group);
    }
    const groupNames = new Set(groups.map((group) => group.name));
    groups.forEach((group) => {
        group.members.forEach((member) => {
            if (member.kind === 'group' && !groupNames.has(member.value)) {
                member.kind = 'proxy';
            }
        });
    });
    return groups;
}

function importRules(section, ruleSets, warnings, independentRuleLines) {
    return (section?.body || []).flatMap((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) return [];
        const values = parseSurgeCsv(line);
        const type = values[0]?.toUpperCase();
        if (type === 'PROCESS-NAME') {
            // PROCESS-NAME is a Surge-only custom rule. Keep it in the
            // independent [Rule] section instead of the shared rule model.
            independentRuleLines.push(rawLine);
            return [];
        }
        if (type === 'FINAL') {
            return [
                {
                    kind: 'final',
                    policy: values[1],
                    dnsFailed: values.includes('dns-failed'),
                },
            ];
        }
        if (type === 'RULE-SET') {
            const source = values[1];
            const baseName = `rule-set-${ruleSets.length + 1}`;
            const ruleSet = {
                name: baseName,
                source: ['SYSTEM', 'LAN'].includes(source)
                    ? { kind: 'builtin', value: source }
                    : { kind: 'url', url: source, target: 'surge' },
            };
            const interval = values
                .slice(3)
                .find((value) => value.startsWith('update-interval='));
            if (interval)
                ruleSet.updateInterval = Number(interval.split('=')[1]);
            ruleSets.push(ruleSet);
            return [
                {
                    kind: 'remote',
                    name: inferRuleBindingName(source, baseName),
                    ruleSet: baseName,
                    policy: values[2],
                    noResolve: values.includes('no-resolve'),
                },
            ];
        }
        if (INLINE_RULE_TYPES.has(type)) {
            return [
                {
                    kind: 'inline',
                    type,
                    value: values[1],
                    policy: values[2],
                    noResolve: values.includes('no-resolve'),
                },
            ];
        }
        warnings.push({
            path: 'rules',
            line: index + 1,
            message: `Unsupported rule line: ${line}`,
        });
        return [];
    });
}

export function importSurgeConfig(content, sourceContext) {
    const ast = parseProfileSections(content);
    const byName = new Map(
        ast.sections.map((section) => [section.name, section]),
    );
    const warnings = [];
    const remoteProxySources = [];
    const ruleSets = [];
    const independentRuleLines = [];
    const groups = importGroups(
        byName.get('proxy group'),
        remoteProxySources,
        warnings,
        sourceContext,
    );
    const rules = importRules(
        byName.get('rule'),
        ruleSets,
        warnings,
        independentRuleLines,
    );
    const independentSections = ast.sections.filter(
        (section) => !['proxy', 'proxy group', 'rule'].includes(section.name),
    );
    if (independentRuleLines.length) {
        const ruleSection = {
            title: '[Rule]',
            name: 'rule',
            body: independentRuleLines,
        };
        const mitmIndex = independentSections.findIndex(
            (section) => section.name === 'mitm',
        );
        independentSections.splice(
            mitmIndex < 0 ? independentSections.length : mitmIndex,
            0,
            ruleSection,
        );
    }
    const independentConfig = serializeProfileSections({
        ...ast,
        sections: independentSections,
    });
    return {
        project: {
            remoteProxySources,
            groups,
            rules,
            outputs: createTargetOutputs('surge', { independentConfig }),
        },
        ruleSets,
        detected: {
            groupCount: groups.length,
            ruleCount: rules.filter(
                (rule) => !['comment', 'blank'].includes(rule.kind),
            ).length,
            remoteProxySources: remoteProxySources.length,
        },
        warnings,
    };
}

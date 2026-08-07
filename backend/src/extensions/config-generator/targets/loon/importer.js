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
import { parseSurgeCsv } from '../surge/serializer';

const MANAGED_SECTIONS = new Set([
    'remote proxy',
    'remote filter',
    'proxy group',
    'rule',
    'remote rule',
]);
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

function booleanValue(value, fallback = undefined) {
    if (value === undefined) return fallback;
    return !['0', 'false', 'no', 'off'].includes(
        `${value}`.trim().toLowerCase(),
    );
}

function assignment(value) {
    const separator = `${value || ''}`.indexOf('=');
    if (separator < 0) return null;
    return [
        value.slice(0, separator).trim(),
        value.slice(separator + 1).trim(),
    ];
}

function uniqueName(value, used, fallback) {
    const base = `${value || fallback}`.trim() || fallback;
    let candidate = base;
    let index = 2;
    while (used.has(candidate.toLowerCase())) {
        candidate = `${base}-${index++}`;
    }
    used.add(candidate.toLowerCase());
    return candidate;
}

function isHttpUrl(value) {
    try {
        const url = new URL(value);
        return ['http:', 'https:'].includes(url.protocol);
    } catch (_) {
        return false;
    }
}

function importRemoteProxySources(section, warnings, sourceContext) {
    const sources = [];
    const byAlias = new Map();
    const usedNames = new Set();

    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || line.startsWith(';')) return;
        const separator = line.indexOf('=');
        if (separator <= 0) {
            warnings.push({
                path: 'remoteProxySources',
                line: index + 1,
                message: `Unsupported Loon Remote Proxy entry: ${line}`,
            });
            return;
        }
        const rawAlias = line.slice(0, separator).trim();
        const values = parseSurgeCsv(line.slice(separator + 1));
        const url = values.shift();
        if (!rawAlias || !isHttpUrl(url)) {
            warnings.push({
                path: `remoteProxySources.${rawAlias || index}`,
                line: index + 1,
                message:
                    'Loon Remote Proxy entries require an alias and an absolute HTTP(S) URL; this entry was omitted.',
            });
            return;
        }
        const name = uniqueName(rawAlias, usedNames, 'remote');
        const native = matchingSubStoreSource(url, sourceContext);
        const source = native
            ? {
                  ...native,
                  name,
                  source: { ...native.source },
              }
            : {
                  name,
                  source: {
                      kind: 'url',
                      url,
                      mode: 'passthrough',
                      target: 'loon',
                  },
              };
        const options = Object.fromEntries(
            values.map(assignment).filter(Boolean),
        );
        source.enabled = booleanValue(options.enabled, true);
        if (!native) {
            warnings.push({
                path: `remoteProxySources.${name}`,
                line: index + 1,
                message:
                    'This URL is bound to Loon only. Choose a Sub-Store source or automatic conversion before generating another client format.',
            });
        }
        sources.push(source);
        byAlias.set(rawAlias, source);
    });

    return { sources, byAlias };
}

function importRemoteFilters(section, remoteSources, warnings) {
    const filters = new Map();
    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#') || line.startsWith(';')) return;
        const separator = line.indexOf('=');
        if (separator <= 0) {
            warnings.push({
                path: 'remoteFilters',
                line: index + 1,
                message: `Unsupported Loon Remote Filter entry: ${line}`,
            });
            return;
        }
        const alias = line.slice(0, separator).trim();
        const values = parseSurgeCsv(line.slice(separator + 1));
        const filterType = `${values.shift() || ''}`.trim().toLowerCase();
        const optionValues = values.filter((value) => assignment(value));
        const options = Object.fromEntries(
            optionValues.map(assignment).filter(Boolean),
        );
        const sourceAliases = values.filter(
            (value) => !assignment(value) && remoteSources.has(value),
        );
        if (!alias || !sourceAliases.length) {
            warnings.push({
                path: `remoteFilters.${alias || index}`,
                line: index + 1,
                message:
                    'This Loon Remote Filter does not reference an imported Remote Proxy source and was omitted.',
            });
            return;
        }
        if (sourceAliases.length > 1) {
            warnings.push({
                path: `remoteFilters.${alias}`,
                line: index + 1,
                message:
                    'The shared model supports one remote proxy source per policy group. Only the first source from this multi-source Loon filter was imported.',
            });
        }
        const filterKey =
            options.FilterKey ||
            options['filter-key'] ||
            options.filterKey ||
            options.filter;
        let nodeNameRegex;
        if (filterType === 'nameregex') {
            nodeNameRegex = filterKey;
        } else if (filterType === 'namekeyword' && filterKey) {
            nodeNameRegex = `${filterKey}`.replace(
                /[.*+?^${}()|[\]\\]/g,
                '\\$&',
            );
            warnings.push({
                path: `remoteFilters.${alias}`,
                line: index + 1,
                message:
                    'Loon NameKeyword was converted to an escaped shared regular expression.',
            });
        } else if (filterType !== 'nodeselect') {
            warnings.push({
                path: `remoteFilters.${alias}`,
                line: index + 1,
                message: `Unsupported Loon Remote Filter type ${filterType}; the first source was kept without this filter.`,
            });
        }
        filters.set(alias, {
            source: remoteSources.get(sourceAliases[0]),
            nodeNameRegex,
        });
    });
    return filters;
}

function parseConditional(value, policy) {
    const condition = `${value || ''}`.trim();
    const target = `${policy || ''}`.trim();
    if (!condition || !target) return null;
    return {
        kind: 'conditional',
        value: `${condition}:${target}`,
        policy: target,
    };
}

function importGroups(section, remoteSources, remoteFilters, warnings) {
    const groups = [];
    let remark;

    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line) return;
        if (line.startsWith('#') || line.startsWith(';')) {
            remark = line.replace(/^[#;]+\s*/, '');
            return;
        }
        const separator = line.indexOf('=');
        if (separator <= 0) {
            warnings.push({
                path: 'groups',
                line: index + 1,
                message: `Unsupported Loon Proxy Group entry: ${line}`,
            });
            return;
        }
        const name = line.slice(0, separator).trim();
        const values = parseSurgeCsv(line.slice(separator + 1));
        const outputType = `${values.shift() || ''}`.trim().toLowerCase();
        const type = getSharedPolicyGroupType('loon', outputType);
        if (!name || !type) {
            warnings.push({
                path: `groups.${name || index}`,
                line: index + 1,
                message: `Unsupported Loon policy group type: ${outputType}`,
            });
            remark = undefined;
            return;
        }

        const group = { name, type, members: [] };
        if (remark) group.remark = remark;
        remark = undefined;
        const remoteBindings = [];

        values.forEach((value) => {
            const option = assignment(value);
            if (!option) {
                if (remoteFilters.has(value)) {
                    remoteBindings.push(remoteFilters.get(value));
                } else if (remoteSources.has(value)) {
                    remoteBindings.push({ source: remoteSources.get(value) });
                } else {
                    group.members.push(
                        ['DIRECT', 'REJECT'].includes(value.toUpperCase())
                            ? {
                                  kind: 'builtin',
                                  value: value.toUpperCase(),
                              }
                            : { kind: 'group', value },
                    );
                }
                return;
            }

            const [rawKey, optionValue] = option;
            const key = rawKey.toLowerCase().replace(/\s+/g, '-');
            if (key === 'url') {
                group.testUrl = optionValue;
            } else if (key === 'interval') {
                group.interval = Number(optionValue);
            } else if (key === 'tolerance') {
                group.tolerance = Number(optionValue);
            } else if (key === 'max-timeout') {
                const milliseconds = Number(optionValue);
                if (Number.isFinite(milliseconds)) {
                    group.timeout = Math.max(1, Math.ceil(milliseconds / 1000));
                    if (milliseconds % 1000 !== 0) {
                        warnings.push({
                            path: `groups.${name}.max-timeout`,
                            line: index + 1,
                            message:
                                'Loon max-timeout was rounded up to whole seconds for the shared model.',
                        });
                    }
                }
            } else if (key === 'algorithm') {
                group.targetOptions = group.targetOptions || {};
                group.targetOptions.loon = group.targetOptions.loon || {};
                group.targetOptions.loon.algorithm = optionValue;
            } else if (type === 'ssid') {
                const conditional = parseConditional(rawKey, optionValue);
                if (conditional) group.members.push(conditional);
            } else {
                warnings.push({
                    path: `groups.${name}.${rawKey}`,
                    line: index + 1,
                    message: `The Loon ${rawKey} policy-group option is target-specific and was omitted.`,
                });
            }
        });

        if (remoteBindings.length) {
            const binding = remoteBindings[0];
            group.remoteProxySource = binding.source.name;
            if (binding.nodeNameRegex)
                group.nodeNameRegex = binding.nodeNameRegex;
            if (remoteBindings.length > 1) {
                warnings.push({
                    path: `groups.${name}.remoteProxySource`,
                    line: index + 1,
                    message:
                        'The shared model supports one remote proxy source per policy group. Only the first Loon source/filter member was imported.',
                });
            }
        }
        groups.push(group);
    });

    const groupNames = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    groups.forEach((group) => {
        group.members = group.members.map((member) => {
            if (member.kind === 'conditional') {
                const policy = groupNames.get(member.policy.toLowerCase());
                return policy
                    ? {
                          ...member,
                          policy,
                          value: `${member.value.slice(
                              0,
                              member.value.lastIndexOf(':'),
                          )}:${policy}`,
                      }
                    : member;
            }
            if (member.kind !== 'group') return member;
            const groupName = groupNames.get(member.value.toLowerCase());
            return groupName
                ? { kind: 'group', value: groupName }
                : { kind: 'proxy', value: member.value };
        });
    });
    return groups;
}

function importedPolicy(value, groups) {
    const text = `${value || ''}`.trim();
    const builtin = text.toUpperCase();
    if (['DIRECT', 'REJECT'].includes(builtin)) return builtin;
    return groups.get(text.toLowerCase()) || text;
}

function importLocalRules(section, ruleSets, groups, warnings) {
    const rules = [];
    const usedRuleSetNames = new Set(ruleSets.map((ruleSet) => ruleSet.name));
    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line) {
            rules.push({ kind: 'blank' });
            return;
        }
        if (line.startsWith('#') || line.startsWith(';')) {
            rules.push({
                kind: 'comment',
                text: line.replace(/^[#;]+\s*/, ''),
            });
            return;
        }
        const values = parseSurgeCsv(line);
        const type = `${values.shift() || ''}`.trim().toUpperCase();
        if (type === 'FINAL') {
            rules.push({
                kind: 'final',
                policy: importedPolicy(values[0], groups),
            });
            return;
        }
        if (type === 'RULE-SET' && isHttpUrl(values[0])) {
            const name = uniqueName(
                inferRuleBindingName(
                    values[0],
                    `rule-set-${ruleSets.length + 1}`,
                ),
                usedRuleSetNames,
                `rule-set-${ruleSets.length + 1}`,
            );
            ruleSets.push({
                name,
                source: { kind: 'url', url: values[0], target: 'loon' },
            });
            rules.push({
                kind: 'remote',
                name,
                ruleSet: name,
                policy: importedPolicy(values[1], groups),
                ...(values.includes('no-resolve') ? { noResolve: true } : {}),
            });
            return;
        }
        if (INLINE_RULE_TYPES.has(type) && values[0] && values[1]) {
            rules.push({
                kind: 'inline',
                type,
                value: values[0],
                policy: importedPolicy(values[1], groups),
                ...(values.includes('no-resolve') ? { noResolve: true } : {}),
            });
            return;
        }
        warnings.push({
            path: 'rules',
            line: index + 1,
            message: `Unsupported Loon local rule: ${line}`,
        });
    });
    return rules;
}

function importRemoteRules(section, ruleSets, groups, warnings, existingRules) {
    const rules = [];
    const usedNames = new Set(ruleSets.map((ruleSet) => ruleSet.name));
    let pendingName;
    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line) {
            pendingName = undefined;
            return;
        }
        if (line.startsWith('#') || line.startsWith(';')) {
            const text = line.replace(/^[#;]+\s*/, '');
            if (!/^=+/.test(text)) pendingName = text;
            return;
        }
        const values = parseSurgeCsv(line);
        const url = values.shift();
        if (!isHttpUrl(url)) {
            warnings.push({
                path: 'remoteRules',
                line: index + 1,
                message:
                    'Loon Remote Rule entries require an absolute HTTP(S) URL; this entry was omitted.',
            });
            pendingName = undefined;
            return;
        }
        const options = Object.fromEntries(
            values.map(assignment).filter(Boolean),
        );
        const policy = importedPolicy(
            options.policy || options['force-policy'],
            groups,
        );
        if (!policy) {
            warnings.push({
                path: 'remoteRules',
                line: index + 1,
                message: 'This Loon Remote Rule has no policy and was omitted.',
            });
            pendingName = undefined;
            return;
        }
        const inferredName =
            pendingName ||
            options.tag ||
            inferRuleBindingName(url, `rule-set-${ruleSets.length + 1}`);
        const name = uniqueName(
            inferredName,
            usedNames,
            `rule-set-${ruleSets.length + 1}`,
        );
        ruleSets.push({
            name,
            source: { kind: 'url', url, target: 'loon' },
        });
        rules.push({
            kind: 'remote',
            name,
            ruleSet: name,
            policy,
            ...(booleanValue(options.enabled, true) ? {} : { disabled: true }),
        });
        pendingName = undefined;
    });
    return [...existingRules, ...rules];
}

function normalizePolicyReferences(groups, rules, warnings) {
    const groupNames = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    rules.forEach((rule, index) => {
        if (!('policy' in rule)) return;
        const policy = importedPolicy(rule.policy, groupNames);
        rule.policy = policy;
        if (
            !['DIRECT', 'REJECT'].includes(policy) &&
            !groupNames.has(policy.toLowerCase())
        ) {
            warnings.push({
                path: `rules[${index}].policy`,
                message: `The Loon policy ${policy} is not an imported policy group. Review this rule before saving.`,
            });
        }
    });
}

export function importLoonConfig(content, sourceContext) {
    const ast = parseProfileSections(content);
    const byName = new Map(
        ast.sections.map((section) => [section.name, section]),
    );
    const warnings = [];
    const { sources: remoteProxySources, byAlias: remoteSourcesByAlias } =
        importRemoteProxySources(
            byName.get('remote proxy'),
            warnings,
            sourceContext,
        );
    const remoteFilters = importRemoteFilters(
        byName.get('remote filter'),
        remoteSourcesByAlias,
        warnings,
    );
    const groups = importGroups(
        byName.get('proxy group'),
        remoteSourcesByAlias,
        remoteFilters,
        warnings,
    );
    const groupNames = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    const ruleSets = [];
    let rules = importLocalRules(
        byName.get('rule'),
        ruleSets,
        groupNames,
        warnings,
    );
    rules = importRemoteRules(
        byName.get('remote rule'),
        ruleSets,
        groupNames,
        warnings,
        rules,
    );
    normalizePolicyReferences(groups, rules, warnings);

    const independentConfig = serializeProfileSections({
        ...ast,
        sections: ast.sections.filter(
            (section) => !MANAGED_SECTIONS.has(section.name),
        ),
    });
    return {
        project: {
            remoteProxySources,
            groups,
            rules,
            outputs: createTargetOutputs('loon', { independentConfig }),
        },
        ruleSets,
        detected: {
            groupCount: groups.length,
            ruleCount: rules.filter(
                (rule) => !['comment', 'blank'].includes(rule.kind),
            ).length,
            remoteProxySources: remoteProxySources.length,
            proxyCount: (byName.get('proxy')?.body || []).filter(
                (line) => line.trim() && !/^[#;]/.test(line.trim()),
            ).length,
        },
        warnings,
    };
}

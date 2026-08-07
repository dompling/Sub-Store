import {
    parseProfileSections,
    serializeProfileSections,
} from '../../core/profile-sections';
import {
    createTargetOutputs,
    getSharedPolicyGroupType,
    policyGroupSupportsField,
} from '../../core/target-capabilities';
import { matchingSubStoreSource } from '../../core/sub-store-source';

const MANAGED_SECTIONS = new Set([
    'server_local',
    'server_remote',
    'policy',
    'filter_local',
    'filter_remote',
]);

const RULE_TYPES = {
    host: 'DOMAIN',
    'host-suffix': 'DOMAIN-SUFFIX',
    'host-keyword': 'DOMAIN-KEYWORD',
    'ip-cidr': 'IP-CIDR',
    'ip6-cidr': 'IP-CIDR6',
    geoip: 'GEOIP',
    'user-agent': 'USER-AGENT',
    'url-regex': 'URL-REGEX',
};

function bool(value, fallback = undefined) {
    if (value === undefined) return fallback;
    return !['0', 'false', 'no'].includes(`${value}`.trim().toLowerCase());
}

function splitLine(line) {
    return line
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
}

function optionMap(values) {
    return values.reduce((options, value) => {
        const index = value.indexOf('=');
        if (index >= 0)
            options[value.slice(0, index).trim().toLowerCase()] = value
                .slice(index + 1)
                .trim();
        return options;
    }, {});
}

function nonOptions(values) {
    return values.filter((value) => value.indexOf('=') < 0);
}

function escapeRegex(value) {
    return `${value}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function normalizePolicy(value, groupNames) {
    const text = `${value || ''}`.trim();
    const builtin = text.toUpperCase();
    if (builtin === 'DIRECT' || builtin === 'REJECT') return builtin;
    return groupNames.get(text.toLowerCase()) || text;
}

function ensureImplicitProxyGroup(groups, rules, remoteSources, warnings) {
    const hasProxyReference =
        groups.some((group) =>
            (group.members || []).some(
                (member) => `${member.value}`.toUpperCase() === 'PROXY',
            ),
        ) ||
        rules.some((rule) => `${rule.policy || ''}`.toUpperCase() === 'PROXY');
    const existing = groups.some(
        (group) => group.name.toUpperCase() === 'PROXY',
    );
    if (!hasProxyReference || existing) return;

    const source = remoteSources[0];
    groups.push({
        name: 'PROXY',
        type: 'select',
        members: [],
        ...(source ? { remoteProxySource: source.name } : {}),
    });
    warnings.push({
        path: 'policy.PROXY',
        message:
            'Added an editable PROXY policy group for Quantumult X implicit PROXY references.',
    });
}

function normalizePolicyReferences(groups, rules) {
    const groupNames = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    groups.forEach((group) => {
        group.members = (group.members || []).map((member) => {
            const value = normalizePolicy(member.value, groupNames);
            if (value === 'DIRECT' || value === 'REJECT')
                return { kind: 'builtin', value };
            return groupNames.has(`${value}`.toLowerCase())
                ? { kind: 'group', value }
                : { ...member, value };
        });
    });
    rules.forEach((rule) => {
        if (rule.policy) rule.policy = normalizePolicy(rule.policy, groupNames);
    });
}

function importRemoteSources(section, warnings, sourceContext) {
    const sources = [];
    const byTag = new Map();
    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) return;
        const values = splitLine(line);
        const url = values.shift();
        if (!/^https?:\/\//i.test(url || '')) {
            warnings.push({
                path: 'server_remote',
                line: index + 1,
                message: `Unsupported server_remote URL: ${url || line}`,
            });
            return;
        }
        const options = optionMap(values);
        const baseTag = options.tag || `remote-${sources.length + 1}`;
        let tag = baseTag;
        let number = 2;
        while (byTag.has(tag)) tag = `${baseTag}-${number++}`;

        const native = matchingSubStoreSource(url, sourceContext);
        const source = native
            ? { ...native, name: tag, source: { ...native.source } }
            : {
                  name: tag,
                  source: {
                      kind: 'url',
                      url,
                      mode: 'passthrough',
                      target: 'qx',
                  },
              };
        source.enabled = bool(options.enabled, true);
        source.targetOptions = {
            ...(source.targetOptions || {}),
            qx: {
                ...(source.targetOptions?.qx || {}),
                tag,
                ...(options['update-interval']
                    ? { updateInterval: Number(options['update-interval']) }
                    : {}),
                ...(options['opt-parser'] !== undefined
                    ? { optParser: bool(options['opt-parser']) }
                    : {}),
            },
        };
        if (!native) {
            warnings.push({
                path: `server_remote.${tag}`,
                line: index + 1,
                message:
                    'This QX URL is only bound to QX. Select a Sub-Store source before generating Surge.',
            });
        }
        sources.push(source);
        byTag.set(tag, source);
    });
    return { sources, byTag };
}

function sourceFromResourceRegex(value, remoteSources) {
    if (!value) return undefined;
    for (const tag of remoteSources.keys()) {
        if (value === `^${escapeRegex(tag)}$`) return tag;
    }
    const exact = value.match(/^\^(.+)\$$/);
    if (exact && remoteSources.has(exact[1])) return exact[1];
    if (remoteSources.has(value)) return value;
    if (value === '.*' && remoteSources.size === 1)
        return remoteSources.keys().next().value;
    return undefined;
}

function importPolicies(section, remoteSources, warnings) {
    const groups = [];
    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) return;
        const values = splitLine(line);
        const first = values.shift() || '';
        const separator = first.indexOf('=');
        const qxType = first.slice(0, separator).trim().toLowerCase();
        const name = separator >= 0 ? first.slice(separator + 1).trim() : '';
        const type = getSharedPolicyGroupType('qx', qxType);
        if (!name || !type) {
            warnings.push({
                path: 'policy',
                line: index + 1,
                message: `Unsupported Quantumult X policy: ${line}`,
            });
            return;
        }
        const options = optionMap(values);
        const group = {
            name,
            type,
            members: nonOptions(values).map((value) =>
                ['DIRECT', 'REJECT'].includes(value.toUpperCase())
                    ? { kind: 'builtin', value: value.toUpperCase() }
                    : { kind: 'group', value },
            ),
        };
        if (options['server-tag-regex']) {
            if (policyGroupSupportsField('qx', type, 'nodeNameRegex')) {
                group.includeAllProxies = true;
                if (options['server-tag-regex'] !== '.*') {
                    group.nodeNameRegex = options['server-tag-regex'];
                }
            } else {
                warnings.push({
                    path: `policy.${name}.server-tag-regex`,
                    line: index + 1,
                    message: `Quantumult X ${qxType} does not support server-tag-regex; it was omitted.`,
                });
            }
        }
        if (options['check-interval']) {
            if (policyGroupSupportsField('qx', type, 'interval')) {
                group.interval = Number(options['check-interval']);
            } else {
                warnings.push({
                    path: `policy.${name}.check-interval`,
                    line: index + 1,
                    message: `Quantumult X ${qxType} does not support check-interval; it was omitted.`,
                });
            }
        }
        if (options.tolerance) {
            if (policyGroupSupportsField('qx', type, 'tolerance')) {
                group.tolerance = Number(options.tolerance);
            } else {
                warnings.push({
                    path: `policy.${name}.tolerance`,
                    line: index + 1,
                    message: `Quantumult X ${qxType} does not support tolerance; it was omitted.`,
                });
            }
        }
        if (options['alive-checking'] !== undefined) {
            if (policyGroupSupportsField('qx', type, 'aliveChecking')) {
                group.targetOptions = group.targetOptions || {};
                group.targetOptions.qx = {
                    ...(group.targetOptions.qx || {}),
                    aliveChecking: bool(options['alive-checking']),
                };
            } else {
                warnings.push({
                    path: `policy.${name}.alive-checking`,
                    line: index + 1,
                    message: `Quantumult X ${qxType} does not support alive-checking; it was omitted.`,
                });
            }
        }
        if (options['img-url']) group.iconUrl = options['img-url'];
        const remoteSource = sourceFromResourceRegex(
            options['resource-tag-regex'],
            remoteSources,
        );
        if (remoteSource) {
            group.remoteProxySource = remoteSource;
        } else if (options['resource-tag-regex']) {
            group.targetOptions = group.targetOptions || {};
            group.targetOptions.qx = {
                ...(group.targetOptions.qx || {}),
                resourceTagRegex: options['resource-tag-regex'],
            };
            warnings.push({
                path: `policy.${name}`,
                line: index + 1,
                message: `Unable to bind resource-tag-regex ${options['resource-tag-regex']} to one imported source; the raw Quantumult X expression was preserved.`,
            });
        }
        groups.push(group);
    });
    const names = new Map(
        groups.map((group) => [group.name.toLowerCase(), group.name]),
    );
    groups.forEach((group) => {
        group.members = group.members.map((member) => {
            if (member.kind !== 'group') return member;
            const canonicalName = names.get(member.value.toLowerCase());
            if (canonicalName) return { ...member, value: canonicalName };

            if (group.type === 'ssid') {
                const separator = member.value.lastIndexOf(':');
                const rawPolicy =
                    separator >= 0 ? member.value.slice(separator + 1) : '';
                const policy = names.get(rawPolicy.toLowerCase());
                if (policy) {
                    return {
                        kind: 'conditional',
                        value: `${member.value.slice(
                            0,
                            separator + 1,
                        )}${policy}`,
                        policy,
                    };
                }
            }

            return { kind: 'proxy', value: member.value };
        });
    });
    return groups;
}

function importRemoteRules(section, warnings) {
    const ruleSets = [];
    const rules = [];
    const usedNames = new Set();
    (section?.body || []).forEach((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) return;
        const values = splitLine(line);
        const sourceValue = values.shift();
        const options = optionMap(values);
        const insertedResource = bool(options['inserted-resource'], false);
        const builtin =
            insertedResource && `${sourceValue}`.toUpperCase() === 'FILTER_LAN'
                ? 'LAN'
                : null;
        if (
            (!builtin && !/^https?:\/\//i.test(sourceValue || '')) ||
            !options['force-policy']
        ) {
            warnings.push({
                path: 'filter_remote',
                line: index + 1,
                message: `Unsupported Quantumult X remote filter: ${line}`,
            });
            return;
        }
        const baseName = options.tag || `rule-set-${ruleSets.length + 1}`;
        let name = baseName;
        let number = 2;
        while (usedNames.has(name)) name = `${baseName}-${number++}`;
        usedNames.add(name);
        ruleSets.push({
            name,
            source: builtin
                ? { kind: 'builtin', value: builtin }
                : { kind: 'url', url: sourceValue, target: 'qx' },
            ...(options['update-interval']
                ? { updateInterval: Number(options['update-interval']) }
                : {}),
            ...(options['opt-parser'] !== undefined
                ? {
                      targetOptions: {
                          qx: { optParser: bool(options['opt-parser']) },
                      },
                  }
                : {}),
        });
        rules.push({
            kind: 'remote',
            name: baseName,
            ruleSet: name,
            policy: options['force-policy'],
            disabled: bool(options.enabled, true) === false,
        });
    });
    return { ruleSets, rules };
}

function importLocalRules(section, warnings) {
    return (section?.body || []).flatMap((rawLine, index) => {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) return [];
        const values = splitLine(line);
        const type = values.shift()?.toLowerCase();
        if (type === 'final' && values[0])
            return [{ kind: 'final', policy: values[0] }];
        const ruleType = RULE_TYPES[type];
        if (ruleType && values[0] && values[1]) {
            return [
                {
                    kind: 'inline',
                    type: ruleType,
                    value: values[0],
                    policy: values[1],
                },
            ];
        }
        warnings.push({
            path: 'filter_local',
            line: index + 1,
            message: `Unsupported Quantumult X local filter: ${line}`,
        });
        return [];
    });
}

export function importQXConfig(content, sourceContext = {}) {
    const ast = parseProfileSections(content);
    const byName = new Map(
        ast.sections.map((section) => [section.name, section]),
    );
    const warnings = [];
    const { sources, byTag } = importRemoteSources(
        byName.get('server_remote'),
        warnings,
        sourceContext,
    );
    const groups = importPolicies(byName.get('policy'), byTag, warnings);
    const { ruleSets, rules: remoteRules } = importRemoteRules(
        byName.get('filter_remote'),
        warnings,
    );
    const localRules = importLocalRules(byName.get('filter_local'), warnings);
    // QX keeps local and remote filters in separate sections.  The shared
    // model requires FINAL to be last, so place it after imported remote rules.
    const finalRules = localRules.filter((rule) => rule.kind === 'final');
    const rules = [
        ...localRules.filter((rule) => rule.kind !== 'final'),
        ...remoteRules,
        ...finalRules,
    ];
    ensureImplicitProxyGroup(groups, rules, sources, warnings);
    normalizePolicyReferences(groups, rules);
    const independentConfig = serializeProfileSections({
        ...ast,
        sections: ast.sections.filter(
            (section) => !MANAGED_SECTIONS.has(section.name),
        ),
    });
    return {
        project: {
            remoteProxySources: sources,
            groups,
            rules,
            outputs: createTargetOutputs('qx', { independentConfig }),
        },
        ruleSets,
        detected: {
            groupCount: groups.length,
            ruleCount: rules.filter(
                (rule) => !['comment', 'blank'].includes(rule.kind),
            ).length,
            remoteProxySources: sources.length,
        },
        warnings,
    };
}

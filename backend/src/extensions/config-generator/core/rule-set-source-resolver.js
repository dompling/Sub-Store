import { getTargetDisplayName, normalizeTargetId } from './target-capabilities';

const BLACKMATRIX7_TARGET_DIRECTORIES = {
    surge: 'Surge',
    qx: 'QuantumultX',
    clash: 'Clash',
    loon: 'Loon',
};

const BLACKMATRIX7_TARGET_EXTENSIONS = {
    surge: '.list',
    qx: '.list',
    clash: '.yaml',
    loon: '.list',
};

const BLACKMATRIX7_DIRECTORY_TARGETS = Object.fromEntries(
    Object.entries(BLACKMATRIX7_TARGET_DIRECTORIES).map(
        ([target, directory]) => [directory, target],
    ),
);

function matchBlackmatrix7IosRuleScript(url) {
    if (url.hostname.toLowerCase() !== 'raw.githubusercontent.com') return null;
    const segments = url.pathname.split('/').filter(Boolean);
    if (
        `${segments[0] || ''}`.toLowerCase() !== 'blackmatrix7' ||
        `${segments[1] || ''}`.toLowerCase() !== 'ios_rule_script'
    )
        return null;

    const ruleIndex = segments.findIndex(
        (segment, index) =>
            // raw.githubusercontent.com URLs always include at least one ref
            // segment between the repository and its path. Requiring the
            // provider directory after that ref avoids treating a branch
            // literally named "rule" as the ios_rule_script layout.
            index >= 3 &&
            segment === 'rule' &&
            BLACKMATRIX7_DIRECTORY_TARGETS[segments[index + 1]],
    );
    if (ruleIndex < 0 || !segments[ruleIndex + 2]) return null;
    return {
        segments,
        targetDirectoryIndex: ruleIndex + 1,
        sourceTarget: BLACKMATRIX7_DIRECTORY_TARGETS[segments[ruleIndex + 1]],
    };
}

const RULE_SET_PROVIDERS = [
    {
        id: 'blackmatrix7-ios-rule-script',
        match: matchBlackmatrix7IosRuleScript,
        resolve(url, match, target) {
            const targetDirectory = BLACKMATRIX7_TARGET_DIRECTORIES[target];
            if (!targetDirectory) return null;
            const resolved = new URL(url);
            const segments = [...match.segments];
            segments[match.targetDirectoryIndex] = targetDirectory;
            const targetExtension = BLACKMATRIX7_TARGET_EXTENSIONS[target];
            if (targetExtension) {
                const fileIndex = segments.length - 1;
                segments[fileIndex] = `${segments[fileIndex].replace(
                    /\.[^.]*$/,
                    '',
                )}${targetExtension}`;
            }
            resolved.pathname = `/${segments.join('/')}`;
            return resolved.toString();
        },
    },
];

const SURGE_SYSTEM_PORTABLE_RULES = [
    { type: 'USER-AGENT', value: '*com.apple.mobileme.fmip1' },
    { type: 'USER-AGENT', value: '*WeatherFoundation*' },
    { type: 'USER-AGENT', value: '%E5%9C%B0%E5%9B%BE*' },
    { type: 'USER-AGENT', value: '%E8%AE%BE%E7%BD%AE*' },
    { type: 'USER-AGENT', value: 'com.apple.geod*' },
    { type: 'USER-AGENT', value: 'com.apple.Maps' },
    { type: 'USER-AGENT', value: 'FindMyFriends*' },
    { type: 'USER-AGENT', value: 'FindMyiPhone*' },
    { type: 'USER-AGENT', value: 'FMDClient*' },
    { type: 'USER-AGENT', value: 'FMFD*' },
    { type: 'USER-AGENT', value: 'fmflocatord*' },
    { type: 'USER-AGENT', value: 'geod*' },
    { type: 'USER-AGENT', value: 'locationd*' },
    { type: 'USER-AGENT', value: 'Maps*' },
    { type: 'DOMAIN', value: 'api.smoot.apple.com' },
    { type: 'DOMAIN', value: 'captive.apple.com' },
    { type: 'DOMAIN', value: 'configuration.apple.com' },
    { type: 'DOMAIN', value: 'guzzoni.apple.com' },
    { type: 'DOMAIN', value: 'smp-device-content.apple.com' },
    { type: 'DOMAIN', value: 'xp.apple.com' },
    { type: 'DOMAIN-SUFFIX', value: 'ess.apple.com' },
    { type: 'DOMAIN-SUFFIX', value: 'push-apple.com.akadns.net' },
    { type: 'DOMAIN-SUFFIX', value: 'push.apple.com' },
    { type: 'DOMAIN', value: 'aod.itunes.apple.com' },
    { type: 'DOMAIN', value: 'mesu.apple.com' },
    { type: 'DOMAIN', value: 'api.smoot.apple.cn' },
    { type: 'DOMAIN', value: 'gs-loc.apple.com' },
    { type: 'DOMAIN', value: 'mvod.itunes.apple.com' },
    { type: 'DOMAIN', value: 'streamingaudio.itunes.apple.com' },
    { type: 'DOMAIN-SUFFIX', value: 'lcdn-locator.apple.com' },
    { type: 'DOMAIN-SUFFIX', value: 'lcdn-registration.apple.com' },
    { type: 'DOMAIN-SUFFIX', value: 'ls.apple.com' },
];

const CLASH_LAN_PORTABLE_RULES = [
    { type: 'IP-CIDR', value: '10.0.0.0/8', noResolve: true },
    { type: 'IP-CIDR', value: '100.64.0.0/10', noResolve: true },
    { type: 'IP-CIDR', value: '127.0.0.0/8', noResolve: true },
    { type: 'IP-CIDR', value: '169.254.0.0/16', noResolve: true },
    { type: 'IP-CIDR', value: '172.16.0.0/12', noResolve: true },
    { type: 'IP-CIDR', value: '192.168.0.0/16', noResolve: true },
    { type: 'IP-CIDR', value: '224.0.0.0/4', noResolve: true },
    { type: 'IP-CIDR6', value: '::1/128', noResolve: true },
    { type: 'IP-CIDR6', value: 'fc00::/7', noResolve: true },
    { type: 'IP-CIDR6', value: 'fe80::/10', noResolve: true },
];

const CLASH_SYSTEM_PORTABLE_RULES = SURGE_SYSTEM_PORTABLE_RULES.filter((rule) =>
    ['DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'].includes(rule.type),
);

function warning(message) {
    return { message };
}

export function resolveRuleSetUrl(ruleSet, target) {
    const targetId = normalizeTargetId(target);
    const source = ruleSet?.source;
    if (!targetId || source?.kind !== 'url') return { url: null };

    let parsed;
    try {
        parsed = new URL(source.url);
    } catch (_) {
        return {
            url: null,
            warning: warning('Rule-set URL is invalid and was omitted.'),
        };
    }

    for (const provider of RULE_SET_PROVIDERS) {
        const match = provider.match(parsed);
        if (!match) continue;
        const resolvedUrl = provider.resolve(parsed, match, targetId);
        if (resolvedUrl) {
            return {
                url: resolvedUrl,
                provider: provider.id,
                sourceTarget: match.sourceTarget,
            };
        }
        return {
            url: null,
            provider: provider.id,
            sourceTarget: match.sourceTarget,
            warning: warning(
                `${getTargetDisplayName(targetId)} is not supported by the ${
                    provider.id
                } rule-set provider; it was omitted.`,
            ),
        };
    }

    const sourceTarget = normalizeTargetId(source.target);
    if (sourceTarget && sourceTarget !== targetId) {
        if (targetId === 'qx' && sourceTarget === 'surge') {
            const fallbackWarning =
                'The Surge-owned HTTP(S) rule set was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.';
            return {
                url: source.url,
                sourceTarget,
                forceOptParser: true,
                fallback: {
                    id: 'qx-resource-parser',
                    approximate: true,
                    warning: fallbackWarning,
                },
                warning: warning(fallbackWarning),
            };
        }
        if (targetId === 'loon' && sourceTarget === 'surge') {
            const fallbackWarning =
                'The Surge-owned HTTP(S) rule set was kept for Loon because the clients share the common rule-list syntax. Loon-specific unsupported rule types may still be omitted by the client.';
            return {
                url: source.url,
                sourceTarget,
                fallback: {
                    id: 'loon-surge-rule-list',
                    approximate: true,
                    warning: fallbackWarning,
                },
                warning: warning(fallbackWarning),
            };
        }
        if (targetId === 'clash' && sourceTarget === 'surge') {
            const fallbackWarning =
                'The Surge-owned HTTP(S) rule set will be downloaded through the Sub-Store cache and converted to inline classic Clash rules. Client-side rule-provider refresh is not available for this fallback.';
            return {
                url: source.url,
                sourceTarget,
                inlineConversion: 'surge-rule-list',
                fallback: {
                    id: 'clash-inline-surge-rule-list',
                    approximate: true,
                    warning: fallbackWarning,
                },
                warning: warning(fallbackWarning),
            };
        }
        return {
            url: null,
            sourceTarget,
            warning: warning(
                `Rule-set URL is bound to ${getTargetDisplayName(
                    sourceTarget,
                )} and no provider mapping is available for ${getTargetDisplayName(
                    targetId,
                )}; it was omitted.`,
            ),
        };
    }

    if (targetId === 'clash' && !sourceTarget) {
        return {
            url: null,
            warning: warning(
                'Rule-set URL has no Clash target ownership and no known provider mapping; it was omitted to avoid emitting an incompatible rule provider.',
            ),
        };
    }

    return {
        url: source.url,
        sourceTarget,
        ...(!sourceTarget
            ? {
                  warning: warning(
                      `Rule-set URL has no target ownership; compatibility with ${getTargetDisplayName(
                          targetId,
                      )} could not be verified and the URL was kept unchanged.`,
                  ),
              }
            : {}),
    };
}

export function resolveRuleSetSource(ruleSet, target) {
    const targetId = normalizeTargetId(target);
    const source = ruleSet?.source;
    if (!targetId || !source) {
        return {
            kind: 'unsupported',
            warning: warning('Rule-set source is missing or invalid.'),
        };
    }

    if (source.kind === 'url') {
        const resolution = resolveRuleSetUrl(ruleSet, targetId);
        return resolution.url
            ? { kind: 'remote-url', ...resolution }
            : { kind: 'unsupported', ...resolution };
    }

    if (source.kind !== 'builtin') {
        return {
            kind: 'unsupported',
            warning: warning(
                `${getTargetDisplayName(
                    targetId,
                )} cannot represent this rule-set source.`,
            ),
        };
    }

    if (targetId === 'surge') {
        return { kind: 'surge-builtin', value: source.value, exact: true };
    }

    if (targetId === 'qx' && source.value === 'LAN') {
        return {
            kind: 'qx-inserted',
            value: 'FILTER_LAN',
            exact: false,
            warning: warning(
                "Surge LAN was mapped to Quantumult X FILTER_LAN. The clients' built-in LAN definitions may differ.",
            ),
        };
    }

    if (targetId === 'qx' && source.value === 'SYSTEM') {
        return {
            kind: 'inline-rules',
            rules: SURGE_SYSTEM_PORTABLE_RULES,
            exact: false,
            warning: warning(
                'Surge SYSTEM was approximated with a portable Quantumult X local-rule snapshot. Surge may change its built-in rules and PROCESS-NAME entries were omitted.',
            ),
        };
    }

    if (targetId === 'clash' && source.value === 'LAN') {
        return {
            kind: 'inline-rules',
            rules: CLASH_LAN_PORTABLE_RULES,
            exact: false,
            warning: warning(
                "LAN was approximated with portable Clash private-network rules. The clients' built-in LAN definitions may differ.",
            ),
        };
    }

    if (targetId === 'clash' && source.value === 'SYSTEM') {
        return {
            kind: 'inline-rules',
            rules: CLASH_SYSTEM_PORTABLE_RULES,
            exact: false,
            warning: warning(
                'SYSTEM was approximated with portable Clash domain rules. Surge may change its built-in rules, and client-specific USER-AGENT or PROCESS-NAME entries were omitted.',
            ),
        };
    }

    if (targetId === 'loon' && source.value === 'LAN') {
        return {
            kind: 'inline-rules',
            rules: CLASH_LAN_PORTABLE_RULES,
            exact: false,
            warning: warning(
                "LAN was approximated with portable Loon private-network rules. The clients' built-in LAN definitions may differ.",
            ),
        };
    }

    if (targetId === 'loon' && source.value === 'SYSTEM') {
        return {
            kind: 'inline-rules',
            rules: SURGE_SYSTEM_PORTABLE_RULES,
            exact: false,
            warning: warning(
                'SYSTEM was approximated with a portable Loon rule snapshot. Surge may change its built-in rules and PROCESS-NAME entries were omitted.',
            ),
        };
    }

    return {
        kind: 'unsupported',
        warning: warning(
            `${getTargetDisplayName(targetId)} cannot represent the ${
                source.value
            } built-in rule set.`,
        ),
    };
}

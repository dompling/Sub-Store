const TARGET_CAPABILITIES = {
    surge: {
        displayName: 'Surge',
        platform: 'Surge',
        policyGroups: {
            select: {
                outputType: 'select',
                members: 'ordered',
                includedPolicyGroupsMode: 'native',
                fields: { remoteProxySource: true },
            },
            'url-test': {
                outputType: 'url-test',
                members: 'ordered',
                includedPolicyGroupsMode: 'native',
                fields: { remoteProxySource: true },
            },
            fallback: {
                outputType: 'fallback',
                members: 'ordered',
                includedPolicyGroupsMode: 'native',
                fields: { remoteProxySource: true },
            },
            'load-balance': {
                outputType: 'load-balance',
                members: 'ordered',
                includedPolicyGroupsMode: 'native',
                fields: { remoteProxySource: true },
            },
            subnet: {
                outputType: 'subnet',
                members: 'ordered',
                includedPolicyGroupsMode: 'native',
                fields: { remoteProxySource: true },
            },
            smart: {
                outputType: 'smart',
                members: 'ordered',
                includedPolicyGroupsMode: 'native',
                fields: { remoteProxySource: true },
            },
        },
    },
    qx: {
        displayName: 'Quantumult X',
        platform: 'QX',
        policyGroups: {
            select: {
                outputType: 'static',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    iconUrl: true,
                    includeAllProxies: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    resourceTagRegex: true,
                },
            },
            fallback: {
                outputType: 'available',
                members: 'ordered',
                includedPolicyGroupsMode: 'omit',
                fields: {
                    iconUrl: true,
                    includeAllProxies: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    resourceTagRegex: true,
                },
            },
            'url-test': {
                outputType: 'url-latency-benchmark',
                members: 'ordered',
                includedPolicyGroupsMode: 'omit',
                fields: {
                    aliveChecking: true,
                    iconUrl: true,
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    resourceTagRegex: true,
                    tolerance: true,
                },
            },
            'round-robin': {
                outputType: 'round-robin',
                members: 'ordered',
                includedPolicyGroupsMode: 'omit',
                fields: {
                    iconUrl: true,
                    includeAllProxies: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    resourceTagRegex: true,
                },
            },
            'dest-hash': {
                outputType: 'dest-hash',
                members: 'ordered',
                includedPolicyGroupsMode: 'omit',
                fields: {
                    iconUrl: true,
                    includeAllProxies: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    resourceTagRegex: true,
                },
            },
            ssid: {
                outputType: 'ssid',
                members: 'ordered',
                includedPolicyGroupsMode: 'omit',
                fields: { iconUrl: true },
            },
        },
    },
    clash: {
        displayName: 'Clash',
        platform: 'Clash',
        policyGroups: {
            select: {
                outputType: 'select',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                },
            },
            'url-test': {
                outputType: 'url-test',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    tolerance: true,
                },
            },
            fallback: {
                outputType: 'fallback',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                },
            },
            'load-balance': {
                outputType: 'load-balance',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                exact: false,
                warning:
                    'Surge load-balance was approximated as classic Clash load-balance with consistent-hashing. Surge availability filtering and random distribution semantics are not preserved.',
                lostSemantics: [
                    'Surge availability filtering',
                    'random distribution',
                ],
                targetDefaults: { strategy: 'consistent-hashing' },
                fields: {
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                },
            },
        },
    },
    loon: {
        displayName: 'Loon',
        platform: 'Loon',
        policyGroups: {
            select: {
                outputType: 'select',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                },
            },
            'url-test': {
                outputType: 'url-test',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    tolerance: true,
                },
            },
            fallback: {
                outputType: 'fallback',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    timeout: true,
                },
            },
            'load-balance': {
                outputType: 'load-balance',
                members: 'ordered',
                includedPolicyGroupsMode: 'nested-group',
                fields: {
                    includeAllProxies: true,
                    interval: true,
                    nodeNameRegex: true,
                    remoteProxySource: true,
                    timeout: true,
                },
            },
            ssid: {
                outputType: 'ssid',
                members: 'ordered',
                includedPolicyGroupsMode: 'omit',
                fields: {},
            },
        },
    },
};

const POLICY_GROUP_FALLBACKS = {
    surge: {
        'round-robin': {
            outputSharedType: 'load-balance',
            warning:
                'Quantumult X round-robin was approximated as Surge load-balance. Surge selects an available policy randomly rather than in strict rotation.',
            targetDefaults: { persistent: false },
            lostSemantics: ['strict rotation order'],
        },
        'dest-hash': {
            outputSharedType: 'load-balance',
            warning:
                'Quantumult X dest-hash was approximated as Surge load-balance with persistent=1. Destination affinity is similar but hashing behavior may differ.',
            targetDefaults: { persistent: true },
            lostSemantics: ['exact destination hashing behavior'],
        },
    },
    qx: {
        smart: {
            outputSharedType: 'url-test',
            warning:
                'Surge smart was approximated as Quantumult X url-latency-benchmark. Adaptive retry, per-site tuning, historical quality scoring, and policy-priority weights are not available.',
            lostSemantics: [
                'adaptive retry',
                'per-site tuning',
                'historical quality scoring',
                'policy-priority weights',
            ],
        },
        'load-balance': {
            outputSharedType: 'round-robin',
            warning:
                'Surge load-balance was approximated as Quantumult X round-robin. Random distribution and availability behavior may differ.',
            lostSemantics: [
                'random distribution',
                'Surge availability behavior',
            ],
        },
    },
    clash: {
        smart: {
            outputSharedType: 'url-test',
            warning:
                'Surge smart was approximated as Clash url-test. Adaptive retry, per-site tuning, historical quality scoring, and policy-priority weights are not available.',
            lostSemantics: [
                'adaptive retry',
                'per-site tuning',
                'historical quality scoring',
                'policy-priority weights',
            ],
        },
        'round-robin': {
            outputSharedType: 'load-balance',
            warning:
                'Quantumult X round-robin was mapped to Clash load-balance with strategy round-robin.',
            targetDefaults: { strategy: 'round-robin' },
        },
        'dest-hash': {
            outputSharedType: 'load-balance',
            warning:
                'Quantumult X dest-hash was approximated as Clash load-balance with strategy consistent-hashing. Hash selection details may differ.',
            targetDefaults: { strategy: 'consistent-hashing' },
            lostSemantics: ['exact destination hashing behavior'],
        },
    },
    loon: {
        smart: {
            outputSharedType: 'url-test',
            warning:
                'Surge smart was approximated as Loon url-test. Adaptive retry, per-site tuning, historical quality scoring, and policy-priority weights are not available.',
            lostSemantics: [
                'adaptive retry',
                'per-site tuning',
                'historical quality scoring',
                'policy-priority weights',
            ],
        },
        'round-robin': {
            outputSharedType: 'load-balance',
            warning:
                'Quantumult X round-robin was approximated as Loon load-balance with algorithm=Round-Robin.',
            targetDefaults: { algorithm: 'Round-Robin' },
        },
        'dest-hash': {
            outputSharedType: 'load-balance',
            warning:
                'Quantumult X dest-hash was approximated as Loon load-balance with algorithm=PCC. Loon PCC affinity is similar but does not guarantee identical destination hashing behavior.',
            targetDefaults: { algorithm: 'PCC' },
            lostSemantics: ['exact destination hashing behavior'],
        },
    },
};

const TARGET_ALIASES = {
    surge: 'surge',
    qx: 'qx',
    quantumultx: 'qx',
    'quantumult x': 'qx',
    clash: 'clash',
    cfw: 'clash',
    clashforwindows: 'clash',
    'clash for windows': 'clash',
    loon: 'loon',
};

export function getTargetIds() {
    return Object.keys(TARGET_CAPABILITIES);
}

export function getTargetPlatform(target) {
    const targetId = normalizeTargetId(target);
    return TARGET_CAPABILITIES[targetId]?.platform;
}

export function getTargetPlatforms() {
    return getTargetIds().map((target) => TARGET_CAPABILITIES[target].platform);
}

export function createTargetOutputs(target, targetOutput = {}) {
    const targetId = normalizeTargetId(target);
    return Object.fromEntries(
        getTargetIds().map((candidate) => [
            candidate,
            candidate === targetId ? targetOutput : {},
        ]),
    );
}

export function normalizeTargetId(target) {
    return TARGET_ALIASES[`${target || ''}`.trim().toLowerCase()];
}

export function getTargetDisplayName(target) {
    const targetId = normalizeTargetId(target);
    return TARGET_CAPABILITIES[targetId]?.displayName || `${target || ''}`;
}

function getPolicyGroupCapability(target, sharedType) {
    const targetId = normalizeTargetId(target);
    return TARGET_CAPABILITIES[targetId]?.policyGroups?.[sharedType] || null;
}

function getPolicyGroupFallback(target, sharedType) {
    const targetId = normalizeTargetId(target);
    const fallback = POLICY_GROUP_FALLBACKS[targetId]?.[sharedType];
    if (!fallback) return null;
    const capability = getPolicyGroupCapability(
        targetId,
        fallback.outputSharedType,
    );
    if (!capability) return null;
    return {
        ...fallback,
        capability,
        sourceSharedType: sharedType,
        target: targetId,
    };
}

export function resolvePolicyGroupCapability(target, sharedType) {
    const targetId = normalizeTargetId(target);
    const exactCapability = getPolicyGroupCapability(targetId, sharedType);
    if (exactCapability) {
        return {
            ...exactCapability,
            exact: exactCapability.exact !== false,
            sourceSharedType: sharedType,
            outputSharedType: sharedType,
            target: targetId,
        };
    }

    const fallback = getPolicyGroupFallback(targetId, sharedType);
    if (!fallback) return null;
    return {
        ...fallback.capability,
        exact: false,
        sourceSharedType: sharedType,
        outputSharedType: fallback.outputSharedType,
        target: targetId,
        warning: fallback.warning,
        lostSemantics: fallback.lostSemantics || [],
        targetDefaults: fallback.targetDefaults || {},
    };
}

export function policyGroupSupportsField(target, sharedType, field) {
    return Boolean(
        getPolicyGroupCapability(target, sharedType)?.fields?.[field],
    );
}

export function resolvedPolicyGroupSupportsField(target, sharedType, field) {
    return Boolean(
        resolvePolicyGroupCapability(target, sharedType)?.fields?.[field],
    );
}

export function getKnownPolicyGroupTypes() {
    return [
        ...new Set(
            Object.values(TARGET_CAPABILITIES).flatMap((target) =>
                Object.keys(target.policyGroups || {}),
            ),
        ),
    ];
}

export function getSharedPolicyGroupType(target, outputType) {
    const targetId = normalizeTargetId(target);
    const entries = Object.entries(
        TARGET_CAPABILITIES[targetId]?.policyGroups || {},
    );
    return entries.find(
        ([, capability]) => capability.outputType === outputType,
    )?.[0];
}

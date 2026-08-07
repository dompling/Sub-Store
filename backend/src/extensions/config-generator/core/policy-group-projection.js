import { getTargetDisplayName } from './target-capabilities';

export function policyGroupCapabilityDiagnostics(group, capability) {
    if (capability?.exact !== false || !capability.warning) return [];
    return [
        {
            path: `groups.${group.name}.type`,
            message: capability.warning,
        },
    ];
}

export function projectIncludedPolicyGroups(group, capability, target) {
    const includedGroups = group.includeOtherGroups || [];
    const mode = capability?.includedPolicyGroupsMode;
    if (!includedGroups.length) {
        return { mode, members: [], dependencies: [], diagnostics: [] };
    }

    if (mode === 'native') {
        return {
            mode,
            members: [],
            dependencies: includedGroups,
            diagnostics: [],
        };
    }

    const targetName = getTargetDisplayName(target);
    if (mode === 'nested-group') {
        return {
            mode,
            members: includedGroups,
            dependencies: includedGroups,
            diagnostics: [
                {
                    path: `groups.${group.name}.includeOtherGroups`,
                    message: `${targetName} cannot flatten nodes from included policy groups; referenced group names were appended as nested policy members instead.`,
                },
            ],
        };
    }

    return {
        mode: 'omit',
        members: [],
        dependencies: [],
        diagnostics: [
            {
                path: `groups.${group.name}.includeOtherGroups`,
                message: `${targetName} ${capability.outputType} cannot safely approximate flattened nodes from another policy group; includeOtherGroups was omitted.`,
            },
        ],
    };
}

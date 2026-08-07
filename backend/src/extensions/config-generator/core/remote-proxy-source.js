import {
    getTargetDisplayName,
    getTargetIds,
    getTargetPlatform,
    normalizeTargetId,
    resolvePolicyGroupCapability,
} from './target-capabilities';
import { subStoreSourceUrl } from './sub-store-source';

function targetNames(targets) {
    return targets.map((target) => getTargetDisplayName(target)).join(', ');
}

export function createRemoteProxySourceContext(project) {
    const sourceMap = new Map(
        (project?.remoteProxySources || []).map((source) => [
            source.name,
            source,
        ]),
    );
    const legacyTargetsBySource = new Map();
    (project?.groups || []).forEach((group) => {
        getTargetIds().forEach((target) => {
            const name = group.targetOptions?.[target]?.remoteProxySource;
            if (!name) return;
            if (!legacyTargetsBySource.has(name)) {
                legacyTargetsBySource.set(name, new Set());
            }
            legacyTargetsBySource.get(name).add(target);
        });
    });
    return {
        sourceMap,
        legacyTargetsBySource,
        projectName: project?.name,
    };
}

export function isAutomaticRemoteProxySource(source) {
    if (source?.source?.kind !== 'url') return false;
    if (source.source.mode === 'auto') return true;
    return Boolean(
        source.source.mode === undefined && source.source.publicBaseUrl,
    );
}

function normalizedPublicBaseUrl(source) {
    return `${source?.source?.publicBaseUrl || ''}`.trim().replace(/\/+$/, '');
}

export function remoteProxySourceOutputUrl(source, target, sourceContext) {
    if (source?.source?.kind === 'sub-store') {
        return subStoreSourceUrl(source, getTargetPlatform(target));
    }
    if (source?.source?.kind !== 'url') return null;
    if (!isAutomaticRemoteProxySource(source)) return source.source.url;

    const publicBaseUrl = normalizedPublicBaseUrl(source);
    const projectName = `${sourceContext?.projectName || ''}`.trim();
    const platform = getTargetPlatform(target);
    if (!publicBaseUrl || !projectName || !platform) return null;
    return `${publicBaseUrl}/download/config-project/${encodeURIComponent(
        projectName,
    )}/proxy-source/${encodeURIComponent(source.name)}/${encodeURIComponent(
        platform,
    )}`;
}

function binding(
    target,
    sourceContext,
    name,
    path,
    legacyTarget,
    allowUrl = true,
) {
    const source = name ? sourceContext.sourceMap.get(name) : null;
    const targetId = normalizeTargetId(target);
    const explicitSourceTarget = normalizeTargetId(source?.source?.target);
    const legacyTargets = sourceContext.legacyTargetsBySource.get(name);
    const inferredLegacyTarget =
        legacyTargets?.size === 1 ? [...legacyTargets][0] : legacyTarget;
    const ambiguousLegacyUrl = Boolean(
        source?.source?.kind === 'url' &&
            !explicitSourceTarget &&
            legacyTargets?.size > 1,
    );
    const automaticUrl = isAutomaticRemoteProxySource(source);
    const automaticUrlReady = Boolean(
        automaticUrl &&
            remoteProxySourceOutputUrl(source, targetId, sourceContext),
    );
    const exact = Boolean(
        source &&
            (source.source?.kind === 'sub-store' ||
                automaticUrlReady ||
                (allowUrl &&
                    source.source?.kind === 'url' &&
                    (explicitSourceTarget === targetId ||
                        (!explicitSourceTarget &&
                            !ambiguousLegacyUrl &&
                            inferredLegacyTarget === targetId)))),
    );
    const qxParserCompatibleSource = Boolean(
        explicitSourceTarget
            ? explicitSourceTarget === 'surge' &&
                  (!legacyTarget || legacyTarget === 'surge')
            : !inferredLegacyTarget || inferredLegacyTarget === 'surge',
    );
    const fallback =
        !exact &&
        !automaticUrl &&
        !ambiguousLegacyUrl &&
        targetId === 'qx' &&
        source?.source?.kind === 'url' &&
        qxParserCompatibleSource
            ? {
                  id: 'qx-resource-parser',
                  approximate: true,
                  forceOptParser: true,
                  warning:
                      explicitSourceTarget === 'surge' ||
                      inferredLegacyTarget === 'surge'
                          ? 'The Surge-owned HTTP(S) proxy source was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.'
                          : 'The unclassified HTTP(S) proxy source was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
              }
            : null;
    return {
        name,
        path,
        source,
        supported: exact || Boolean(fallback),
        exact,
        fallback,
        supportLevel: exact ? 'exact' : fallback ? 'fallback' : 'unsupported',
        sourceTarget: ambiguousLegacyUrl
            ? undefined
            : automaticUrl
            ? undefined
            : allowUrl
            ? explicitSourceTarget || inferredLegacyTarget
            : legacyTarget,
        ...(ambiguousLegacyUrl
            ? {
                  reason: 'ambiguous-dual-target-legacy-url',
                  legacyTargets: [...legacyTargets],
              }
            : automaticUrl && !automaticUrlReady
            ? { reason: 'automatic-conversion-url-missing' }
            : {}),
    };
}

function resolveGroupRemoteProxySource(group, target, sourceContext) {
    const targetId = normalizeTargetId(target);
    if (!targetId) return null;

    if (group.remoteProxySource) {
        return binding(
            targetId,
            sourceContext,
            group.remoteProxySource,
            `groups.${group.name}.remoteProxySource`,
        );
    }

    const directLegacy = group.targetOptions?.[targetId]?.remoteProxySource;
    if (directLegacy) {
        return binding(
            targetId,
            sourceContext,
            directLegacy,
            `groups.${group.name}.targetOptions.${targetId}.remoteProxySource`,
            targetId,
        );
    }

    const fallbackBindings = getTargetIds()
        .filter((candidate) => candidate !== targetId)
        .flatMap((candidate) => {
            const name = group.targetOptions?.[candidate]?.remoteProxySource;
            return name
                ? [
                      binding(
                          targetId,
                          sourceContext,
                          name,
                          `groups.${group.name}.targetOptions.${candidate}.remoteProxySource`,
                          candidate,
                          false,
                      ),
                  ]
                : [];
        });
    const supportedFallbackBindings = fallbackBindings.filter(
        (candidate) => candidate.supported,
    );
    const supportedSourceNames = [
        ...new Set(
            supportedFallbackBindings.map((candidate) => candidate.name),
        ),
    ];
    if (supportedSourceNames.length > 1) {
        return {
            ...supportedFallbackBindings[0],
            path: `groups.${group.name}.targetOptions`,
            supported: false,
            exact: false,
            fallback: null,
            supportLevel: 'unsupported',
            reason: 'ambiguous-multiple-legacy-sources',
            candidateSourceNames: supportedSourceNames,
        };
    }
    return supportedFallbackBindings[0] || fallbackBindings[0] || null;
}

export function projectGroupRemoteProxySource(group, target, sourceContext) {
    const targetId = normalizeTargetId(target);
    const capability = resolvePolicyGroupCapability(targetId, group.type);
    const bindingResult = resolveGroupRemoteProxySource(
        group,
        targetId,
        sourceContext,
    );
    if (!bindingResult) return { status: 'none', capability };

    const projection = { ...bindingResult, capability };
    if (!capability?.fields?.remoteProxySource) {
        return { ...projection, status: 'unsupported-field' };
    }
    if (!bindingResult.source) return { ...projection, status: 'missing' };
    if (!bindingResult.supported) {
        return { ...projection, status: 'incompatible' };
    }
    if (bindingResult.source.enabled === false) {
        return { ...projection, status: 'disabled' };
    }
    return { ...projection, status: 'ready' };
}

export function remoteProxySourceWarning(bindingResult, target) {
    if (!bindingResult?.source) {
        return 'The selected remote proxy source does not exist and was omitted.';
    }
    if (bindingResult.reason === 'ambiguous-dual-target-legacy-url') {
        const targets = bindingResult.legacyTargets || [];
        if (
            targets.length !== 2 ||
            !targets.includes('surge') ||
            !targets.includes('qx')
        ) {
            return `This target-less URL remote proxy source is bound by multiple legacy target fields (${targetNames(
                targets,
            )}); select explicit target ownership before generating.`;
        }
        return 'This target-less URL remote proxy source is bound by both legacy Surge and Quantumult X fields; select explicit target ownership before generating.';
    }
    if (bindingResult.reason === 'ambiguous-multiple-legacy-sources') {
        return `Multiple compatible legacy remote proxy sources (${bindingResult.candidateSourceNames.join(
            ', ',
        )}) are available for this group; select one shared remote proxy source explicitly.`;
    }
    if (isAutomaticRemoteProxySource(bindingResult.source)) {
        return 'This automatic URL proxy source has no usable Sub-Store public base URL and was omitted.';
    }
    if (bindingResult.source.source?.kind !== 'url') {
        return 'The selected remote proxy source is not compatible with this target and was omitted.';
    }
    if (!bindingResult.sourceTarget) {
        return `This URL remote proxy source has no target ownership; compatibility with ${getTargetDisplayName(
            target,
        )} could not be verified and it was omitted.`;
    }
    return `This URL remote proxy source is only bound to ${getTargetDisplayName(
        bindingResult.sourceTarget,
    )} and was omitted from ${getTargetDisplayName(target)}.`;
}

export function remoteProxySourceFallbackWarning(bindingResult) {
    return bindingResult?.fallback?.warning;
}

import { getTargetPlatforms } from './target-capabilities';

export function subStoreSourceUrl(source, target) {
    if (source?.source?.kind !== 'sub-store') return '';
    const base = source.source.publicBaseUrl.replace(/\/$/, '');
    const path =
        source.source.type === 'collection'
            ? `/download/collection/${encodeURIComponent(source.source.name)}`
            : `/download/${encodeURIComponent(source.source.name)}`;
    return `${base}${path}${target ? `/${target}` : ''}`;
}

export function matchingSubStoreSource(url, sourceContext) {
    const remoteSources = Array.isArray(sourceContext)
        ? sourceContext
        : sourceContext?.remoteProxySources || [];
    return remoteSources.find(
        (source) =>
            source?.source?.kind === 'sub-store' &&
            [
                ...getTargetPlatforms().map((platform) =>
                    subStoreSourceUrl(source, platform),
                ),
                subStoreSourceUrl(source),
            ].includes(url),
    );
}

const extensions = [];

export function registerExtension(extension) {
    if (!extension?.id || extensions.some((item) => item.id === extension.id)) {
        return;
    }
    extensions.push(extension);
}

export function getArtifactSourceAdapter(type) {
    for (const extension of extensions) {
        const adapter = (extension.artifactSources || []).find(
            (item) => item.type === type,
        );
        if (adapter) return adapter;
    }
    return null;
}

export function listArtifactSources() {
    return extensions.flatMap((extension) =>
        (extension.artifactSources || []).map((adapter) => ({
            type: adapter.type,
            labelKey: adapter.labelKey,
            platforms: adapter.platforms,
            items: adapter.list(),
        })),
    );
}

export function listExtensionFeatures() {
    return Object.fromEntries(
        extensions
            .filter((extension) => extension.feature)
            .map((extension) => [extension.feature, true]),
    );
}

export function registerExtensionRoutes($app, dependencies = {}) {
    extensions.forEach((extension) =>
        extension.registerRoutes?.($app, dependencies),
    );
    $app.get('/api/extensions/artifact-sources', (req, res) => {
        res.json({ status: 'success', data: listArtifactSources() });
    });
}

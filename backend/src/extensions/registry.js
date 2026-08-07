import { findCatalogEntry } from './catalog.generated';
import { getExtensionManager } from './manager';
import { failed } from '@/restful/response';

const extensions = [];

function canonicalExtensionId(extension) {
    if (extension?.extensionId) return extension.extensionId;
    if (extension?.id === 'config-generator') {
        return 'org.substore.config-generator';
    }
    return extension?.id;
}

export function registerExtension(extension) {
    const extensionId = canonicalExtensionId(extension);
    if (
        !extensionId ||
        extensions.some((item) => item.extensionId === extensionId)
    ) {
        return (
            extensions.find((item) => item.extensionId === extensionId) || null
        );
    }
    const catalogEntry = findCatalogEntry(extensionId);
    const registered = {
        ...extension,
        // Keep `id` untouched for old artifact adapters while exposing the
        // immutable manifest id to new Host consumers.
        extensionId,
        manifest: extension.manifest || catalogEntry?.manifest || null,
    };
    extensions.push(registered);
    try {
        getExtensionManager().registerAdapter(extensionId, registered);
    } catch (e) {
        // Registry registration predates the Host. A third-party/fixture
        // extension may intentionally have no catalog entry; keep its legacy
        // registration available and let explicit Host registration fail with
        // a structured error instead of breaking application startup.
    }
    return registered;
}

export function getArtifactSourceAdapter(type) {
    const manager = getExtensionManager();
    for (const extension of extensions) {
        const adapter = (extension.artifactSources || []).find(
            (item) => item.type === type,
        );
        if (adapter) {
            const availability = manager.getAvailability(extension.extensionId);
            if (availability.status === 'enabled') return adapter;
            const unavailable = () => {
                const error = new Error(
                    `Extension ${extension.extensionId} is ${availability.status}`,
                );
                error.code = availability.reasonCode || 'EXTENSION_UNAVAILABLE';
                error.statusCode = 409;
                error.details = availability;
                throw error;
            };
            return {
                ...adapter,
                availability,
                get: unavailable,
                findSourceConfig: unavailable,
                collectDependencies: unavailable,
                produce: unavailable,
                produceForSync: unavailable,
            };
        }
    }
    return null;
}

export function listArtifactSources() {
    const manager = getExtensionManager();
    return extensions.flatMap((extension) =>
        (extension.artifactSources || []).map((adapter) => ({
            type: adapter.type,
            labelKey: adapter.labelKey,
            platforms: adapter.platforms,
            items:
                manager.getAvailability(extension.extensionId).status ===
                'enabled'
                    ? adapter.list()
                    : [],
            ownerExtensionId: extension.extensionId || null,
            status: extension.extensionId
                ? manager.getAvailability(extension.extensionId).status
                : 'enabled',
        })),
    );
}

export function listExtensionFeatures() {
    const manager = getExtensionManager();
    const flags = manager.getFeatureFlags();
    // Preserve the old feature names for older frontends, even though the
    // canonical manifest contribution is namespaced.
    extensions.forEach((extension) => {
        if (
            extension.feature &&
            manager.getAvailability(extension.extensionId).status === 'enabled'
        ) {
            flags[extension.feature] = true;
        }
    });
    return flags;
}

export function listRegisteredExtensions() {
    return extensions.map((extension) => ({
        id: extension.extensionId || extension.id,
        legacyId: extension.id,
        feature: extension.feature,
        manifest: extension.manifest || null,
        artifactSourceTypes: (extension.artifactSources || []).map(
            (adapter) => adapter.type,
        ),
    }));
}

export function getRegisteredExtension(extensionId) {
    const canonicalId =
        extensionId === 'config-generator'
            ? 'org.substore.config-generator'
            : extensionId;
    return (
        extensions.find((extension) => extension.extensionId === canonicalId) ||
        null
    );
}

export function clearExtensionRegistryForTests() {
    extensions.splice(0, extensions.length);
}

export function resolveExtensionRouteLane(extensionId, path) {
    const canonicalId =
        extensionId === 'config-generator'
            ? 'org.substore.config-generator'
            : extensionId;
    if (canonicalId === 'org.substore.config-generator') {
        return /^\/api\/extensions\/config-generator\/(preview|import)(\/|$)/.test(
            path,
        ) || /^\/download\/config-project(\/|$)/.test(path)
            ? 'parser'
            : 'simple';
    }
    if (canonicalId === 'org.substore.config-hosting') {
        return /\/runtime\/(sync|preview|produce|import|download)(\/|$)/.test(
            path,
        )
            ? 'parser'
            : 'simple';
    }
    return 'simple';
}

function gatedApp($app, extension, manager, executionLane) {
    const proxy = Object.create($app);
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
        if (typeof $app[method] !== 'function') continue;
        proxy[method] = (path, handler) => {
            if (
                executionLane &&
                resolveExtensionRouteLane(extension.extensionId, path) !==
                    executionLane
            ) {
                return proxy;
            }
            $app[method](path, async (req, res, next) => {
                try {
                    // Legacy aliases intentionally do not require the new
                    // revision header. Availability still changes
                    // immediately after enable/disable.
                    manager.guard(extension.extensionId);
                    return await handler(req, res, next);
                } catch (error) {
                    failed(res, error, error.statusCode || 409);
                    return undefined;
                }
            });
            return proxy;
        };
    }
    return proxy;
}

export function registerExtensionRoutes($app, dependencies = {}) {
    const manager = dependencies.extensionManager || getExtensionManager();
    extensions.forEach((extension) =>
        extension.registerRoutes?.(
            gatedApp($app, extension, manager, dependencies.executionLane),
            {
                ...dependencies,
                extensionManager: manager,
            },
        ),
    );
    if (
        !dependencies.executionLane ||
        dependencies.executionLane === 'simple'
    ) {
        $app.get('/api/extensions/artifact-sources', (req, res) => {
            res.json({ status: 'success', data: listArtifactSources() });
        });
    }
}

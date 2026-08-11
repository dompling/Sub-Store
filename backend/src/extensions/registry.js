import { findCatalogEntry } from './catalog.generated';
import { getExtensionManager } from './manager';
import { failed } from '@/restful/response';

const extensions = [];
const routeHosts = [];

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
    if (extension.lifecycleAdapter) {
        getExtensionManager().registerAdapter(
            extensionId,
            extension.lifecycleAdapter,
        );
    }
    routeHosts.forEach((host) => mountExtensionRoutes(host, registered));
    return registered;
}

export function unregisterExtension(extensionId) {
    const canonicalId =
        extensionId === 'config-generator'
            ? 'org.substore.config-generator'
            : extensionId;
    const index = extensions.findIndex(
        (extension) => extension.extensionId === canonicalId,
    );
    if (index < 0) return false;
    extensions.splice(index, 1);
    routeHosts.forEach((host) => {
        for (const key of host.handlers.keys()) {
            if (key.startsWith(`${canonicalId}\u0000`)) {
                host.handlers.delete(key);
            }
        }
    });
    return true;
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
    routeHosts.splice(0, routeHosts.length);
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

function routeHandlerKey(extensionId, method, path) {
    return `${extensionId}\u0000${method}\u0000${path}`;
}

function dynamicGatedApp(host, extension) {
    const { app: $app, manager, executionLane } = host;
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
            const key = routeHandlerKey(extension.extensionId, method, path);
            host.handlers.set(key, handler);
            if (!host.mounted.has(key)) {
                $app[method](path, async (req, res, next) => {
                    try {
                        // Route dispatchers are permanent, but the active
                        // handler is looked up for every request. Disabling or
                        // uninstalling therefore cannot leave a stale closure
                        // from an old package version callable.
                        manager.guard(extension.extensionId);
                        const current = host.handlers.get(key);
                        if (typeof current !== 'function') {
                            const error = new Error(
                                `Extension route ${path} is unavailable`,
                            );
                            error.code = 'EXTENSION_ROUTE_UNAVAILABLE';
                            error.statusCode = 409;
                            throw error;
                        }
                        return await current(req, res, next);
                    } catch (error) {
                        failed(res, error, error.statusCode || 409);
                        return undefined;
                    }
                });
                host.mounted.add(key);
            }
            return proxy;
        };
    }
    return proxy;
}

function mountExtensionRoutes(host, extension) {
    extension.registerRoutes?.(dynamicGatedApp(host, extension), {
        ...host.dependencies,
        extensionManager: host.manager,
    });
}

export function registerExtensionRoutes($app, dependencies = {}) {
    const manager = dependencies.extensionManager || getExtensionManager();
    let host = routeHosts.find(
        (candidate) =>
            candidate.rootApp === $app &&
            candidate.executionLane === dependencies.executionLane,
    );
    if (!host) {
        const routeApp =
            typeof $app.createRouter === 'function' &&
            typeof $app.use === 'function'
                ? $app.createRouter()
                : $app;
        if (routeApp !== $app) $app.use(routeApp);
        host = {
            rootApp: $app,
            app: routeApp,
            manager,
            dependencies,
            executionLane: dependencies.executionLane,
            handlers: new Map(),
            mounted: new Set(),
        };
        routeHosts.push(host);
    }
    extensions.forEach((extension) => mountExtensionRoutes(host, extension));
    if (
        !dependencies.executionLane ||
        dependencies.executionLane === 'simple'
    ) {
        $app.get('/api/extensions/artifact-sources', (req, res) => {
            res.json({ status: 'success', data: listArtifactSources() });
        });
    }
}

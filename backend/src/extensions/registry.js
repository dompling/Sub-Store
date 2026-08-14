import { findCatalogEntry } from './catalog.generated';
import { routeExecutionLane } from './contracts';
import { getExtensionManager } from './manager';
import { failed } from '@/restful/response';
import {
    normalizeProviderResourceDescriptor,
    normalizeResourceRef,
    resourceError,
} from './resource-contracts';

const extensions = [];
const routeHosts = [];

function canonicalExtensionId(extension) {
    if (extension?.extensionId) return extension.extensionId;
    return extension?.id;
}

function permission(manifest, name) {
    return (manifest?.permissions || []).find((candidate) =>
        typeof candidate === 'string'
            ? candidate === name
            : candidate?.name === name,
    );
}

function scopeIncludes(scope, type) {
    if (!Array.isArray(scope)) return false;
    const aliases = new Set([
        type,
        type === 'subscription' ? 'subscriptions' : null,
        type === 'collection' ? 'collections' : null,
    ]);
    return scope.some((candidate) => aliases.has(candidate));
}

function isStrictResourceProvider(manifest) {
    return (manifest?.requires?.hard || []).includes('resource-broker@1');
}

function manifestArtifactSource(manifest, sourceId) {
    return (manifest?.contributes?.artifactSources || []).find(
        (candidate) => candidate?.id === sourceId,
    );
}

function validateStrictArtifactSources(extensionId, manifest, sources) {
    if (!isStrictResourceProvider(manifest)) return;
    const registerPermission = permission(manifest, 'artifact-source.register');
    const seen = new Set();
    for (const source of sources) {
        if (
            !source ||
            typeof source.id !== 'string' ||
            typeof source.type !== 'string' ||
            typeof source.contract !== 'string' ||
            !Array.isArray(source.representations) ||
            source.representations.length === 0 ||
            typeof source.list !== 'function' ||
            typeof source.get !== 'function' ||
            typeof source.produce !== 'function'
        ) {
            throw resourceError(
                'EXTENSION_ARTIFACT_SOURCE_INVALID',
                `Extension ${extensionId} registered an incomplete resource provider`,
                { extensionId, sourceId: source?.id || null },
                409,
            );
        }
        if (seen.has(source.id)) {
            throw resourceError(
                'EXTENSION_ARTIFACT_SOURCE_DUPLICATE',
                `Extension ${extensionId} registered duplicate artifact source ${source.id}`,
                { extensionId, sourceId: source.id },
                409,
            );
        }
        seen.add(source.id);
        const declared = manifestArtifactSource(manifest, source.id);
        if (!declared) {
            throw resourceError(
                'EXTENSION_ARTIFACT_SOURCE_UNDECLARED',
                `Artifact source ${source.id} is not declared by its manifest`,
                { extensionId, sourceId: source.id },
                409,
            );
        }
        if (
            declared.type !== source.type ||
            declared.contract !== source.contract
        ) {
            throw resourceError(
                'EXTENSION_ARTIFACT_SOURCE_MISMATCH',
                `Artifact source ${source.id} does not match its manifest`,
                {
                    extensionId,
                    sourceId: source.id,
                    manifestType: declared.type,
                    runtimeType: source.type,
                    manifestContract: declared.contract,
                    runtimeContract: source.contract,
                },
                409,
            );
        }
        if (
            new Set(source.representations).size !==
                source.representations.length ||
            source.representations.some(
                (representation) =>
                    typeof representation !== 'string' ||
                    !representation.trim() ||
                    !declared.representations.includes(representation),
            )
        ) {
            throw resourceError(
                'EXTENSION_ARTIFACT_SOURCE_REPRESENTATION_DENIED',
                `Artifact source ${source.id} registered undeclared representations`,
                { extensionId, sourceId: source.id },
                409,
            );
        }
        if (
            !registerPermission ||
            typeof registerPermission === 'string' ||
            !scopeIncludes(registerPermission.scope, source.type)
        ) {
            throw resourceError(
                'EXTENSION_PERMISSION_SCOPE_DENIED',
                `Extension ${extensionId} cannot register ${source.type} resources`,
                {
                    extensionId,
                    permission: 'artifact-source.register',
                    type: source.type,
                },
                403,
            );
        }
    }
    const runtimeIds = new Set(sources.map((source) => source.id));
    const missing = (manifest.contributes?.artifactSources || []).filter(
        (source) => !runtimeIds.has(source.id),
    );
    if (missing.length) {
        throw resourceError(
            'EXTENSION_ARTIFACT_SOURCE_MISSING',
            `Extension ${extensionId} did not register all declared artifact sources`,
            { extensionId, sourceIds: missing.map((source) => source.id) },
            409,
        );
    }
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
    const manifest = extension.manifest || catalogEntry?.manifest || null;
    validateStrictArtifactSources(
        extensionId,
        manifest,
        extension.artifactSources || [],
    );
    const registered = {
        ...extension,
        // Keep `id` untouched for old artifact adapters while exposing the
        // immutable manifest id to new Host consumers.
        extensionId,
        manifest,
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
    const canonicalId = extensionId;
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
    const matching = extensions.flatMap((extension) =>
        (extension.artifactSources || [])
            .filter((item) => item.type === type)
            .map((adapter) => ({ extension, adapter })),
    );
    const enabled = matching.filter(
        ({ extension }) =>
            manager.getAvailability(extension.extensionId).status === 'enabled',
    );
    if (enabled.length > 1) {
        throw resourceError(
            'RESOURCE_PROVIDER_AMBIGUOUS',
            `Multiple enabled resource providers handle ${type}`,
            {
                type,
                providers: enabled.map(({ extension, adapter }) => ({
                    providerId: extension.extensionId,
                    providerContributionId: adapter.id || null,
                })),
            },
            409,
        );
    }
    if (enabled.length === 1) return enabled[0].adapter;
    if (matching.length !== 1) return null;
    const { extension, adapter } = matching[0];
    const availability = manager.getAvailability(extension.extensionId);
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

export function listResourceProviders() {
    return extensions.flatMap((extension) => {
        if (!isStrictResourceProvider(extension.manifest)) return [];
        return (extension.artifactSources || []).map((source) => ({
            providerId: extension.extensionId,
            providerContributionId: source.id,
            source,
            manifest: extension.manifest,
        }));
    });
}

export function resolveResourceProvider(input) {
    const ref = normalizeResourceRef(input);
    return (
        listResourceProviders().find(
            (provider) =>
                provider.providerId === ref.providerId &&
                provider.providerContributionId ===
                    ref.providerContributionId &&
                provider.source.type === ref.type,
        ) || null
    );
}

function strictSourceItems(extension, source) {
    return Promise.resolve(source.list()).then((items) => {
        if (!Array.isArray(items)) {
            throw resourceError(
                'RESOURCE_DESCRIPTOR_INVALID',
                'Resource provider list result must be an array',
                {
                    providerId: extension.extensionId,
                    providerContributionId: source.id,
                },
            );
        }
        return items.map((item) => {
            return normalizeProviderResourceDescriptor(
                {
                    providerId: extension.extensionId,
                    providerContributionId: source.id,
                    type: source.type,
                    contract: source.contract,
                    representations: source.representations,
                },
                item,
            );
        });
    });
}

export async function listArtifactSources() {
    const manager = getExtensionManager();
    const groups = await Promise.all(
        extensions.flatMap((extension) =>
            (extension.artifactSources || []).map(async (adapter) => {
                const availability = manager.getAvailability(
                    extension.extensionId,
                );
                const strict = isStrictResourceProvider(extension.manifest);
                return {
                    id: adapter.id || null,
                    sourceId: adapter.id || null,
                    type: adapter.type,
                    contract: adapter.contract || null,
                    representations: Array.isArray(adapter.representations)
                        ? [...adapter.representations]
                        : [],
                    labelKey: adapter.labelKey,
                    platforms: adapter.platforms,
                    items:
                        availability.status === 'enabled'
                            ? strict
                                ? await strictSourceItems(extension, adapter)
                                : await adapter.list()
                            : [],
                    ownerExtensionId: extension.extensionId || null,
                    status: extension.extensionId
                        ? availability.status
                        : 'enabled',
                };
            }),
        ),
    );
    return groups;
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
    const canonicalId = extensionId;
    return (
        extensions.find((extension) => extension.extensionId === canonicalId) ||
        null
    );
}

export function clearExtensionRegistryForTests() {
    extensions.splice(0, extensions.length);
    routeHosts.splice(0, routeHosts.length);
}

export function resolveExtensionRouteLane(extensionId, path, method) {
    const canonicalId = extensionId;
    const extension = getRegisteredExtension(canonicalId);
    const manifest =
        extension?.manifest || findCatalogEntry(canonicalId)?.manifest || null;
    if (manifest) {
        const normalizedPath = `${path || ''}`.replace(/^\/+/, '');
        const extensionRoute = normalizedPath.replace(
            /^api\/extensions\/[^/]+\//,
            '',
        );
        for (const candidate of [extensionRoute, normalizedPath]) {
            const lane = routeExecutionLane(manifest, candidate, method);
            if (lane) return lane;
        }
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
                resolveExtensionRouteLane(
                    extension.extensionId,
                    path,
                    method,
                ) !== executionLane
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
        $app.get('/api/extensions/artifact-sources', async (req, res) => {
            try {
                res.json({
                    status: 'success',
                    data: await listArtifactSources(),
                });
            } catch (error) {
                failed(res, error, error.statusCode || 409);
            }
        });
    }
}

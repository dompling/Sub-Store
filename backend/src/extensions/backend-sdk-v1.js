import $ from '@/core/app';
import { ARTIFACTS_KEY } from '@/constants';
import { ProxyUtils } from '@/core/proxy-utils';
import resourceCache from '@/utils/resource-cache';
import { runBackendRequestTask } from '@/utils/request-concurrency';

const SDK_API_VERSION = '1.0.0';

function permissionsByName(manifest) {
    return new Map(
        (manifest?.permissions || []).map((permission) => [
            typeof permission === 'string' ? permission : permission?.name,
            permission,
        ]),
    );
}

function requirePermission(permissions, name, extensionId) {
    if (permissions.has(name)) return permissions.get(name);
    const error = new Error(
        `Extension ${extensionId} did not declare permission ${name}`,
    );
    error.code = 'EXTENSION_PERMISSION_DENIED';
    error.statusCode = 403;
    error.details = { extensionId, permission: name };
    throw error;
}

function permissionScope(permission) {
    return permission && typeof permission === 'object'
        ? permission.scope
        : null;
}

function scopeAliases(type) {
    return [
        type,
        type === 'subscription' ? 'subscriptions' : null,
        type === 'collection' ? 'collections' : null,
    ].filter(Boolean);
}

function scopeAllows(permission, type) {
    const scope = permissionScope(permission);
    return (
        Array.isArray(scope) &&
        scope.some((candidate) => scopeAliases(type).includes(candidate))
    );
}

function requireResourceScope(permissions, permissionName, type, extensionId) {
    const permission = requirePermission(
        permissions,
        permissionName,
        extensionId,
    );
    if (scopeAllows(permission, type)) return;
    const error = new Error(
        `Extension ${extensionId} cannot use ${permissionName} for ${type}`,
    );
    error.code = 'EXTENSION_PERMISSION_SCOPE_DENIED';
    error.statusCode = 403;
    error.details = { extensionId, permission: permissionName, type };
    throw error;
}

function ownStorageKey(manifest) {
    return (
        manifest?.storage?.namespace ||
        manifest?.storage?.legacyKeys?.[0] ||
        null
    );
}

function freezeService(value) {
    Object.values(value).forEach((entry) => {
        if (entry && typeof entry === 'object') Object.freeze(entry);
    });
    return Object.freeze(value);
}

/**
 * Versioned, capability-scoped Host services for trusted official packages.
 * The package never receives the raw database root, Express app or Node file
 * system.  Every service is derived from a declared manifest permission.
 */
export function createBackendExtensionSdkV1({
    extensionId,
    manifest,
    store,
    resourceBroker,
    referenceIndex,
}) {
    const permissions = permissionsByName(manifest);
    const storageKey = ownStorageKey(manifest);
    const cachePrefix = `${extensionId}:`;
    const storage = {
        read() {
            requirePermission(permissions, 'storage.own', extensionId);
            if (!storageKey) return undefined;
            return store.read(storageKey);
        },
        write(value) {
            requirePermission(permissions, 'storage.own', extensionId);
            if (!storageKey) {
                const error = new Error(
                    `Extension ${extensionId} has no declared storage namespace`,
                );
                error.code = 'EXTENSION_STORAGE_NAMESPACE_MISSING';
                throw error;
            }
            return store.write(value, storageKey);
        },
    };
    const resources = {
        listArtifacts() {
            requirePermission(permissions, 'resources.read', extensionId);
            return store.read(ARTIFACTS_KEY) || [];
        },
        async list(options = {}) {
            const listPermission = requirePermission(
                permissions,
                'resources.list',
                extensionId,
            );
            if (!resourceBroker) {
                const error = new Error('Host Resource Broker is unavailable');
                error.code = 'RESOURCE_BROKER_UNAVAILABLE';
                error.statusCode = 409;
                throw error;
            }
            const scope = permissionScope(listPermission) || [];
            const requestedTypes = Array.isArray(options.types)
                ? options.types
                : null;
            if (
                requestedTypes?.some(
                    (type) => !scopeAllows(listPermission, type),
                )
            ) {
                const error = new Error(
                    `Extension ${extensionId} requested resources outside its permission scope`,
                );
                error.code = 'EXTENSION_PERMISSION_SCOPE_DENIED';
                error.statusCode = 403;
                error.details = {
                    extensionId,
                    permission: 'resources.list',
                    requestedTypes,
                };
                throw error;
            }
            return resourceBroker.list({
                ...options,
                types:
                    requestedTypes ||
                    scope
                        .map((type) =>
                            type === 'subscriptions'
                                ? 'subscription'
                                : type === 'collections'
                                ? 'collection'
                                : type,
                        )
                        .filter(Boolean),
            });
        },
        async get(ref) {
            requireResourceScope(
                permissions,
                'resources.read',
                ref?.type,
                extensionId,
            );
            if (!resourceBroker) {
                const error = new Error('Host Resource Broker is unavailable');
                error.code = 'RESOURCE_BROKER_UNAVAILABLE';
                error.statusCode = 409;
                throw error;
            }
            return resourceBroker.get(ref);
        },
        async produce(ref, options) {
            requireResourceScope(
                permissions,
                'resources.produce',
                ref?.type,
                extensionId,
            );
            if (!resourceBroker) {
                const error = new Error('Host Resource Broker is unavailable');
                error.code = 'RESOURCE_BROKER_UNAVAILABLE';
                error.statusCode = 409;
                throw error;
            }
            return resourceBroker.produce(ref, options);
        },
    };
    const references = {
        replaceOwn(input) {
            requireResourceScope(
                permissions,
                'references.manage-own',
                input?.owner?.type,
                extensionId,
            );
            if (input?.owner?.providerId !== extensionId) {
                const error = new Error(
                    `Extension ${extensionId} cannot manage another provider's references`,
                );
                error.code = 'EXTENSION_PERMISSION_SCOPE_DENIED';
                error.statusCode = 403;
                error.details = {
                    extensionId,
                    permission: 'references.manage-own',
                    providerId: input?.owner?.providerId || null,
                };
                throw error;
            }
            if (!referenceIndex) {
                const error = new Error('Host reference index is unavailable');
                error.code = 'REFERENCE_INDEX_UNAVAILABLE';
                error.statusCode = 409;
                throw error;
            }
            return referenceIndex.replaceOwn(input);
        },
        listIncoming(ref) {
            requireResourceScope(
                permissions,
                'references.read-own',
                ref?.type,
                extensionId,
            );
            if (ref?.providerId !== extensionId) {
                const error = new Error(
                    `Extension ${extensionId} cannot inspect another provider's references`,
                );
                error.code = 'EXTENSION_PERMISSION_SCOPE_DENIED';
                error.statusCode = 403;
                error.details = {
                    extensionId,
                    permission: 'references.read-own',
                    providerId: ref?.providerId || null,
                };
                throw error;
            }
            if (!referenceIndex) {
                const error = new Error('Host reference index is unavailable');
                error.code = 'REFERENCE_INDEX_UNAVAILABLE';
                error.statusCode = 409;
                throw error;
            }
            return referenceIndex.listIncoming(ref);
        },
    };
    const network = {
        get(options) {
            requirePermission(permissions, 'network.fetch', extensionId);
            return $.http.get(options);
        },
    };
    const transform = {
        processResponse(...args) {
            requirePermission(permissions, 'artifact.produce', extensionId);
            return ProxyUtils.processResponse(...args);
        },
    };
    const cache = {
        get(key, ...args) {
            return resourceCache.get(`${cachePrefix}${key}`, ...args);
        },
        set(key, value, ...args) {
            return resourceCache.set(`${cachePrefix}${key}`, value, ...args);
        },
    };
    const tasks = {
        runRequest(task, label) {
            return runBackendRequestTask(
                task,
                `${extensionId}:${label || 'request'}`,
            );
        },
    };
    return freezeService({
        apiVersion: SDK_API_VERSION,
        extensionId,
        storage,
        resources,
        references,
        network,
        transform,
        cache,
        tasks,
    });
}

export default createBackendExtensionSdkV1;

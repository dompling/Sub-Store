import $ from '@/core/app';
import { ARTIFACTS_KEY } from '@/constants';
import { ProxyUtils } from '@/core/proxy-utils';
import resourceCache from '@/utils/resource-cache';
import { runBackendRequestTask } from '@/utils/request-concurrency';

const SDK_API_VERSION = '1.0.0';

function permissionNames(manifest) {
    return new Set(
        (manifest?.permissions || []).map((permission) =>
            typeof permission === 'string' ? permission : permission?.name,
        ),
    );
}

function requirePermission(permissions, name, extensionId) {
    if (permissions.has(name)) return;
    const error = new Error(
        `Extension ${extensionId} did not declare permission ${name}`,
    );
    error.code = 'EXTENSION_PERMISSION_DENIED';
    error.statusCode = 403;
    error.details = { extensionId, permission: name };
    throw error;
}

function ownStorageKey(manifest) {
    return (
        manifest?.storage?.namespace || manifest?.storage?.legacyKeys?.[0] || null
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
}) {
    const permissions = permissionNames(manifest);
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
            return runBackendRequestTask(task, `${extensionId}:${label || 'request'}`);
        },
    };
    return freezeService({
        apiVersion: SDK_API_VERSION,
        extensionId,
        storage,
        resources,
        network,
        transform,
        cache,
        tasks,
    });
}

export default createBackendExtensionSdkV1;

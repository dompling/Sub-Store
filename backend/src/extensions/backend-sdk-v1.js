import $ from '@/core/app';
import { ARTIFACTS_KEY } from '@/constants';
import { ProxyUtils } from '@/core/proxy-utils';
import resourceCache from '@/utils/resource-cache';
import { runBackendRequestTask } from '@/utils/request-concurrency';
import {
    getUserAgentFromHeaders,
    resolvePlatformFromUserAgent,
} from '@/utils/user-agent';
import { createExtensionScheduler } from './scheduler';

const SDK_API_VERSION = '1.0.0';

// Extension-submitted request bodies stay small: the supported caller is a
// probe controller handshake, not a general-purpose HTTP client.
const MAX_EXTENSION_REQUEST_BODY_BYTES = 512 * 1024;
const MAX_EXTENSION_RESPONSE_BODY_BYTES = 2 * 1024 * 1024;
const MAX_EXTENSION_REQUEST_TIMEOUT_MS = 120000;
const EXTENSION_REQUEST_METHODS = new Set([
    'GET',
    'HEAD',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
]);
// Only these request options reach the Host HTTP client. Everything else
// (`proxy`, `insecure`, `strictSSL`, `node`, `events`, ...) would let an
// extension change how the Host dials or verifies TLS.
const EXTENSION_REQUEST_OPTION_KEYS = new Set([
    'method',
    'url',
    'query',
    'headers',
    'body',
    'timeout',
]);
const USER_CONFIGURED_SCOPES = new Set([
    'user-configured',
    'user-configured-http',
    'user-configured-https',
]);

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

function extensionNetworkError(code, message, details, statusCode = 502) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    error.details = details;
    return error;
}

function networkScopeEntries(permission) {
    const scope = permissionScope(permission);
    return Array.isArray(scope)
        ? scope
              .map((entry) => `${entry || ''}`.trim().toLowerCase())
              .filter(Boolean)
        : [];
}

function hostAllowedByScope(host, entries) {
    return entries.some((entry) => {
        if (entry.startsWith('*.')) return host.endsWith(entry.slice(1));
        return host === entry;
    });
}

function assertNetworkTargetAllowed(permission, rawUrl, extensionId) {
    let url;
    try {
        url = new URL(`${rawUrl || ''}`);
    } catch {
        throw extensionNetworkError(
            'EXTENSION_NETWORK_URL_INVALID',
            'Extension network request URL is invalid',
            { extensionId },
        );
    }
    if (!['http:', 'https:'].includes(url.protocol)) {
        throw extensionNetworkError(
            'EXTENSION_NETWORK_URL_INVALID',
            'Extension network requests only allow http and https',
            { extensionId },
        );
    }
    const host = url.hostname.toLowerCase();
    if (!host) {
        throw extensionNetworkError(
            'EXTENSION_NETWORK_URL_INVALID',
            'Extension network request URL has no host',
            { extensionId },
        );
    }
    const entries = networkScopeEntries(permission);
    if (!entries.length) return url;
    const userConfigured = entries.filter((entry) =>
        USER_CONFIGURED_SCOPES.has(entry),
    );
    const hostEntries = entries.filter(
        (entry) => !USER_CONFIGURED_SCOPES.has(entry),
    );
    const schemes = new Set(
        userConfigured.map((entry) =>
            entry === 'user-configured-https'
                ? 'https:'
                : entry === 'user-configured-http'
                ? 'http:'
                : null,
        ),
    );
    const allowsAnyScheme =
        userConfigured.includes('user-configured') ||
        schemes.size === 0 ||
        schemes.has(null);
    if (userConfigured.length && (allowsAnyScheme || schemes.has(url.protocol))) {
        return url;
    }
    if (hostEntries.length && hostAllowedByScope(host, hostEntries)) return url;
    const error = new Error(
        `Extension ${extensionId} cannot reach this network target`,
    );
    error.code = 'EXTENSION_PERMISSION_SCOPE_DENIED';
    error.statusCode = 403;
    error.details = { extensionId, permission: 'network.fetch' };
    throw error;
}

function normalizeExtensionRequestBody(body) {
    if (body === undefined || body === null) return undefined;
    if (typeof body === 'string') return body;
    return JSON.stringify(body);
}

function appendQuery(url, query) {
    if (!query || typeof query !== 'object') return url;
    for (const [key, value] of Object.entries(query)) {
        if (value === undefined || value === null) continue;
        url.searchParams.set(key, `${value}`);
    }
    return url;
}

/**
 * Stable, extension-facing reason codes. The Host HTTP client reports a
 * timeout as a plain Error without a code, and dial failures arrive as undici
 * errors whose code lives on `cause`; extensions need one vocabulary.
 */
function networkFailureReason(error) {
    const code = `${error?.code || error?.cause?.code || ''}`;
    const message = `${error?.message || ''}`;
    if (
        /exceeds the timeout/i.test(message) ||
        /TIMEOUT|TIMEDOUT/i.test(code) ||
        error?.name === 'AbortError'
    ) {
        return 'TIMEOUT';
    }
    if (/ECONNREFUSED/.test(code)) return 'CONNECTION_REFUSED';
    if (/ECONNRESET|EPIPE/.test(code)) return 'CONNECTION_RESET';
    if (/ENOTFOUND|EAI_AGAIN/.test(code)) return 'DNS_FAILED';
    if (/EHOSTUNREACH|ENETUNREACH/.test(code)) return 'HOST_UNREACHABLE';
    if (/CERT|TLS|SSL|HANDSHAKE/i.test(code) || /certificate|handshake/i.test(message)) {
        return 'TLS_HANDSHAKE';
    }
    return code.slice(0, 64) || 'REQUEST_FAILED';
}

function redactNetworkFailure(error, extensionId) {
    if (
        error?.code === 'EXTENSION_PERMISSION_SCOPE_DENIED' ||
        error?.code === 'EXTENSION_NETWORK_RESPONSE_TOO_LARGE'
    ) {
        return error;
    }
    const reasonCode = networkFailureReason(error);
    return extensionNetworkError(
        reasonCode === 'TIMEOUT'
            ? 'EXTENSION_NETWORK_TIMEOUT'
            : 'EXTENSION_NETWORK_REQUEST_FAILED',
        reasonCode === 'TIMEOUT'
            ? 'Extension network request timed out'
            : 'Extension network request failed',
        { extensionId, reasonCode },
        reasonCode === 'TIMEOUT' ? 504 : 502,
    );
}

function normalizeExtensionResponse(response, extensionId) {
    const rawBody = response?.body;
    const body =
        rawBody === undefined || rawBody === null
            ? ''
            : typeof rawBody === 'string'
            ? rawBody
            : Buffer.isBuffer(rawBody) || rawBody instanceof ArrayBuffer
            ? Buffer.from(rawBody).toString('utf8')
            : JSON.stringify(rawBody);
    if (Buffer.byteLength(body) > MAX_EXTENSION_RESPONSE_BODY_BYTES) {
        throw extensionNetworkError(
            'EXTENSION_NETWORK_RESPONSE_TOO_LARGE',
            'Extension network response body is too large',
            { extensionId },
        );
    }
    let json = null;
    if (body) {
        try {
            json = JSON.parse(body);
        } catch {
            json = null;
        }
    }
    return {
        statusCode: Number(response?.statusCode || response?.status) || 0,
        headers: response?.headers || {},
        body,
        json,
    };
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

function resolveClientTarget(req = {}) {
    const query = req.query || {};
    if (query.platform) {
        return { value: query.platform, source: 'platform-query' };
    }
    if (query.target) {
        return { value: query.target, source: 'target-query' };
    }
    return resolvePlatformFromUserAgent(
        getUserAgentFromHeaders(req.headers || {}),
    );
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
                return {
                    available: false,
                    items: [],
                    reasonCode: 'REFERENCE_INDEX_UNAVAILABLE',
                };
            }
            try {
                return referenceIndex.listIncoming(ref);
            } catch (error) {
                if (
                    ![
                        'REFERENCE_INDEX_CORRUPT',
                        'REFERENCE_INDEX_SCHEMA_UNSUPPORTED',
                    ].includes(error?.code)
                ) {
                    throw error;
                }
                return {
                    available: false,
                    items: [],
                    reasonCode: error.code,
                };
            }
        },
    };
    const requestExtension = async (options) => {
        const permission = requirePermission(
            permissions,
            'network.fetch',
            extensionId,
        );
        const input = options && typeof options === 'object' ? options : {};
        const method = `${input.method || 'GET'}`.toUpperCase();
        if (!EXTENSION_REQUEST_METHODS.has(method)) {
            throw extensionNetworkError(
                'EXTENSION_NETWORK_METHOD_UNSUPPORTED',
                `Extension network requests do not support ${method}`,
                { extensionId },
            );
        }
        const url = appendQuery(
            assertNetworkTargetAllowed(permission, input.url, extensionId),
            input.query,
        );
        const body = normalizeExtensionRequestBody(input.body);
        if (body !== undefined && Buffer.byteLength(body) > MAX_EXTENSION_REQUEST_BODY_BYTES) {
            throw extensionNetworkError(
                'EXTENSION_NETWORK_BODY_TOO_LARGE',
                'Extension network request body is too large',
                { extensionId },
            );
        }
        const timeout = Math.min(
            Math.max(1, Number(input.timeout) || 15000),
            MAX_EXTENSION_REQUEST_TIMEOUT_MS,
        );
        try {
            const { query: _query, ...forwarded } = input;
            return await $.http.request({
                ...forwarded,
                method,
                url: url.href,
                ...(body !== undefined ? { body } : {}),
                timeout,
            });
        } catch (error) {
            throw redactNetworkFailure(error, extensionId);
        }
    };
    const network = {
        get(options) {
            requirePermission(permissions, 'network.fetch', extensionId);
            return $.http.get(options);
        },
        request: requestExtension,
    };
    const transform = {
        processResponse(...args) {
            requirePermission(permissions, 'artifact.produce', extensionId);
            return ProxyUtils.processResponse(...args);
        },
        produceNodes(proxies, target, opts = {}) {
            requirePermission(permissions, 'artifact.produce', extensionId);
            const list = Array.isArray(proxies)
                ? proxies
                : proxies == null
                ? []
                : [proxies];
            const platform = `${target || ''}`.trim() || 'JSON';
            // `internal` keeps the existing Sub-Store proxy object shape so a
            // caller can read produced nodes as JavaScript objects instead of
            // a platform-specific document.
            return ProxyUtils.produce(
                list.map((proxy) => ({ ...proxy })),
                platform,
                'internal',
                opts && typeof opts === 'object' ? { ...opts } : {},
            );
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
    const request = {
        resolveClientTarget,
    };
    // Host-owned CronJobs (Node only). The Host stops every job of this
    // extension on deactivate/upgrade, so a package never owns a raw timer.
    const hostScheduler = createExtensionScheduler(extensionId);
    const scheduler = {
        available() {
            return (
                permissions.has('scheduler.jobs') && hostScheduler.available()
            );
        },
        validate(cron) {
            requirePermission(permissions, 'scheduler.jobs', extensionId);
            return hostScheduler.validate(cron);
        },
        schedule(options) {
            requirePermission(permissions, 'scheduler.jobs', extensionId);
            return hostScheduler.schedule(options);
        },
        unschedule(id) {
            requirePermission(permissions, 'scheduler.jobs', extensionId);
            return hostScheduler.unschedule(id);
        },
        list() {
            requirePermission(permissions, 'scheduler.jobs', extensionId);
            return hostScheduler.list();
        },
        clear() {
            requirePermission(permissions, 'scheduler.jobs', extensionId);
            return hostScheduler.clear();
        },
        status() {
            return hostScheduler.status();
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
        request,
        scheduler,
    });
}

export default createBackendExtensionSdkV1;

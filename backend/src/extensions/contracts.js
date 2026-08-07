/**
 * Versioned contracts shared by the Extension Host, the registry and the
 * lifecycle REST API.
 *
 * This module deliberately contains no persistence, Express or plugin code.
 * Keeping the schema/pure helpers here makes it safe to import from the Node
 * bundle as well as the small proxy-app products.
 */

export const EXTENSION_MANIFEST_SCHEMA_VERSION = 1;
export const EXTENSION_RECEIPT_SCHEMA_VERSION = 1;
export const EXTENSION_HOST_API_VERSION = '1.0.0';
export const EXTENSION_RUNTIME_REVISION = 1;

export const EXTENSION_IDS = Object.freeze({
    configGenerator: 'org.substore.config-generator',
    configHosting: 'org.substore.config-hosting',
});

export const EXTENSION_KINDS = Object.freeze([
    'bundled',
    'trusted-official',
    'content',
    'sandboxed-ui',
    'isolated-service',
]);

export const EXTENSION_INSTALLATION_STATUSES = Object.freeze([
    'never-installed',
    'installed',
    'removed',
]);

export const EXTENSION_DATA_STATUSES = Object.freeze([
    'none',
    'active',
    'retained',
    'migration-conflict',
]);

export const EXTENSION_LANES = Object.freeze({
    simple: Object.freeze({
        id: 'simple',
        product: 'sub-store-0',
        description: 'CRUD/settings and lifecycle control routes',
    }),
    parser: Object.freeze({
        id: 'parser',
        product: 'sub-store-1',
        description: 'Parsing, preview and produce routes',
    }),
    scheduled: Object.freeze({
        id: 'scheduled',
        product: 'cron-sync-artifacts',
        description: 'Scheduled command contributions',
    }),
});

const CONTRIBUTION_PREFIX_RE =
    /^[a-z0-9]+(?:[.-][a-z0-9]+)*\.[A-Za-z0-9][A-Za-z0-9.-]*$/;
const EXTENSION_ID_RE = /^[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z0-9][a-z0-9.-]*$/;
const RESERVED_IDS = new Set([
    'runtime',
    'catalog',
    'installed',
    'tasks',
    'artifact-sources',
    'output-targets',
]);

function clone(value) {
    if (value === undefined) return undefined;
    return JSON.parse(JSON.stringify(value));
}

function assert(condition, message, details = {}) {
    if (condition) return;
    const error = new Error(message);
    error.code = 'EXTENSION_MANIFEST_INVALID';
    error.details = details;
    throw error;
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim().length > 0;
}

function validateContributionIds(manifest) {
    const contributions = manifest.contributes || {};
    for (const field of [
        'routes',
        'navigation',
        'pageActions',
        'commands',
        'settings',
        'scheduledCommands',
        'archiveTypes',
        'features',
    ]) {
        for (const contribution of contributions[field] || []) {
            const id =
                typeof contribution === 'string'
                    ? contribution
                    : contribution?.id;
            assert(
                isNonEmptyString(id) &&
                    CONTRIBUTION_PREFIX_RE.test(id) &&
                    id.startsWith(`${manifest.id}.`),
                `Contribution ${field} must be namespaced by ${manifest.id}`,
                { field, id, extensionId: manifest.id },
            );
        }
    }
}

function validateLanes(manifest) {
    const lanes = manifest.scriptExecutionLanes;
    if (lanes == null) return;
    assert(
        lanes && typeof lanes === 'object' && !Array.isArray(lanes),
        'scriptExecutionLanes must be an object',
    );
    const seenRoutes = new Map();
    for (const [laneId, lane] of Object.entries(lanes)) {
        assert(
            Object.prototype.hasOwnProperty.call(EXTENSION_LANES, laneId),
            `Unknown extension execution lane: ${laneId}`,
            { laneId },
        );
        assert(
            lane && typeof lane === 'object',
            `Execution lane ${laneId} must be an object`,
        );
        assert(
            lane.product === EXTENSION_LANES[laneId].product,
            `Execution lane ${laneId} targets the wrong product`,
            { laneId, product: lane.product },
        );
        if (lane.implementationId != null) {
            assert(
                isNonEmptyString(lane.implementationId),
                `Execution lane ${laneId} implementationId is invalid`,
            );
        }
        for (const route of lane.routes || []) {
            assert(
                isNonEmptyString(route),
                `Execution lane ${laneId} route is invalid`,
            );
            const previous = seenRoutes.get(route);
            assert(
                !previous,
                `Route ${route} is assigned to multiple execution lanes`,
                { route, previous, laneId },
            );
            seenRoutes.set(route, laneId);
        }
        for (const command of lane.commands || []) {
            assert(
                isNonEmptyString(command) &&
                    command.startsWith(`${manifest.id}.`),
                `Scheduled command must be namespaced by ${manifest.id}`,
                { command, laneId },
            );
        }
    }
}

/** Validate and clone an extension manifest before it enters any registry. */
export function validateExtensionManifest(input) {
    const manifest = clone(input);
    assert(
        manifest && typeof manifest === 'object' && !Array.isArray(manifest),
        'Extension manifest must be an object',
    );
    assert(
        manifest.schemaVersion === EXTENSION_MANIFEST_SCHEMA_VERSION,
        `Unsupported extension manifest schema: ${manifest.schemaVersion}`,
    );
    assert(
        isNonEmptyString(manifest.id) && EXTENSION_ID_RE.test(manifest.id),
        'Extension id must use reverse-domain notation',
        { id: manifest.id },
    );
    assert(
        !manifest.id.split('.').some((part) => RESERVED_IDS.has(part)),
        'Extension id contains a reserved path segment',
        { id: manifest.id },
    );
    assert(
        EXTENSION_KINDS.includes(manifest.kind),
        `Unsupported extension kind: ${manifest.kind}`,
    );
    assert(isNonEmptyString(manifest.name), 'Extension name is required');
    assert(isNonEmptyString(manifest.version), 'Extension version is required');
    assert(
        manifest.publisher &&
            isNonEmptyString(manifest.publisher.id) &&
            isNonEmptyString(manifest.publisher.name),
        'Extension publisher is required',
    );
    assert(
        manifest.host && isNonEmptyString(manifest.host.apiVersion),
        'Extension host.apiVersion is required',
    );
    if (manifest.host.runtimes != null) {
        assert(
            Array.isArray(manifest.host.runtimes) &&
                manifest.host.runtimes.every(isNonEmptyString),
            'Extension host.runtimes must be a string array',
        );
    }
    if (manifest.permissions != null) {
        assert(
            Array.isArray(manifest.permissions),
            'Extension permissions must be an array',
        );
        for (const permission of manifest.permissions) {
            const name =
                typeof permission === 'string' ? permission : permission?.name;
            assert(isNonEmptyString(name), 'Extension permission is invalid');
        }
    }
    validateContributionIds(manifest);
    validateLanes(manifest);

    return manifest;
}

export function normalizeExtensionManifest(input) {
    const manifest = validateExtensionManifest(input);
    return {
        ...manifest,
        distribution:
            manifest.distribution ||
            (manifest.kind === 'bundled' ? 'bundled' : 'store'),
        permissions: clone(manifest.permissions || []),
        contributes: clone(manifest.contributes || {}),
        scriptExecutionLanes: clone(manifest.scriptExecutionLanes || {}),
    };
}

/**
 * Canonical JSON used by catalog/receipt digest verification. Undefined object
 * members are removed and object keys are sorted recursively. Arrays retain
 * their declared order because route order and permission prompts are
 * meaningful to the Host.
 */
export function canonicalize(value) {
    if (Array.isArray(value)) return value.map(canonicalize);
    if (value && typeof value === 'object') {
        return Object.keys(value)
            .filter((key) => value[key] !== undefined)
            .sort()
            .reduce((result, key) => {
                result[key] = canonicalize(value[key]);
                return result;
            }, {});
    }
    return value;
}

export function canonicalJson(value) {
    return JSON.stringify(canonicalize(value));
}

export function assertExtensionId(id) {
    assert(
        isNonEmptyString(id) && EXTENSION_ID_RE.test(id),
        'Invalid extension id',
        { id },
    );
    return id;
}

export function listManifestContributionIds(manifest) {
    const normalized = normalizeExtensionManifest(manifest);
    const result = [];
    for (const field of [
        'routes',
        'navigation',
        'pageActions',
        'commands',
        'settings',
        'scheduledCommands',
        'archiveTypes',
        'features',
    ]) {
        for (const item of normalized.contributes[field] || []) {
            result.push(typeof item === 'string' ? item : item.id);
        }
    }
    return result;
}

export function routeExecutionLane(manifest, route, method) {
    const lanes = manifest?.scriptExecutionLanes || {};
    const normalizedMethod = method ? `${method}`.toUpperCase() : null;
    for (const [laneId, lane] of Object.entries(lanes)) {
        for (const candidate of lane.routes || []) {
            if (typeof candidate === 'object') {
                if (
                    candidate.path === route &&
                    (!candidate.method ||
                        `${candidate.method}`.toUpperCase() ===
                            normalizedMethod)
                ) {
                    return laneId;
                }
            } else if (candidate === route) {
                return laneId;
            }
        }
    }
    return null;
}

export function extensionAvailability(record, extensionId) {
    if (!record) {
        return {
            status: 'missing',
            extensionId,
            reasonCode: 'EXTENSION_NOT_INSTALLED',
        };
    }
    if (
        record.installationStatus === 'removed' &&
        record.dataStatus === 'retained'
    ) {
        return {
            status: 'reinstall-required',
            extensionId,
            reasonCode: 'EXTENSION_REINSTALL_REQUIRED',
            installationStatus: 'removed',
            dataStatus: 'retained',
            codeStatus: record.codeStatus || 'missing',
            retainedReason: record.retainedReason || 'user-uninstalled',
            reinstallHint: clone(record.reinstallHint || {}),
        };
    }
    if (
        record.lifecycleStatus === 'installing' ||
        record.lifecycleStatus === 'updating' ||
        record.lifecycleStatus === 'restoring'
    ) {
        return {
            status: record.lifecycleStatus,
            extensionId,
            taskId: record.taskId,
        };
    }
    if (
        record.compatibilityStatus &&
        record.compatibilityStatus !== 'compatible'
    ) {
        return {
            status: 'incompatible',
            extensionId,
            reasonCode: record.reasonCode || 'EXTENSION_INCOMPATIBLE',
        };
    }
    if (record.installationStatus !== 'installed') {
        return {
            status: 'missing',
            extensionId,
            reasonCode: 'EXTENSION_NOT_INSTALLED',
        };
    }
    if (record.enabled !== true) {
        return {
            status: 'disabled',
            extensionId,
            reasonCode: 'EXTENSION_DISABLED',
        };
    }
    return { status: 'enabled', extensionId };
}

export function cloneExtensionValue(value) {
    return clone(value);
}

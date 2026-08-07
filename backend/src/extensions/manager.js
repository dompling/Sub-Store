import $ from '@/core/app';
import { ARTIFACTS_KEY, EXTENSIONS_KEY } from '@/constants';
import {
    EXTENSION_HOST_API_VERSION,
    EXTENSION_IDS,
    EXTENSION_MANIFEST_SCHEMA_VERSION,
    canonicalJson,
    cloneExtensionValue,
    extensionAvailability,
    normalizeExtensionManifest,
} from './contracts';
import {
    createLocalOfficialPackage,
    embeddedExtensionImplementations,
    findCatalogEntry,
    listCatalogEntries,
    officialExtensionTrustedKeys,
    signedExtensionCatalog,
} from './catalog.generated';
import {
    diagnosticDigest,
    extensionPackageDigest,
    isSha256Digest,
    sha256Hex,
    verifyReceipt,
    verifySignedEnvelope,
} from './signature';
import { createNodeExtensionPackageStore } from './package-store';
import { version as packageVersion } from '../../package.json';

const STATE_SCHEMA_VERSION = 1;
const MAX_TASKS = 100;
const MAX_PACKAGE_FILES = 128;
const MAX_PACKAGE_FILE_BYTES = 2 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 8 * 1024 * 1024;
const RESERVED_PACKAGE_FILES = new Set([
    'manifest.json',
    'receipt.json',
    'package.json',
    'active.json',
]);
const LEGACY_CONFIG_HOSTING_ADOPTION = 'config-hosting-legacy-artifacts-v1';
const TRUSTED_OFFICIAL_ALLOWLIST = Object.freeze({
    [EXTENSION_IDS.configHosting]: 'org.substore',
});
const KNOWN_EXTENSION_PERMISSIONS = Object.freeze([
    'storage.own',
    'resources.list',
    'resources.read',
    'resources.produce',
    'references.manage-own',
    'publishers.use',
    'credentials.use-handle',
    'scheduler.jobs',
    'crypto.age.encrypt',
    'archive.contribute',
    'backup.contribute',
    'settings.contribute',
    'routes.namespaced',
    'routes.legacy-alias',
    'navigation.register',
    'commands.register',
    'network.fetch',
    'artifact.produce',
    'artifact-source.register',
]);
const DEFAULT_EXTENSION_HOST_CAPABILITIES = Object.freeze({
    'resource-producer@1': Object.freeze({
        status: 'compatibility-adapter',
        complete: false,
        implementation: 'legacy-resource-producer-adapter',
    }),
    'artifact-source-registry@1': Object.freeze({
        status: 'compatibility-adapter',
        complete: false,
        implementation: 'legacy-artifact-source-registry-adapter',
    }),
    'reference-graph@1': Object.freeze({
        status: 'compatibility-adapter',
        complete: false,
        implementation: 'legacy-reference-projection',
    }),
    'generation-storage@1': Object.freeze({
        status: 'compatibility-adapter',
        complete: false,
        implementation: 'legacy-extension-state-generation',
    }),
    'route-gateway@1': Object.freeze({
        status: 'available',
        complete: true,
        implementation: 'extension-route-gateway',
    }),
});
let taskSequence = 0;

function now() {
    return Date.now();
}

function clone(value) {
    return cloneExtensionValue(value);
}

function parseStoredState(value) {
    if (typeof value === 'string') {
        try {
            return JSON.parse(value);
        } catch (e) {
            return null;
        }
    }
    return value && typeof value === 'object' ? value : null;
}

function createTaskId() {
    taskSequence += 1;
    return `extension-task-${now()}-${taskSequence}`;
}

function runtimeName(env = {}) {
    if (env.isNode) return 'node';
    if (env.isQX) return 'qx';
    if (env.isLoon) return 'loon';
    if (env.isSurge) return 'surge';
    if (env.isStash) return 'stash';
    if (env.isShadowRocket) return 'shadowrocket';
    if (env.isEgern) return 'egern';
    return 'unknown';
}

function managementMode(env = {}) {
    const configuredToken = (() => {
        try {
            return (
                eval('process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN') ||
                eval('process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH')
            );
        } catch (e) {
            return null;
        }
    })();
    if (env.isNode && configuredToken) return 'token';
    if (env.isNode) return 'read-only';
    return 'read-only';
}

function digestOnlyEnabledFromEnvironment() {
    try {
        return (
            eval('process.env.SUB_STORE_EXTENSION_ALLOW_DIGEST_ONLY') === 'true'
        );
    } catch (e) {
        return false;
    }
}

function verificationMode(result) {
    if (!result?.valid) return 'unverified';
    if (result.trust === 'trusted') return 'trusted-signature';
    if (result.trust === 'integrity-only') {
        return 'digest-only-development';
    }
    return 'unverified';
}

function parseVersion(value) {
    const match = `${value || ''}`.match(/^(\d+)\.(\d+)\.(\d+)/);
    return match ? match.slice(1).map(Number) : null;
}

function compareVersions(left, right) {
    const a = parseVersion(left);
    const b = parseVersion(right);
    if (!a || !b) return null;
    for (let index = 0; index < 3; index += 1) {
        if (a[index] > b[index]) return 1;
        if (a[index] < b[index]) return -1;
    }
    return 0;
}

function satisfiesVersionConstraint(current, constraint) {
    if (!constraint) return true;
    const comparators = `${constraint}`.trim().split(/\s+/).filter(Boolean);
    return comparators.every((comparator) => {
        const match = comparator.match(/^(>=|<=|>|<|=)?(\d+\.\d+\.\d+)$/);
        if (!match) return false;
        const comparison = compareVersions(current, match[2]);
        if (comparison === null) return false;
        switch (match[1] || '=') {
            case '>=':
                return comparison >= 0;
            case '<=':
                return comparison <= 0;
            case '>':
                return comparison > 0;
            case '<':
                return comparison < 0;
            default:
                return comparison === 0;
        }
    });
}

function runtimeVariant(manifest, runtime) {
    if (manifest?.variants?.[runtime]) return runtime;
    if (runtime !== 'node' && manifest?.variants?.['default-script-runtime']) {
        return 'default-script-runtime';
    }
    return null;
}

function packageFileIsSafe(value) {
    const file = `${value || ''}`.replace(/\\/g, '/');
    return Boolean(
        file &&
            !file.startsWith('/') &&
            !file
                .split('/')
                .some((part) => !part || part === '.' || part === '..'),
    );
}

function defaultConsistency(env = {}) {
    if (env.isNode) {
        return {
            mode: 'single-process-verified-write',
            crossRequestLock: false,
            atomicPointerCommit: false,
            conflictDetection: 'revision-and-postwrite-verification',
        };
    }
    return {
        mode: 'single-writer-required',
        crossRequestLock: false,
        atomicPointerCommit: false,
        conflictDetection: 'revision-and-postwrite-verification',
    };
}

function defaultRestoreIsolation() {
    return 'none';
}

function createEmptyState() {
    return {
        schemaVersion: STATE_SCHEMA_VERSION,
        revision: 0,
        storeRevision: 0,
        dataGeneration: 0,
        installed: {},
        migrations: {},
        tasks: [],
        audit: [],
    };
}

function normalizeState(value) {
    const parsed = parseStoredState(value);
    const state = parsed && typeof parsed === 'object' ? parsed : {};
    return {
        ...createEmptyState(),
        ...state,
        schemaVersion: STATE_SCHEMA_VERSION,
        revision: Number.isInteger(state.revision) ? state.revision : 0,
        storeRevision: Number.isInteger(state.storeRevision)
            ? state.storeRevision
            : Number.isInteger(state.revision)
            ? state.revision
            : 0,
        dataGeneration: Number.isInteger(state.dataGeneration)
            ? state.dataGeneration
            : 0,
        installed:
            state.installed && typeof state.installed === 'object'
                ? state.installed
                : {},
        migrations:
            state.migrations && typeof state.migrations === 'object'
                ? state.migrations
                : {},
        tasks: Array.isArray(state.tasks) ? state.tasks : [],
        audit: Array.isArray(state.audit) ? state.audit : [],
    };
}

function stateRecordFromBundled(entry) {
    const manifest = entry.manifest;
    return {
        extensionId: manifest.id,
        version: manifest.version,
        kind: manifest.kind,
        manifestDigest: null,
        packageDigest: null,
        selectedVariant: 'bundled',
        installationStatus: 'installed',
        dataStatus: 'active',
        enabled: entry.defaultEnabled === true,
        codeStatus: 'embedded-active',
        verificationMode: 'unverified',
        compatibilityStatus: 'compatible',
        installedAt: 0,
        updatedAt: 0,
        source: 'bundled',
    };
}

function embeddedVariant(manifest, runtime) {
    if (manifest?.variants?.[runtime]) return runtime;
    return manifest?.variants?.['default-script-runtime']
        ? 'default-script-runtime'
        : null;
}

function stateRecordFromEmbedded(entry, runtime) {
    const manifest = entry.manifest || entry;
    const selectedVariant = embeddedVariant(manifest, runtime);
    const variant = manifest.variants?.[selectedVariant] || {};
    return {
        extensionId: manifest.id,
        version: manifest.version,
        kind: manifest.kind,
        manifestDigest: entry.manifestDigest || null,
        packageDigest: null,
        receiptDigest: null,
        selectedVariant,
        implementation: {
            id: variant.implementationId,
            abi: variant.implementationAbi,
            frontendAssetId: variant.frontendAssetId,
            entrypoint: variant.entrypoint,
            lanes:
                embeddedExtensionImplementations[manifest.id]?.lanes ||
                manifest.scriptExecutionLanes,
            containsExecutableCode: variant.containsExecutableCode === true,
        },
        installationStatus: 'installed',
        dataStatus: 'active',
        enabled: true,
        codeStatus: 'embedded-active',
        verificationMode: 'unverified',
        compatibilityStatus: selectedVariant
            ? 'compatible'
            : 'backend-update-required',
        reasonCode: selectedVariant
            ? undefined
            : 'EXTENSION_BACKEND_UPDATE_REQUIRED',
        installedAt: 0,
        updatedAt: 0,
        source: 'release-embedded-adoption',
    };
}

function errorWithCode(code, message, details) {
    const error = new Error(message || code);
    error.code = code;
    error.details = details;
    error.statusCode = 409;
    return error;
}

function publicRecord(record) {
    if (!record) return null;
    const result = clone(record);
    delete result.packageDirectory;
    delete result.entrypoint;
    return result;
}

function catalogEntryKey(id, version) {
    return `${id}\u0000${version}`;
}

function buildCatalogAuthorizationIndex(envelope) {
    const index = new Map();
    const entries = envelope?.payload?.entries;
    if (!Array.isArray(entries)) {
        return {
            index,
            error: errorWithCode(
                'EXTENSION_CATALOG_ENTRIES_INVALID',
                'Signed extension catalog does not contain an entries array',
            ),
        };
    }
    for (const entry of entries) {
        if (
            !entry ||
            typeof entry.id !== 'string' ||
            typeof entry.version !== 'string' ||
            !isSha256Digest(entry.manifestDigest)
        ) {
            return {
                index,
                error: errorWithCode(
                    'EXTENSION_CATALOG_ENTRY_INVALID',
                    'Signed extension catalog entry is missing its identity digest',
                    { entry: clone(entry) },
                ),
            };
        }
        const key = catalogEntryKey(entry.id, entry.version);
        if (index.has(key)) {
            return {
                index,
                error: errorWithCode(
                    'EXTENSION_CATALOG_ENTRY_DUPLICATE',
                    'Signed extension catalog contains a duplicate extension version',
                    { id: entry.id, version: entry.version },
                ),
            };
        }
        const packageDigests = entry.packageDigests || {};
        if (
            typeof packageDigests !== 'object' ||
            Array.isArray(packageDigests) ||
            Object.values(packageDigests).some(
                (digest) => !isSha256Digest(digest),
            )
        ) {
            return {
                index,
                error: errorWithCode(
                    'EXTENSION_CATALOG_PACKAGE_DIGESTS_INVALID',
                    'Signed extension catalog package digest projection is invalid',
                    { id: entry.id, version: entry.version },
                ),
            };
        }
        index.set(key, {
            ...clone(entry),
            packageDigests: clone(packageDigests),
        });
    }
    return { index, error: null };
}

const RETRYABLE_LEGACY_ADOPTION_ERRORS = new Set([
    'EXTENSION_CATALOG_UNVERIFIED',
    'EXTENSION_CATALOG_EXPIRED',
    'EXTENSION_CRYPTO_UNAVAILABLE',
    'EXTENSION_SIGNING_KEY_UNTRUSTED',
    'EXTENSION_SIGNING_KEY_REVOKED',
    'EXTENSION_DIGEST_SIGNATURE_UNTRUSTED',
    'EXTENSION_CATALOG_ENTRIES_INVALID',
    'EXTENSION_CATALOG_ENTRY_INVALID',
    'EXTENSION_CATALOG_ENTRY_DUPLICATE',
    'EXTENSION_CATALOG_PACKAGE_DIGESTS_INVALID',
    'EXTENSION_CATALOG_ENTRY_UNAUTHORIZED',
    'EXTENSION_CATALOG_MANIFEST_MISMATCH',
    'EXTENSION_CATALOG_PACKAGE_MISMATCH',
]);

function retryableLegacyAdoptionError(error) {
    return RETRYABLE_LEGACY_ADOPTION_ERRORS.has(error?.code);
}

export class ExtensionManager {
    constructor({
        store = $,
        env = $.env,
        bundledCatalog = null,
        officialCatalog = null,
        catalogEnvelope = signedExtensionCatalog,
        persistDefaults = false,
        allowDigestOnly,
        trustedKeys,
        revokedKeyIds = [],
        backendVersion = packageVersion,
        hostCapabilities = DEFAULT_EXTENSION_HOST_CAPABILITIES,
        trustedOfficialAllowlist = TRUSTED_OFFICIAL_ALLOWLIST,
        knownPermissions = KNOWN_EXTENSION_PERMISSIONS,
        packageStore,
    } = {}) {
        this.store = store;
        this.env = env || {};
        this.runtime = runtimeName(this.env);
        this.backendVersion = backendVersion;
        this.hostCapabilities = clone(hostCapabilities || {});
        this.trustedOfficialAllowlist = clone(trustedOfficialAllowlist || {});
        this.knownPermissions = new Set(knownPermissions || []);
        this.bundledCatalog =
            bundledCatalog ||
            listCatalogEntries().filter(
                (entry) => entry.distribution === 'bundled',
            );
        this.officialCatalog =
            officialCatalog ||
            listCatalogEntries().filter(
                (entry) => entry.distribution !== 'bundled',
            );
        this.catalogEnvelope = catalogEnvelope;
        this.allowDigestOnly =
            allowDigestOnly === undefined
                ? digestOnlyEnabledFromEnvironment()
                : allowDigestOnly === true;
        this.verificationOptions = {
            allowDigestOnly: this.allowDigestOnly,
            trustedKeys: {
                ...officialExtensionTrustedKeys,
                ...(trustedKeys || {}),
            },
            revokedKeyIds: [...(revokedKeyIds || [])],
        };
        this.adapters = new Map();
        this.persistDefaults = persistDefaults;
        this.packageStore =
            packageStore === undefined && this.env.isNode && this.store === $
                ? createNodeExtensionPackageStore({
                      verificationOptions: this.verificationOptions,
                  })
                : packageStore || null;
        const storageIdentitySeed =
            this.packageStore?.rootPath ||
            this.store?.identity ||
            `${this.runtime}:${EXTENSIONS_KEY}`;
        this.storageIdentity =
            sha256Hex(storageIdentitySeed) ||
            diagnosticDigest(storageIdentitySeed);
        this.instanceId = this.storageIdentity;
        this.packageStore?.setVerificationOptions?.(this.verificationOptions);
        this.catalogVerification = verifySignedEnvelope(
            catalogEnvelope,
            this.verificationOptions,
        );
        const catalogAuthorization = buildCatalogAuthorizationIndex(
            this.catalogEnvelope,
        );
        this.catalogAuthorizations = catalogAuthorization.index;
        this.catalogAuthorizationError = catalogAuthorization.error;
        if (this.catalogVerification.valid && this.catalogAuthorizationError) {
            this.catalogVerification = {
                ...this.catalogVerification,
                valid: false,
                trust: 'untrusted',
                reasonCode: this.catalogAuthorizationError.code,
                details: clone(this.catalogAuthorizationError.details),
            };
        }
        this.catalogVerificationMode = verificationMode(
            this.catalogVerification,
        );
        if (
            !this.catalogVerification.valid &&
            this.catalogEnvelope === signedExtensionCatalog
        ) {
            // A proxy host without synchronous SHA-256 can still expose the
            // read-only bundled catalog, but lifecycle install remains closed.
            this.catalogVerification = {
                ...this.catalogVerification,
                reasonCode:
                    this.catalogVerification.reasonCode ||
                    'EXTENSION_CATALOG_UNVERIFIED',
            };
        }
    }

    registerAdapter(extensionId, adapter) {
        const entry = this.findEntry(extensionId);
        if (!entry)
            throw errorWithCode(
                'EXTENSION_UNKNOWN',
                `Unknown extension ${extensionId}`,
            );
        this.adapters.set(extensionId, adapter || {});
        return this.adapters.get(extensionId);
    }

    registerManifest(manifest, adapter, options = {}) {
        const normalized = normalizeExtensionManifest(manifest);
        const existing = this.findEntry(normalized.id);
        const existingManifest = existing
            ? normalizeExtensionManifest(existing.manifest || existing)
            : null;
        if (
            existingManifest &&
            canonicalJson(existingManifest) !== canonicalJson(normalized)
        ) {
            throw errorWithCode(
                'EXTENSION_MANIFEST_CONFLICT',
                `Extension ${normalized.id} was registered with a conflicting manifest`,
                {
                    extensionId: normalized.id,
                    registeredVersion: existingManifest.version,
                    requestedVersion: normalized.version,
                },
            );
        }
        const authorization = this.catalogVerification.valid
            ? this._assertManifestCatalogAuthorization(normalized)
            : null;
        if (!existing) {
            if (options.kind === 'official') {
                this.officialCatalog.push({
                    id: normalized.id,
                    manifest: normalized,
                    distribution: 'trusted-official-package',
                    source: 'runtime-local',
                    defaultEnabled: false,
                    manifestDigest: authorization?.manifestDigest || null,
                    packageDigests: clone(authorization?.packageDigests || {}),
                });
            } else {
                this.bundledCatalog.push({
                    id: normalized.id,
                    manifest: normalized,
                    distribution: 'bundled',
                    source: 'runtime-bundled',
                    defaultEnabled: options.defaultEnabled === true,
                    manifestDigest: authorization?.manifestDigest || null,
                });
            }
        }
        if (adapter) this.adapters.set(normalized.id, adapter);
        return normalized;
    }

    findEntry(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        return (
            this.bundledCatalog.find(
                (entry) =>
                    entry.id === canonicalId ||
                    entry.manifest?.id === canonicalId,
            ) ||
            this.officialCatalog.find(
                (entry) =>
                    entry.id === canonicalId ||
                    entry.manifest?.id === canonicalId,
            ) ||
            findCatalogEntry(canonicalId)
        );
    }

    resolveId(extensionId) {
        if (extensionId === 'config-generator')
            return EXTENSION_IDS.configGenerator;
        if (extensionId === 'config-hosting')
            return EXTENSION_IDS.configHosting;
        return extensionId;
    }

    getManifest(extensionId) {
        const entry = this.findEntry(extensionId);
        return entry
            ? normalizeExtensionManifest(entry.manifest || entry)
            : null;
    }

    readState() {
        const state = normalizeState(this.store.read(EXTENSIONS_KEY));
        for (const entry of this.bundledCatalog) {
            const manifest = entry.manifest || entry;
            if (!state.installed[manifest.id]) {
                state.installed[manifest.id] = stateRecordFromBundled({
                    manifest,
                    defaultEnabled: entry.defaultEnabled,
                });
            }
        }
        if (!this.env.isNode) {
            for (const entry of this.officialCatalog) {
                const manifest = entry.manifest || entry;
                if (
                    manifest.id === EXTENSION_IDS.configHosting &&
                    !state.installed[manifest.id] &&
                    embeddedExtensionImplementations[manifest.id]
                ) {
                    state.installed[manifest.id] = stateRecordFromEmbedded(
                        entry,
                        this.runtime,
                    );
                }
            }
        }
        return state;
    }

    persistState(state) {
        const normalized = normalizeState(state);
        // Root stores in script hosts historically accept a serialized value;
        // Node's OpenAPI adapter parses both forms on the next read.
        this.store.write(JSON.stringify(normalized), EXTENSIONS_KEY);
        return normalized;
    }

    _commit(mutator, { expectedRevision } = {}) {
        const current = this.readState();
        if (
            expectedRevision !== undefined &&
            Number(expectedRevision) !== Number(current.revision)
        ) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state changed; reload before retrying',
                {
                    expectedRevision: Number(expectedRevision),
                    currentRevision: current.revision,
                },
            );
        }
        const next = normalizeState(mutator(clone(current)) || current);
        next.revision = current.revision + 1;
        next.storeRevision = next.revision;
        next.updatedAt = now();
        this.persistState(next);
        const committed = this.readState();
        if (
            Number(committed.revision) !== Number(next.revision) ||
            Number(committed.storeRevision) !== Number(next.storeRevision)
        ) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state write could not be verified',
                {
                    expectedRevision: next.revision,
                    currentRevision: committed.revision,
                    recoverySnapshot: clone(next),
                },
            );
        }
        return committed;
    }

    _recordAudit(state, event) {
        state.audit = [...(state.audit || []), { ...event, at: now() }].slice(
            -MAX_TASKS,
        );
    }

    getAvailability(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        return extensionAvailability(
            this.readState().installed[canonicalId],
            canonicalId,
        );
    }

    getRecord(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        return this.readState().installed[canonicalId] || null;
    }

    getHealth(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        const availability = this.getAvailability(canonicalId);
        let implementation = null;
        let implementationError = null;
        try {
            implementation = clone(
                this.adapters.get(canonicalId)?.health?.() || null,
            );
        } catch (error) {
            implementationError = {
                code: error.code || 'EXTENSION_HEALTH_CHECK_FAILED',
                message: error.message,
            };
        }
        const activeMismatch =
            availability.status === 'enabled' &&
            implementation &&
            implementation.active === false;
        return {
            extensionId: canonicalId,
            status:
                availability.status === 'enabled' &&
                !implementationError &&
                !activeMismatch
                    ? 'healthy'
                    : implementationError || activeMismatch
                    ? 'unhealthy'
                    : availability.status,
            availability,
            implementation,
            error: implementationError,
        };
    }

    getRuntimeManifest() {
        const state = this.readState();
        const consistency = defaultConsistency(this.env);
        const currentManagementMode = managementMode(this.env);
        const restoreIsolation = defaultRestoreIsolation(this.env);
        const entries = [...this.bundledCatalog, ...this.officialCatalog];
        const extensions = entries.map((entry) => {
            const manifest = normalizeExtensionManifest(
                entry.manifest || entry,
            );
            const record = state.installed[manifest.id];
            const availability = extensionAvailability(record, manifest.id);
            return {
                id: manifest.id,
                version: manifest.version,
                name: manifest.name,
                kind: manifest.kind,
                distribution: manifest.distribution,
                manifest: clone(manifest),
                manifestDigest: record?.manifestDigest || null,
                status: availability.status,
                availability,
                enabled: record?.enabled === true,
                installationStatus:
                    record?.installationStatus || 'never-installed',
                dataStatus: record?.dataStatus || 'none',
                codeStatus: record?.codeStatus || 'missing',
                retainedReason: record?.retainedReason,
                selectedVariant: record?.selectedVariant || null,
                receipt: publicRecord(record),
                implementation: clone(record?.implementation || {}),
                contributes: clone(manifest.contributes || {}),
                scriptExecutionLanes: clone(
                    manifest.scriptExecutionLanes || {},
                ),
            };
        });
        return {
            schemaVersion: EXTENSION_MANIFEST_SCHEMA_VERSION,
            hostApiVersion: EXTENSION_HOST_API_VERSION,
            backendVersion: this.backendVersion,
            runtime: this.runtime,
            instanceId: this.instanceId,
            storageIdentity: this.storageIdentity,
            revision: state.revision,
            dataGeneration: state.dataGeneration,
            managementMode: currentManagementMode,
            storageConsistency: consistency.mode,
            consistency,
            restoreIsolation,
            verificationMode: this.catalogVerificationMode,
            capabilities: {
                managementMode: currentManagementMode,
                storageConsistency: consistency,
                restoreIsolation,
                verificationMode: this.catalogVerificationMode,
                supportsSignedCatalog:
                    this.catalogVerificationMode === 'trusted-signature',
                supportsIntegrityVerifiedCatalog:
                    this.catalogVerification.valid === true,
                supportsTrustedOfficialPackage: Boolean(this.env.isNode),
                supportsEmbeddedReceipt: !this.env.isNode,
                extensionCompatibility: {
                    mode: 'manifest-preflight-v1',
                    knownPermissionCount: this.knownPermissions.size,
                    hostCapabilities: clone(this.hostCapabilities),
                },
            },
            extensions,
        };
    }

    getCatalog() {
        const entries = [...this.bundledCatalog, ...this.officialCatalog];
        const projectedEntries = entries.map((entry) => {
            const manifest = normalizeExtensionManifest(
                entry.manifest || entry,
            );
            const manifestDigest = sha256Hex(canonicalJson(manifest));
            const authorization = this.catalogAuthorizations.get(
                catalogEntryKey(manifest.id, manifest.version),
            );
            const catalogAuthorized = Boolean(
                authorization &&
                    manifestDigest &&
                    authorization.manifestDigest === manifestDigest,
            );
            return {
                ...clone(manifest),
                id: manifest.id,
                manifest: clone(manifest),
                distribution:
                    entry.distribution || manifest.distribution || 'bundled',
                source: entry.source,
                defaultEnabled: entry.defaultEnabled === true,
                manifestDigest,
                packageDigests: clone(
                    authorization?.packageDigests || entry.packageDigests || {},
                ),
                catalogAuthorized,
            };
        });
        const catalogClosed = projectedEntries.every(
            (entry) => entry.catalogAuthorized,
        );
        return {
            schemaVersion: this.catalogEnvelope?.payload?.schemaVersion || 1,
            sequence: this.catalogEnvelope?.payload?.sequence || 0,
            channel: this.catalogEnvelope?.payload?.channel || 'stable',
            expiresAt: this.catalogEnvelope?.expiresAt || null,
            verified: this.catalogVerification.valid && catalogClosed,
            verificationMode: this.catalogVerificationMode,
            verification: {
                ...clone(this.catalogVerification),
                catalogClosed,
            },
            entries: projectedEntries,
        };
    }

    getInstalled() {
        const state = this.readState();
        return Object.values(state.installed).map((record) => ({
            ...publicRecord(record),
            availability: extensionAvailability(record, record.extensionId),
        }));
    }

    getTask(taskId) {
        return (
            this.readState().tasks.find((task) => task.id === taskId) || null
        );
    }

    _createTask(state, { extensionId, action, idempotencyKey }) {
        const existing = idempotencyKey
            ? state.tasks.find(
                  (task) =>
                      task.extensionId === extensionId &&
                      task.action === action &&
                      task.idempotencyKey === idempotencyKey,
              )
            : null;
        if (existing) return existing;
        const task = {
            id: createTaskId(),
            extensionId,
            action,
            idempotencyKey: idempotencyKey || null,
            status: 'running',
            startedAt: now(),
            completedAt: null,
            error: null,
        };
        state.tasks = [...state.tasks, task].slice(-MAX_TASKS);
        return task;
    }

    _finishTask(state, task, result, error = null) {
        const target = state.tasks.find((item) => item.id === task.id);
        if (!target) return;
        target.status = error ? 'failed' : 'succeeded';
        target.completedAt = now();
        target.result = clone(result);
        target.error = error
            ? {
                  code: error.code || 'EXTENSION_TASK_FAILED',
                  message: error.message,
                  details: clone(error.details),
              }
            : null;
    }

    _findIdempotentTask(state, extensionId, action, idempotencyKey) {
        if (!idempotencyKey) return null;
        return (
            state.tasks.find(
                (task) =>
                    task.extensionId === extensionId &&
                    task.action === action &&
                    task.idempotencyKey === idempotencyKey,
            ) || null
        );
    }

    _taskResult(task, record) {
        return {
            taskId: task.id,
            ...clone(task.result || {}),
            task: clone(task),
            record: publicRecord(record),
        };
    }

    _preflightManifest(manifest, runtime = this.runtime) {
        if (manifest.host?.apiVersion !== EXTENSION_HOST_API_VERSION) {
            throw errorWithCode(
                'EXTENSION_HOST_API_INCOMPATIBLE',
                `Extension requires Host API ${
                    manifest.host?.apiVersion || 'unknown'
                }`,
                {
                    required: manifest.host?.apiVersion || null,
                    available: EXTENSION_HOST_API_VERSION,
                },
            );
        }
        if (
            manifest.host?.backend &&
            !satisfiesVersionConstraint(
                this.backendVersion,
                manifest.host.backend,
            )
        ) {
            throw errorWithCode(
                'EXTENSION_BACKEND_VERSION_INCOMPATIBLE',
                `Extension requires backend ${manifest.host.backend}`,
                {
                    required: manifest.host.backend,
                    available: this.backendVersion,
                },
            );
        }
        if (
            Array.isArray(manifest.host?.runtimes) &&
            !manifest.host.runtimes.includes(runtime)
        ) {
            throw errorWithCode(
                'EXTENSION_RUNTIME_UNSUPPORTED',
                `Extension does not support the ${runtime} runtime`,
                {
                    runtime,
                    supportedRuntimes: clone(manifest.host.runtimes),
                },
            );
        }
        const selectedVariant = runtimeVariant(manifest, runtime);
        if (manifest.variants && !selectedVariant) {
            throw errorWithCode(
                'EXTENSION_RUNTIME_UNSUPPORTED',
                `No ${runtime} package variant is available`,
                { runtime },
            );
        }
        if (manifest.kind === 'trusted-official') {
            const allowedPublisher =
                this.trustedOfficialAllowlist[manifest.id] || null;
            if (!allowedPublisher) {
                throw errorWithCode(
                    'EXTENSION_TRUSTED_OFFICIAL_ID_NOT_ALLOWLISTED',
                    'Trusted official extension id is not allowlisted',
                    { extensionId: manifest.id },
                );
            }
            if (
                manifest.publisher?.id !== allowedPublisher ||
                manifest.publisher?.verified !== true
            ) {
                throw errorWithCode(
                    'EXTENSION_PUBLISHER_NOT_ALLOWLISTED',
                    'Trusted official extension publisher is not allowlisted',
                    {
                        extensionId: manifest.id,
                        expectedPublisher: allowedPublisher,
                        actualPublisher: manifest.publisher?.id || null,
                    },
                );
            }
            if (
                manifest.trust?.level !== 'official-root' ||
                manifest.trust?.allowedPublisher !== allowedPublisher ||
                manifest.trust?.allowlistedId !== true
            ) {
                throw errorWithCode(
                    'EXTENSION_TRUST_POLICY_INVALID',
                    'Trusted official extension trust policy is invalid',
                    { extensionId: manifest.id },
                );
            }
        }
        const unknownPermissions = (manifest.permissions || [])
            .map((permission) =>
                typeof permission === 'string' ? permission : permission?.name,
            )
            .filter((permission) => !this.knownPermissions.has(permission));
        if (unknownPermissions.length) {
            throw errorWithCode(
                'EXTENSION_PERMISSION_UNKNOWN',
                'Extension requests permissions that this Host does not know',
                { unknownPermissions },
            );
        }
        const capabilityAvailable = (name) => {
            const descriptor = this.hostCapabilities[name];
            return (
                descriptor === true ||
                descriptor?.status === 'available' ||
                descriptor?.status === 'compatibility-adapter'
            );
        };
        const hardCapabilities = clone(manifest.requires?.hard || []);
        const missingHardCapabilities = hardCapabilities.filter(
            (capability) => !capabilityAvailable(capability),
        );
        if (missingHardCapabilities.length) {
            throw errorWithCode(
                'EXTENSION_HARD_CAPABILITY_MISSING',
                'Extension requires Host capabilities that are unavailable',
                {
                    missingCapabilities: missingHardCapabilities,
                    runtime,
                },
            );
        }
        const optionalCapabilities = clone(manifest.requires?.optional || []);
        return {
            status: 'compatible',
            selectedVariant,
            hostApiVersion: EXTENSION_HOST_API_VERSION,
            backendVersion: this.backendVersion,
            runtime,
            hardCapabilities: hardCapabilities.map((name) => ({
                name,
                descriptor: clone(this.hostCapabilities[name]),
            })),
            optionalCapabilities: optionalCapabilities.map((name) => ({
                name,
                available: capabilityAvailable(name),
                descriptor: clone(this.hostCapabilities[name]),
            })),
        };
    }

    _assertManifestCatalogAuthorization(manifest) {
        const normalized = normalizeExtensionManifest(manifest);
        const authorization = this.catalogAuthorizations.get(
            catalogEntryKey(normalized.id, normalized.version),
        );
        if (!authorization) {
            throw errorWithCode(
                'EXTENSION_CATALOG_ENTRY_UNAUTHORIZED',
                'Extension version is not authorized by the signed catalog',
                {
                    extensionId: normalized.id,
                    version: normalized.version,
                },
            );
        }
        const actualDigest = sha256Hex(canonicalJson(normalized));
        if (!actualDigest || authorization.manifestDigest !== actualDigest) {
            throw errorWithCode(
                'EXTENSION_CATALOG_MANIFEST_MISMATCH',
                'Extension manifest does not match the signed catalog entry',
                {
                    extensionId: normalized.id,
                    version: normalized.version,
                    expectedManifestDigest: authorization.manifestDigest,
                    actualManifestDigest: actualDigest,
                },
            );
        }
        return authorization;
    }

    _assertPackageCatalogAuthorization(
        manifest,
        selectedVariant,
        packageDigest,
    ) {
        const authorization =
            this._assertManifestCatalogAuthorization(manifest);
        const expectedPackageDigest =
            authorization.packageDigests?.[selectedVariant];
        if (
            !isSha256Digest(expectedPackageDigest) ||
            expectedPackageDigest !== packageDigest
        ) {
            throw errorWithCode(
                'EXTENSION_CATALOG_PACKAGE_MISMATCH',
                'Extension package does not match the signed catalog entry',
                {
                    extensionId: manifest.id,
                    version: manifest.version,
                    selectedVariant,
                    expectedPackageDigest: expectedPackageDigest || null,
                    actualPackageDigest: packageDigest || null,
                },
            );
        }
        return authorization;
    }

    _assertCatalogReady(manifest) {
        if (!this.catalogVerification.valid) {
            throw errorWithCode(
                'EXTENSION_CATALOG_UNVERIFIED',
                'Signed extension catalog is not verified',
                this.catalogVerification,
            );
        }
        if (this.catalogAuthorizationError) {
            throw this.catalogAuthorizationError;
        }
        if (manifest) this._assertManifestCatalogAuthorization(manifest);
    }

    _hostFacade(extensionId) {
        const adapter = this.adapters.get(extensionId);
        const invoke = (method) => {
            if (!adapter || typeof adapter[method] !== 'function') {
                throw errorWithCode(
                    'EXTENSION_IMPLEMENTATION_UNAVAILABLE',
                    `Extension ${extensionId} has no ${method} implementation`,
                    { extensionId, method },
                );
            }
            return adapter[method]();
        };
        return Object.freeze({
            apiVersion: EXTENSION_HOST_API_VERSION,
            extensionId,
            activate: () => invoke('activate'),
            deactivate: () => invoke('deactivate'),
        });
    }

    _activateRecord(record) {
        const facade = this._hostFacade(record.extensionId);
        if (this.packageStore && record.entrypoint) {
            const runtimeModule = this.packageStore.load(record);
            if (
                runtimeModule?.extensionId !== record.extensionId ||
                runtimeModule?.implementationAbi !== record.implementation?.abi
            ) {
                throw errorWithCode(
                    'EXTENSION_ABI_MISMATCH',
                    'Installed extension entrypoint does not match its receipt',
                    {
                        extensionId: record.extensionId,
                        expectedAbi: record.implementation?.abi,
                        actualAbi: runtimeModule?.implementationAbi,
                    },
                );
            }
            if (typeof runtimeModule.activate !== 'function') {
                throw errorWithCode(
                    'EXTENSION_ACTIVATION_UNAVAILABLE',
                    'Installed extension entrypoint has no activate function',
                    { extensionId: record.extensionId },
                );
            }
            const result = runtimeModule.activate(facade);
            if (result?.active === false) {
                throw errorWithCode(
                    'EXTENSION_ACTIVATION_FAILED',
                    'Installed extension did not become active',
                    { extensionId: record.extensionId },
                );
            }
            this.packageStore.commitActive(record);
            return result;
        }
        if (
            record.source === 'bundled' &&
            !this.adapters.has(record.extensionId)
        ) {
            return { active: true, bundled: true };
        }
        return facade.activate();
    }

    _deactivateRecord(record) {
        const facade = this._hostFacade(record.extensionId);
        if (this.packageStore && record.entrypoint) {
            try {
                this.packageStore.load(record)?.deactivate?.(facade);
            } finally {
                this.packageStore.deactivate(record.extensionId, record);
            }
            return;
        }
        if (
            record.source === 'bundled' &&
            !this.adapters.has(record.extensionId)
        ) {
            return;
        }
        facade.deactivate();
    }

    restoreEnabledExtension(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        const record = this.getRecord(canonicalId);
        if (
            !record ||
            record.installationStatus !== 'installed' ||
            record.enabled !== true ||
            record.compatibilityStatus !== 'compatible'
        ) {
            return null;
        }
        try {
            this._activateRecord(record);
            return {
                extensionId: canonicalId,
                status: 'enabled',
                record: publicRecord(record),
            };
        } catch (error) {
            try {
                this._deactivateRecord(record);
            } catch (cleanupError) {
                error.cleanupError = cleanupError;
            }
            this._commit((state) => {
                const failedRecord = state.installed[canonicalId];
                if (!failedRecord) return state;
                failedRecord.enabled = false;
                failedRecord.codeStatus = 'activation-failed';
                failedRecord.compatibilityStatus = 'activation-failed';
                failedRecord.reasonCode =
                    error.code || 'EXTENSION_ACTIVATION_FAILED';
                failedRecord.updatedAt = now();
                this._recordAudit(state, {
                    action: 'restore-activation',
                    extensionId: canonicalId,
                    result: 'failed-closed',
                    reasonCode: failedRecord.reasonCode,
                });
                return state;
            });
            return {
                extensionId: canonicalId,
                status: 'incompatible',
                reasonCode: error.code || 'EXTENSION_ACTIVATION_FAILED',
            };
        }
    }

    restoreEnabledExtensions() {
        return Object.values(this.readState().installed)
            .filter(
                (record) =>
                    record?.source !== 'bundled' &&
                    record?.installationStatus === 'installed' &&
                    record?.enabled === true &&
                    record?.compatibilityStatus === 'compatible',
            )
            .map((record) => this.restoreEnabledExtension(record.extensionId));
    }

    adoptLegacyConfigHostingIfNeeded() {
        const extensionId = EXTENSION_IDS.configHosting;
        if (!this.env.isNode || !this.packageStore) return null;
        const state = this.readState();
        if (state.installed[extensionId]) return null;
        const previousMigration =
            state.migrations[LEGACY_CONFIG_HOSTING_ADOPTION];
        if (previousMigration && previousMigration.status !== 'deferred') {
            return {
                extensionId,
                status: previousMigration.status,
                reasonCode: previousMigration.reasonCode,
                previouslyAttempted: true,
            };
        }
        let legacyValue;
        try {
            legacyValue = this.store.read(ARTIFACTS_KEY);
        } catch (error) {
            return {
                extensionId,
                status: 'failed-closed',
                reasonCode: 'EXTENSION_LEGACY_ADOPTION_READ_FAILED',
            };
        }
        if (legacyValue === undefined) return null;
        const adoption = {
            kind: 'legacy-artifacts',
            key: ARTIFACTS_KEY,
            detectedAt: now(),
        };
        try {
            this.install(extensionId, {
                idempotencyKey: 'legacy-config-hosting-adoption-v1',
                source: 'legacy-adoption',
                adoption,
            });
            this.enable(extensionId, {
                idempotencyKey: 'legacy-config-hosting-adoption-enable-v1',
            });
            this._commit((nextState) => {
                const record = nextState.installed[extensionId];
                if (record) {
                    record.adoption = clone(adoption);
                    record.adoptionStatus = 'completed';
                    record.updatedAt = now();
                }
                nextState.migrations[LEGACY_CONFIG_HOSTING_ADOPTION] = {
                    status: 'completed',
                    extensionId,
                    completedAt: now(),
                };
                this._recordAudit(nextState, {
                    action: 'legacy-adoption',
                    extensionId,
                    result: 'installed-and-enabled',
                });
                return nextState;
            });
            return {
                extensionId,
                status: 'adopted',
                record: publicRecord(this.getRecord(extensionId)),
            };
        } catch (error) {
            let activeRecord = null;
            try {
                activeRecord = this.getRecord(extensionId);
            } catch (readError) {
                error.readError = readError;
            }
            if (activeRecord?.enabled === true) {
                try {
                    this._deactivateRecord(activeRecord);
                } catch (cleanupError) {
                    error.cleanupError = cleanupError;
                }
            }
            if (!activeRecord && retryableLegacyAdoptionError(error)) {
                if (
                    previousMigration?.status !== 'deferred' ||
                    previousMigration.reasonCode !== error.code
                ) {
                    try {
                        this._commit((nextState) => {
                            nextState.migrations[
                                LEGACY_CONFIG_HOSTING_ADOPTION
                            ] = {
                                status: 'deferred',
                                extensionId,
                                reasonCode: error.code,
                                lastAttemptAt: now(),
                            };
                            this._recordAudit(nextState, {
                                action: 'legacy-adoption',
                                extensionId,
                                result: 'deferred',
                                reasonCode: error.code,
                            });
                            return nextState;
                        });
                    } catch (stateError) {
                        error.stateError = stateError;
                    }
                }
                return {
                    extensionId,
                    status: 'deferred',
                    reasonCode: error.code,
                    retryable: true,
                    error: {
                        code: error.code,
                        message: error.message,
                    },
                };
            }
            try {
                this._commit((nextState) => {
                    const record = nextState.installed[extensionId];
                    if (record) {
                        record.enabled = false;
                        record.adoption = clone(adoption);
                        record.adoptionStatus = 'failed';
                        record.codeStatus = 'activation-failed';
                        record.compatibilityStatus = 'activation-failed';
                        record.reasonCode =
                            error.code || 'EXTENSION_LEGACY_ADOPTION_FAILED';
                        record.updatedAt = now();
                    }
                    nextState.migrations[LEGACY_CONFIG_HOSTING_ADOPTION] = {
                        status: 'failed-closed',
                        extensionId,
                        reasonCode:
                            error.code || 'EXTENSION_LEGACY_ADOPTION_FAILED',
                        failedAt: now(),
                    };
                    this._recordAudit(nextState, {
                        action: 'legacy-adoption',
                        extensionId,
                        result: 'failed-closed',
                        reasonCode:
                            error.code || 'EXTENSION_LEGACY_ADOPTION_FAILED',
                    });
                    return nextState;
                });
            } catch (stateError) {
                error.stateError = stateError;
            }
            return {
                extensionId,
                status: 'failed-closed',
                reasonCode: error.code || 'EXTENSION_LEGACY_ADOPTION_FAILED',
                error: {
                    code: error.code,
                    message: error.message,
                },
            };
        }
    }

    _verifyLocalPackage(extensionId, input = {}) {
        const manifest = this.getManifest(extensionId);
        if (!manifest) {
            throw errorWithCode(
                'EXTENSION_UNKNOWN',
                `Unknown extension ${extensionId}`,
            );
        }
        this._assertCatalogReady(manifest);
        const runtime = input.runtime || this.runtime;
        if (input.runtime && input.runtime !== this.runtime) {
            throw errorWithCode(
                'EXTENSION_RUNTIME_MISMATCH',
                `Package runtime ${input.runtime} does not match ${this.runtime}`,
            );
        }
        const compatibility = this._preflightManifest(manifest, runtime);
        const expectedVariant = compatibility.selectedVariant;
        const packageInput =
            input.package || createLocalOfficialPackage(manifest.id, runtime);
        if (!packageInput) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_NOT_FOUND',
                `No local official package is available for ${manifest.id}`,
            );
        }
        if (
            canonicalJson(packageInput.manifest || null) !==
            canonicalJson(manifest)
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_MANIFEST_MISMATCH',
                'Package manifest does not exactly match the catalog entry',
            );
        }
        const payload = packageInput.payload;
        if (
            !payload ||
            canonicalJson(payload.manifest || null) !== canonicalJson(manifest)
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_MANIFEST_MISMATCH',
                'Signed package payload does not contain the catalog manifest',
            );
        }
        if (input.version && input.version !== manifest.version) {
            throw errorWithCode(
                'EXTENSION_VERSION_UNAVAILABLE',
                `Requested extension version ${input.version} is unavailable`,
                {
                    requestedVersion: input.version,
                    availableVersion: manifest.version,
                },
            );
        }
        if (
            (input.variant && input.variant !== expectedVariant) ||
            packageInput.selectedVariant !== expectedVariant ||
            payload.selectedVariant !== expectedVariant
        ) {
            throw errorWithCode(
                'EXTENSION_VARIANT_MISMATCH',
                `Requested extension variant ${input.variant} is unavailable for ${runtime}`,
                {
                    requestedVariant: input.variant,
                    selectedVariant: packageInput.selectedVariant,
                    payloadVariant: payload.selectedVariant,
                    expectedVariant,
                },
            );
        }
        const variant = manifest.variants?.[expectedVariant];
        if (
            !variant ||
            canonicalJson(payload.variant || null) !== canonicalJson(variant)
        ) {
            throw errorWithCode(
                'EXTENSION_VARIANT_PROJECTION_MISMATCH',
                'Signed package variant does not match the manifest variant',
            );
        }
        if (
            packageInput.schemaVersion !== 1 ||
            payload.schemaVersion !== packageInput.schemaVersion
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_SCHEMA_INCOMPATIBLE',
                'Extension package schema is unsupported',
                {
                    packageSchemaVersion: packageInput.schemaVersion,
                    payloadSchemaVersion: payload.schemaVersion,
                },
            );
        }
        const expectedImplementation = {
            id: variant.implementationId,
            abi: variant.implementationAbi,
            frontendAssetId: variant.frontendAssetId,
            entrypoint: variant.entrypoint,
            lanes:
                embeddedExtensionImplementations[manifest.id]?.lanes ||
                manifest.scriptExecutionLanes,
            containsExecutableCode: variant.containsExecutableCode === true,
        };
        if (
            canonicalJson(payload.receipt || null) !==
            canonicalJson(packageInput.receipt || null)
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_RECEIPT_MISMATCH',
                'Signed package receipt does not match the outer receipt',
            );
        }
        const calculatedPackageDigest = extensionPackageDigest(payload);
        if (
            !isSha256Digest(packageInput.packageDigest) ||
            packageInput.packageDigest !== payload.packageDigest ||
            packageInput.packageDigest !==
                packageInput.receipt?.packageDigest ||
            calculatedPackageDigest !== packageInput.packageDigest
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_DIGEST_INVALID',
                'Package digest is not closed over the signed payload',
                {
                    packageDigest: packageInput.packageDigest || null,
                    payloadPackageDigest: payload.packageDigest || null,
                    receiptPackageDigest:
                        packageInput.receipt?.packageDigest || null,
                    calculatedPackageDigest,
                },
            );
        }
        this._assertPackageCatalogAuthorization(
            manifest,
            expectedVariant,
            packageInput.packageDigest,
        );
        const files = payload.files;
        const fileDigests = payload.fileDigests;
        if (
            !files ||
            typeof files !== 'object' ||
            Array.isArray(files) ||
            !fileDigests ||
            typeof fileDigests !== 'object' ||
            Array.isArray(fileDigests) ||
            Object.keys(files).length > MAX_PACKAGE_FILES ||
            canonicalJson(Object.keys(files).sort()) !==
                canonicalJson(Object.keys(fileDigests).sort())
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH',
                'Package files and file digest map do not match',
            );
        }
        let totalPackageBytes = 0;
        for (const [relativeName, content] of Object.entries(files)) {
            const normalizedName = relativeName.replace(/\\/g, '/');
            const rootName = normalizedName.split('/')[0];
            const byteLength =
                typeof content === 'string'
                    ? typeof TextEncoder === 'function'
                        ? new TextEncoder().encode(content).byteLength
                        : content.length
                    : Number.POSITIVE_INFINITY;
            totalPackageBytes += byteLength;
            if (
                !packageFileIsSafe(relativeName) ||
                (normalizedName === rootName &&
                    RESERVED_PACKAGE_FILES.has(rootName.toLowerCase())) ||
                typeof content !== 'string' ||
                byteLength > MAX_PACKAGE_FILE_BYTES ||
                totalPackageBytes > MAX_PACKAGE_BYTES ||
                !isSha256Digest(fileDigests[relativeName]) ||
                sha256Hex(content) !== fileDigests[relativeName]
            ) {
                throw errorWithCode(
                    'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH',
                    `Package file failed verification: ${relativeName}`,
                    { file: relativeName },
                );
            }
        }
        const containsExecutableCode =
            expectedImplementation.containsExecutableCode;
        if (
            typeof payload.containsExecutableCode !== 'boolean' ||
            payload.containsExecutableCode !== containsExecutableCode
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_EXECUTION_CONTRACT_MISMATCH',
                'Package executable-code declaration does not match its variant',
            );
        }
        if (payload.containsInstallHook !== false) {
            throw errorWithCode(
                'EXTENSION_INSTALL_HOOK_FORBIDDEN',
                'Extension install hooks are not supported',
            );
        }
        if (containsExecutableCode) {
            const entrypoint = expectedImplementation.entrypoint;
            if (
                !packageFileIsSafe(entrypoint) ||
                !Object.prototype.hasOwnProperty.call(files, entrypoint) ||
                !Object.prototype.hasOwnProperty.call(fileDigests, entrypoint)
            ) {
                throw errorWithCode(
                    'EXTENSION_ENTRYPOINT_UNVERIFIED',
                    'Package entrypoint is not included in the verified file map',
                );
            }
        } else if (packageInput.receipt?.implementation?.entrypoint != null) {
            throw errorWithCode(
                'EXTENSION_RECEIPT_IMPLEMENTATION_MISMATCH',
                'A non-executable variant cannot declare an entrypoint',
            );
        }
        const envelopeResult = verifySignedEnvelope(
            {
                payload,
                signature: packageInput.signature,
            },
            this.verificationOptions,
        );
        if (!envelopeResult.valid) {
            throw errorWithCode(
                envelopeResult.reasonCode ||
                    'EXTENSION_PACKAGE_SIGNATURE_INVALID',
                'Official package signature/digest verification failed',
                envelopeResult,
            );
        }
        const receiptResult = verifyReceipt(packageInput.receipt, manifest, {
            expectedVariant,
            expectedPackageDigest: packageInput.packageDigest,
            expectedImplementation,
        });
        if (!receiptResult.valid) {
            throw errorWithCode(
                receiptResult.reasonCode || 'EXTENSION_RECEIPT_INVALID',
                'Official package receipt verification failed',
                receiptResult,
            );
        }
        if (
            containsExecutableCode &&
            (runtime !== 'node' || manifest.kind !== 'trusted-official')
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_EXECUTION_PAYLOAD_FORBIDDEN',
                'Executable extension payloads are only accepted for trusted official Node packages',
            );
        }
        return {
            manifest,
            packageInput,
            receipt: packageInput.receipt,
            variant,
            compatibility,
            expectedImplementation,
            verification: envelopeResult,
            verificationMode: verificationMode(envelopeResult),
        };
    }

    install(extensionId, input = {}) {
        const canonicalId = this.resolveId(extensionId);
        this._assertCatalogReady();
        const currentState = this.readState();
        const currentRevision = currentState.revision;
        if (
            input.expectedRevision !== undefined &&
            Number(input.expectedRevision) !== Number(currentRevision)
        ) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state changed; reload before retrying',
                {
                    expectedRevision: Number(input.expectedRevision),
                    currentRevision,
                },
            );
        }
        const existingTask = this._findIdempotentTask(
            currentState,
            canonicalId,
            'install',
            input.idempotencyKey,
        );
        if (existingTask) {
            return this._taskResult(
                existingTask,
                currentState.installed[canonicalId],
            );
        }
        const verified = this._verifyLocalPackage(canonicalId, input);
        const stagedPackage = this.packageStore
            ? this.packageStore.stage(verified.packageInput)
            : null;
        const previous = currentState.installed[canonicalId];
        const shouldReactivatePrevious = previous?.enabled === true;
        if (shouldReactivatePrevious) this._deactivateRecord(previous);
        let result;
        try {
            this._commit(
                (state) => {
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action: 'install',
                        idempotencyKey: input.idempotencyKey,
                    });
                    if (task.status === 'succeeded') {
                        result = {
                            taskId: task.id,
                            ...clone(task.result || {}),
                            record: publicRecord(state.installed[canonicalId]),
                        };
                        return state;
                    }
                    const previousRecord = state.installed[canonicalId];
                    const record = {
                        extensionId: canonicalId,
                        version: verified.manifest.version,
                        kind: verified.manifest.kind,
                        manifestDigest: verified.receipt.manifestDigest,
                        packageDigest: verified.receipt.packageDigest,
                        receiptDigest: verified.receipt.receiptDigest || null,
                        payloadDigest: verified.verification.digest,
                        fileDigests: clone(
                            verified.packageInput.payload.fileDigests || {},
                        ),
                        selectedVariant: verified.receipt.selectedVariant,
                        implementation: clone(
                            verified.receipt.implementation || {},
                        ),
                        verificationMode: verified.verificationMode,
                        compatibility: clone(verified.compatibility),
                        adoption: clone(input.adoption),
                        adoptionStatus: input.adoption ? 'pending' : undefined,
                        packageDirectory: stagedPackage?.directory || null,
                        entrypoint: stagedPackage?.entrypoint || null,
                        installationStatus: 'installed',
                        dataStatus: 'active',
                        retainedReason: undefined,
                        enabled: false,
                        codeStatus: this.env.isNode
                            ? 'verified-package-installed'
                            : 'embedded-inactive',
                        compatibilityStatus: 'compatible',
                        installedAt: previousRecord?.installedAt || now(),
                        updatedAt: now(),
                        source: input.source || 'official-local',
                    };
                    state.installed[canonicalId] = record;
                    state.dataGeneration += 1;
                    this._finishTask(state, task, {
                        extensionId: canonicalId,
                        status: 'installed-disabled',
                        selectedVariant: record.selectedVariant,
                        packageDigest: record.packageDigest,
                    });
                    this._recordAudit(state, {
                        action: 'install',
                        extensionId: canonicalId,
                        packageDigest: record.packageDigest,
                        manifestDigest: record.manifestDigest,
                        result: 'installed-disabled',
                    });
                    result = {
                        taskId: task.id,
                        status: 'installed-disabled',
                        record: publicRecord(record),
                    };
                    return state;
                },
                { expectedRevision: input.expectedRevision },
            );
        } catch (error) {
            if (shouldReactivatePrevious) {
                try {
                    this._activateRecord(previous);
                } catch (rollbackError) {
                    error.rollbackError = rollbackError;
                }
            }
            throw error;
        }
        const completedTask = this.getTask(result.taskId);
        if (completedTask) result.task = clone(completedTask);
        return result;
    }

    setEnabled(extensionId, enabled, input = {}) {
        const canonicalId = this.resolveId(extensionId);
        const currentState = this.readState();
        if (
            input.expectedRevision !== undefined &&
            Number(input.expectedRevision) !== Number(currentState.revision)
        ) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state changed; reload before retrying',
                {
                    expectedRevision: Number(input.expectedRevision),
                    currentRevision: currentState.revision,
                },
            );
        }
        const before = currentState.installed[canonicalId];
        if (!before || before.installationStatus !== 'installed') {
            throw errorWithCode(
                'EXTENSION_NOT_INSTALLED',
                `Extension ${canonicalId} is not installed`,
            );
        }
        if (enabled && before.compatibilityStatus !== 'compatible') {
            throw errorWithCode(
                before.reasonCode || 'EXTENSION_INCOMPATIBLE',
                `Extension ${canonicalId} is incompatible with this runtime`,
            );
        }
        const action = enabled ? 'enable' : 'disable';
        const existingTask = this._findIdempotentTask(
            currentState,
            canonicalId,
            action,
            input.idempotencyKey,
        );
        if (existingTask) return this._taskResult(existingTask, before);
        if (before.enabled === enabled) {
            let noOpResult;
            this._commit(
                (state) => {
                    const record = state.installed[canonicalId];
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action,
                        idempotencyKey: input.idempotencyKey,
                    });
                    const status = enabled ? 'enabled' : 'disabled';
                    this._finishTask(state, task, {
                        extensionId: canonicalId,
                        status,
                        noOp: true,
                    });
                    this._recordAudit(state, {
                        action,
                        extensionId: canonicalId,
                        result: `${status}-no-op`,
                    });
                    noOpResult = {
                        taskId: task.id,
                        status,
                        noOp: true,
                        record: publicRecord(record),
                    };
                    return state;
                },
                { expectedRevision: input.expectedRevision },
            );
            const completedTask = this.getTask(noOpResult.taskId);
            if (completedTask) noOpResult.task = clone(completedTask);
            return noOpResult;
        }
        let result;
        try {
            if (enabled) this._activateRecord(before);
            else this._deactivateRecord(before);
            this._commit(
                (state) => {
                    const record = state.installed[canonicalId];
                    if (!record || record.installationStatus !== 'installed') {
                        throw errorWithCode(
                            'EXTENSION_NOT_INSTALLED',
                            `Extension ${canonicalId} is not installed`,
                        );
                    }
                    if (
                        enabled &&
                        record.compatibilityStatus !== 'compatible'
                    ) {
                        throw errorWithCode(
                            record.reasonCode || 'EXTENSION_INCOMPATIBLE',
                            `Extension ${canonicalId} is incompatible with this runtime`,
                        );
                    }
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action,
                        idempotencyKey: input.idempotencyKey,
                    });
                    if (task.status === 'succeeded') {
                        result = {
                            taskId: task.id,
                            ...clone(task.result || {}),
                            record: publicRecord(record),
                        };
                        return state;
                    }
                    record.enabled = enabled;
                    record.updatedAt = now();
                    record.codeStatus = enabled
                        ? this.env.isNode
                            ? 'verified-package-active'
                            : 'embedded-active'
                        : this.env.isNode
                        ? 'verified-package-inactive'
                        : 'embedded-inactive';
                    this._finishTask(state, task, {
                        extensionId: canonicalId,
                        status: enabled ? 'enabled' : 'disabled',
                    });
                    this._recordAudit(state, {
                        action,
                        extensionId: canonicalId,
                        result: enabled ? 'enabled' : 'disabled',
                    });
                    result = {
                        taskId: task.id,
                        status: enabled ? 'enabled' : 'disabled',
                        record: publicRecord(record),
                    };
                    return state;
                },
                { expectedRevision: input.expectedRevision },
            );
        } catch (error) {
            try {
                if (enabled) this._deactivateRecord(before);
                else this._activateRecord(before);
            } catch (rollbackError) {
                error.rollbackError = rollbackError;
            }
            throw error;
        }
        const completedTask = this.getTask(result.taskId);
        if (completedTask) result.task = clone(completedTask);
        return result;
    }

    enable(extensionId, input = {}) {
        return this.setEnabled(extensionId, true, input);
    }

    disable(extensionId, input = {}) {
        return this.setEnabled(extensionId, false, input);
    }

    uninstall(
        extensionId,
        { purgeData = false, expectedRevision, idempotencyKey } = {},
    ) {
        const canonicalId = this.resolveId(extensionId);
        const currentState = this.readState();
        if (
            expectedRevision !== undefined &&
            Number(expectedRevision) !== Number(currentState.revision)
        ) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state changed; reload before retrying',
                {
                    expectedRevision: Number(expectedRevision),
                    currentRevision: currentState.revision,
                },
            );
        }
        if (purgeData) {
            return this.purgeData(canonicalId);
        }
        const existingTask = this._findIdempotentTask(
            currentState,
            canonicalId,
            'uninstall',
            idempotencyKey,
        );
        if (existingTask) {
            return this._taskResult(
                existingTask,
                currentState.installed[canonicalId],
            );
        }
        const before = currentState.installed[canonicalId];
        const cleanupRetry =
            before?.installationStatus === 'removed' &&
            before?.codeStatus === 'cleanup-pending';
        if (
            !before ||
            (before.installationStatus !== 'installed' && !cleanupRetry)
        ) {
            throw errorWithCode(
                'EXTENSION_NOT_INSTALLED',
                `Extension ${canonicalId} is not installed`,
            );
        }
        let deactivated = false;
        if (!cleanupRetry && before.enabled === true) {
            this._deactivateRecord(before);
            deactivated = true;
        } else {
            this.packageStore?.deactivate(canonicalId, before);
        }
        const requiresCodeCleanup = Boolean(
            this.packageStore && before.packageDirectory,
        );
        let taskId;
        let preparedState;
        try {
            preparedState = this._commit(
                (state) => {
                    const record = state.installed[canonicalId];
                    if (
                        !record ||
                        (record.installationStatus !== 'installed' &&
                            !(
                                record.installationStatus === 'removed' &&
                                record.codeStatus === 'cleanup-pending'
                            ))
                    ) {
                        throw errorWithCode(
                            'EXTENSION_NOT_INSTALLED',
                            `Extension ${canonicalId} is not installed`,
                        );
                    }
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action: 'uninstall',
                        idempotencyKey,
                    });
                    taskId = task.id;
                    record.enabled = false;
                    record.installationStatus = 'removed';
                    record.dataStatus = 'retained';
                    record.retainedReason = 'user-uninstalled';
                    record.codeStatus = requiresCodeCleanup
                        ? 'cleanup-pending'
                        : this.env.isNode
                        ? 'removed'
                        : 'embedded-inactive';
                    delete record.cleanupError;
                    record.updatedAt = now();
                    if (!requiresCodeCleanup) {
                        this._finishTask(state, task, {
                            extensionId: canonicalId,
                            status: 'reinstall-required',
                            dataStatus: 'retained',
                            codeStatus: record.codeStatus,
                        });
                        this._recordAudit(state, {
                            action: 'uninstall',
                            extensionId: canonicalId,
                            result: 'removed-code-retained-data',
                        });
                    }
                    return state;
                },
                { expectedRevision },
            );
        } catch (error) {
            if (deactivated) {
                try {
                    this._activateRecord(before);
                } catch (rollbackError) {
                    error.rollbackError = rollbackError;
                }
            }
            throw error;
        }
        if (!requiresCodeCleanup) {
            const record = preparedState.installed[canonicalId];
            return this._taskResult(this.getTask(taskId), record);
        }
        try {
            this.packageStore.remove(before);
        } catch (cleanupError) {
            let stateCommitError = null;
            try {
                this._commit(
                    (state) => {
                        const record = state.installed[canonicalId];
                        const task = state.tasks.find(
                            (candidate) => candidate.id === taskId,
                        );
                        if (record) {
                            record.codeStatus = 'cleanup-pending';
                            record.cleanupError = {
                                code:
                                    cleanupError.code ||
                                    'EXTENSION_PACKAGE_CLEANUP_FAILED',
                                message: cleanupError.message,
                            };
                            record.updatedAt = now();
                        }
                        if (task) {
                            this._finishTask(
                                state,
                                task,
                                {
                                    extensionId: canonicalId,
                                    status: 'cleanup-pending',
                                    dataStatus: 'retained',
                                },
                                cleanupError,
                            );
                        }
                        this._recordAudit(state, {
                            action: 'uninstall',
                            extensionId: canonicalId,
                            result: 'cleanup-pending',
                            reasonCode:
                                cleanupError.code ||
                                'EXTENSION_PACKAGE_CLEANUP_FAILED',
                        });
                        return state;
                    },
                    { expectedRevision: preparedState.revision },
                );
            } catch (commitError) {
                stateCommitError = commitError;
            }
            const error = errorWithCode(
                'EXTENSION_PACKAGE_CLEANUP_FAILED',
                'Extension code cleanup failed; data remains retained and cleanup can be retried',
                {
                    extensionId: canonicalId,
                    taskId,
                    cleanupError: {
                        code:
                            cleanupError.code ||
                            'EXTENSION_PACKAGE_CLEANUP_FAILED',
                        message: cleanupError.message,
                    },
                    stateCommitError: stateCommitError
                        ? {
                              code: stateCommitError.code,
                              message: stateCommitError.message,
                          }
                        : null,
                },
            );
            error.statusCode = 500;
            throw error;
        }
        const completedState = this._commit(
            (state) => {
                const record = state.installed[canonicalId];
                const task = state.tasks.find(
                    (candidate) => candidate.id === taskId,
                );
                if (!record || !task) {
                    throw errorWithCode(
                        'EXTENSION_CONSISTENCY_CONFLICT',
                        'Extension cleanup task state is unavailable',
                        { extensionId: canonicalId, taskId },
                    );
                }
                record.codeStatus = 'removed';
                delete record.packageDirectory;
                delete record.entrypoint;
                delete record.payloadDigest;
                delete record.fileDigests;
                delete record.cleanupError;
                record.updatedAt = now();
                this._finishTask(state, task, {
                    extensionId: canonicalId,
                    status: 'reinstall-required',
                    dataStatus: 'retained',
                    codeStatus: 'removed',
                });
                this._recordAudit(state, {
                    action: 'uninstall',
                    extensionId: canonicalId,
                    result: 'removed-code-retained-data',
                });
                return state;
            },
            { expectedRevision: preparedState.revision },
        );
        return this._taskResult(
            completedState.tasks.find((task) => task.id === taskId),
            completedState.installed[canonicalId],
        );
    }

    update(extensionId) {
        const error = errorWithCode(
            'EXTENSION_UPDATE_UNSUPPORTED',
            'Extension update is not implemented by this Host version',
            { extensionId: this.resolveId(extensionId) },
        );
        error.statusCode = 501;
        throw error;
    }

    rollback(extensionId) {
        const error = errorWithCode(
            'EXTENSION_ROLLBACK_UNSUPPORTED',
            'Extension rollback is not implemented by this Host version',
            { extensionId: this.resolveId(extensionId) },
        );
        error.statusCode = 501;
        throw error;
    }

    purgeData(extensionId) {
        const error = errorWithCode(
            'EXTENSION_DATA_PURGE_UNSUPPORTED',
            'Extension data purge is unavailable until reference cleanup is transactional',
            {
                extensionId: this.resolveId(extensionId),
                retained: true,
            },
        );
        error.statusCode = 501;
        throw error;
    }

    guard(extensionId, { expectedRevision, allowDisabled = false } = {}) {
        const canonicalId = this.resolveId(extensionId);
        const availability = this.getAvailability(canonicalId);
        if (expectedRevision !== undefined) {
            const currentRevision = this.readState().revision;
            if (Number(expectedRevision) !== Number(currentRevision)) {
                throw errorWithCode(
                    'EXTENSION_REVISION_MISMATCH',
                    'Extension runtime revision is stale',
                    {
                        currentBackendRevision: currentRevision,
                        expectedRevision: Number(expectedRevision),
                    },
                );
            }
        }
        if (availability.status === 'enabled' || allowDisabled) {
            return {
                ...availability,
                extensionId: canonicalId,
                adapter: this.adapters.get(canonicalId) || null,
            };
        }
        const error = errorWithCode(
            availability.reasonCode || 'EXTENSION_UNAVAILABLE',
            `Extension ${canonicalId} is ${availability.status}`,
            availability,
        );
        error.statusCode = 409;
        throw error;
    }

    async invoke(extensionId, handler, options = {}) {
        const gate = this.guard(extensionId, options);
        if (typeof handler !== 'function') return gate;
        return handler(gate.adapter, gate);
    }

    getFeatureFlags() {
        const flags = {};
        for (const entry of this.bundledCatalog) {
            const manifest = entry.manifest || entry;
            const record = this.getRecord(manifest.id);
            if (record?.enabled) {
                for (const feature of manifest.contributes?.features || []) {
                    flags[feature] = true;
                    if (manifest.id === EXTENSION_IDS.configGenerator) {
                        flags.configGenerator = true;
                    }
                }
            }
        }
        return flags;
    }
}

let defaultManager;

export function getExtensionManager(options = {}) {
    if (!defaultManager || options.reset) {
        defaultManager = new ExtensionManager(options);
    }
    return defaultManager;
}

export function resetExtensionManagerForTests() {
    defaultManager = null;
}

export default ExtensionManager;

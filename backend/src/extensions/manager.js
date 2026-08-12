import $ from '@/core/app';
import {
    ARTIFACTS_KEY,
    EXTENSION_RECORD_KEY_PREFIX,
    EXTENSION_STATE_INDEX_KEY,
    EXTENSIONS_KEY,
    LEGACY_EXTENSIONS_KEY,
} from '@/constants';
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
    createDigestReceipt,
    diagnosticDigest,
    extensionPackageDigest,
    isSha256Digest,
    sha256Hex,
    verifyReceipt,
    verifySignedEnvelope,
} from './signature';
import { createNodeExtensionPackageStore } from './package-store';
import {
    extensionSourceId,
    fetchExtensionSourceDocument,
    isCommunityContentPackage,
    normalizeCommunityCatalog,
    normalizeExtensionSourceUrl,
    publicExtensionSource,
    sourceEntryPackageDigest,
    sourceEntryPackageUrl,
    SOURCE_EXECUTABLE_DISTRIBUTION,
} from './sources';
import { version as packageVersion } from '../../package.json';
import { compare as compareSemver, valid as validSemver } from 'semver';

const STATE_SCHEMA_VERSION = 1;
const MAX_TASKS = 100;
const MAX_PACKAGE_FILES = 128;
const MAX_PACKAGE_FILE_BYTES = 2 * 1024 * 1024;
const MAX_PACKAGE_BYTES = 8 * 1024 * 1024;
const MAX_ROLLBACK_VERSIONS = 3;
const RESERVED_PACKAGE_FILES = new Set([
    'manifest.json',
    'receipt.json',
    'package.json',
    'active.json',
]);
const LEGACY_CONFIG_HOSTING_ADOPTION = 'config-hosting-legacy-artifacts-v1';
const LOCAL_EXECUTABLE_DISTRIBUTION = 'local-executable';
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

function isSourceDistribution(distribution) {
    return (
        distribution === 'community' ||
        distribution === SOURCE_EXECUTABLE_DISTRIBUTION
    );
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
    if (env.isNode) return 'open';
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

function compareVersions(left, right) {
    const a = validSemver(`${left || ''}`);
    const b = validSemver(`${right || ''}`);
    return a && b ? compareSemver(a, b) : null;
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

function assertVerifiedPackageFiles(files, fileDigests) {
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
        sources: {},
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
        sources:
            state.sources && typeof state.sources === 'object'
                ? state.sources
                : {},
        migrations:
            state.migrations && typeof state.migrations === 'object'
                ? state.migrations
                : {},
        tasks: Array.isArray(state.tasks) ? state.tasks : [],
        audit: Array.isArray(state.audit) ? state.audit : [],
    };
}

function extensionRecordKey(extensionId) {
    return `${EXTENSION_RECORD_KEY_PREFIX}${extensionId}`;
}

function parseExtensionRecord(value) {
    const parsed = parseStoredState(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed
        : null;
}

function stateIndexParts(value) {
    const parsed = parseStoredState(value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return {
            state: createEmptyState(),
            extensionIds: [],
            exists: false,
        };
    }
    const { extensionIds, ...metadata } = parsed;
    delete metadata.installed;
    return {
        state: normalizeState({ ...metadata, installed: {} }),
        extensionIds: Array.isArray(extensionIds)
            ? extensionIds.filter(
                  (extensionId) =>
                      typeof extensionId === 'string' && extensionId,
              )
            : [],
        exists: true,
    };
}

function stateIndexFromState(state) {
    const normalized = normalizeState(state);
    const { installed, ...metadata } = normalized;
    return {
        ...metadata,
        extensionIds: Object.keys(installed).sort(),
    };
}

function extensionIdsFromSources(sources = {}) {
    const ids = [];
    for (const source of Object.values(sources || {})) {
        for (const entry of source?.entries || []) {
            if (typeof entry?.id === 'string' && entry.id) ids.push(entry.id);
        }
    }
    return ids;
}

function sourceCanReplaceRemovedInstallation(record) {
    return Boolean(
        record &&
            record.installationStatus === 'removed' &&
            record.codeStatus === 'removed' &&
            record.enabled !== true,
    );
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

function isVerifiedRollbackSnapshot(record) {
    return Boolean(
        record?.packageDigest && record?.packageDirectory && record?.entrypoint,
    );
}

function verifiedRollbackHistory(record) {
    return (
        Array.isArray(record?.rollbackHistory) ? record.rollbackHistory : []
    ).filter(isVerifiedRollbackSnapshot);
}

function publicRecord(record) {
    if (!record) return null;
    const result = clone(record);
    delete result.packageDirectory;
    delete result.entrypoint;
    result.rollbackHistory = verifiedRollbackHistory(result).map((snapshot) => {
        const publicSnapshot = clone(snapshot);
        delete publicSnapshot.packageDirectory;
        delete publicSnapshot.entrypoint;
        return publicSnapshot;
    });
    result.rollbackVersions = result.rollbackHistory.map(
        (snapshot) => snapshot.version,
    );
    result.rollbackAvailable = result.rollbackHistory.length > 0;
    return result;
}

function rollbackSnapshot(record) {
    if (!record) return null;
    const snapshot = clone(record);
    delete snapshot.rollbackHistory;
    delete snapshot.rollbackVersions;
    delete snapshot.rollbackAvailable;
    delete snapshot.lifecycleStatus;
    delete snapshot.taskId;
    delete snapshot.cleanupError;
    return snapshot;
}

function appendRollbackSnapshot(history, record) {
    const snapshot = rollbackSnapshot(record);
    const next = verifiedRollbackHistory({
        rollbackHistory: Array.isArray(history) ? clone(history) : [],
    });
    if (!isVerifiedRollbackSnapshot(snapshot)) {
        return next.slice(-MAX_ROLLBACK_VERSIONS);
    }
    const withoutDuplicate = next.filter(
        (candidate) => candidate.packageDigest !== snapshot.packageDigest,
    );
    return [...withoutDuplicate, snapshot].slice(-MAX_ROLLBACK_VERSIONS);
}

function packageVersionIdentity(record) {
    if (
        !record?.extensionId ||
        !record?.version ||
        !record?.packageDigest ||
        !record?.packageDirectory
    ) {
        return null;
    }
    return [
        record.extensionId,
        record.version,
        record.packageDigest,
        record.packageDirectory,
    ].join('\u0000');
}

function cleanupObsoleteVersionPackages(
    packageStore,
    previousRecord,
    currentRecord,
) {
    if (!packageStore?.removeVersion || !previousRecord || !currentRecord) {
        return null;
    }
    const retained = new Set(
        [currentRecord, ...(currentRecord.rollbackHistory || [])]
            .map(packageVersionIdentity)
            .filter(Boolean),
    );
    const seen = new Set();
    const failures = [];
    for (const candidate of [
        ...(previousRecord.rollbackHistory || []),
        previousRecord,
    ]) {
        const identity = packageVersionIdentity(candidate);
        if (!identity || retained.has(identity) || seen.has(identity)) continue;
        seen.add(identity);
        try {
            packageStore.removeVersion(candidate);
        } catch (error) {
            failures.push({
                version: candidate.version,
                packageDigest: candidate.packageDigest,
                code: error.code || 'EXTENSION_PACKAGE_CLEANUP_FAILED',
                message: error.message,
            });
        }
    }
    if (failures.length === 0) return null;
    return {
        code: 'EXTENSION_PACKAGE_CLEANUP_FAILED',
        message: `Failed to clean ${failures.length} obsolete extension package version(s)`,
        failures,
    };
}

function catalogManifest(entry) {
    return entry ? normalizeExtensionManifest(entry.manifest || entry) : null;
}

function receiptImplementationLanes(manifest) {
    const embedded = embeddedExtensionImplementations[manifest.id]?.lanes;
    if (embedded) return embedded;
    return Object.fromEntries(
        Object.entries(manifest.scriptExecutionLanes || {}).map(
            ([laneId, lane]) => [
                laneId,
                {
                    product: lane.product,
                    implementationId: lane.implementationId,
                },
            ],
        ),
    );
}

function preferCatalogEntry(current, candidate) {
    if (!current) return candidate;
    if (!candidate) return current;
    const currentManifest = catalogManifest(current);
    const candidateManifest = catalogManifest(candidate);
    const comparison = compareVersions(
        candidateManifest?.version,
        currentManifest?.version,
    );
    if (comparison === 1) return candidate;
    if (comparison === -1) return current;
    if (candidate.sourceId) return candidate;
    return current;
}

function catalogReleaseEntries(entry, { includeNonInstallable = false } = {}) {
    if (!entry) return [];
    const manifest = entry.manifest || entry;
    const releases =
        Array.isArray(entry.releases) && entry.releases.length
            ? entry.releases
            : [entry];
    const byVersion = new Map();
    for (const candidate of releases) {
        const candidateManifest = candidate?.manifest || candidate;
        if (
            candidateManifest?.id !== manifest?.id ||
            !candidateManifest?.version ||
            (!includeNonInstallable && candidate.installable === false)
        ) {
            continue;
        }
        byVersion.set(candidateManifest.version, candidate);
    }
    if (!byVersion.has(manifest?.version))
        byVersion.set(manifest.version, entry);
    return [...byVersion.values()];
}

function catalogRelease(entry, version, options) {
    if (!version) return entry;
    return (
        catalogReleaseEntries(entry, options).find(
            (candidate) =>
                (candidate.manifest || candidate).version === version,
        ) || null
    );
}

function sourceVersionEntries(entries) {
    return (entries || []).flatMap((entry) =>
        catalogReleaseEntries(entry, { includeNonInstallable: true }),
    );
}

function assertImmutableSourceVersions(previousEntries, nextEntries) {
    const previousByVersion = new Map(
        sourceVersionEntries(previousEntries).map((entry) => [
            catalogEntryKey(entry.id, entry.version),
            entry,
        ]),
    );
    for (const nextEntry of sourceVersionEntries(nextEntries)) {
        const previousEntry = previousByVersion.get(
            catalogEntryKey(nextEntry.id, nextEntry.version),
        );
        if (!previousEntry) continue;
        const previousManifestDigest =
            previousEntry.manifestDigest ||
            sha256Hex(
                canonicalJson(
                    normalizeExtensionManifest(
                        previousEntry.manifest || previousEntry,
                    ),
                ),
            );
        const nextManifestDigest =
            nextEntry.manifestDigest ||
            sha256Hex(
                canonicalJson(
                    normalizeExtensionManifest(nextEntry.manifest || nextEntry),
                ),
            );
        const immutableProjection = (entry, manifestDigest) => ({
            manifestDigest,
            distribution: entry.distribution || null,
            selectedVariant: entry.selectedVariant || null,
            installable: entry.installable !== false,
            packageUrls: entry.packageUrls || {},
            packageDigests: entry.packageDigests || {},
        });
        const previousProjection = immutableProjection(
            previousEntry,
            previousManifestDigest,
        );
        const nextProjection = immutableProjection(
            nextEntry,
            nextManifestDigest,
        );
        if (
            canonicalJson(previousProjection) !== canonicalJson(nextProjection)
        ) {
            throw errorWithCode(
                'EXTENSION_SOURCE_VERSION_MUTATED',
                'An extension source changed immutable content for an existing version',
                {
                    extensionId: nextEntry.id,
                    version: nextEntry.version,
                    previousManifestDigest,
                    nextManifestDigest,
                    previousPackageDigests: clone(
                        previousEntry.packageDigests || {},
                    ),
                    nextPackageDigests: clone(nextEntry.packageDigests || {}),
                    previousImmutableProjection: clone(previousProjection),
                    nextImmutableProjection: clone(nextProjection),
                },
            );
        }
    }
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
        knownPermissions = KNOWN_EXTENSION_PERMISSIONS,
        packageStore,
        sourceFetcher,
    } = {}) {
        this.store = store;
        this.env = env || {};
        this.runtime = runtimeName(this.env);
        this.backendVersion = backendVersion;
        this.hostCapabilities = clone(hostCapabilities || {});
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
        this.hostBindings = {};
        // Runtime entrypoints are verified once during activation and retained
        // only for the lifetime of this Host process. Deactivation must never
        // reload executable code from disk: the package may have been removed
        // or tampered with after it became active.
        this.activeRuntimeModules = new Map();
        // This in-memory gate is the last fail-closed boundary when lifecycle
        // persistence or package cleanup fails after deactivation has started.
        this.runtimeGateBlocks = new Map();
        this.persistDefaults = persistDefaults;
        this.packageStore =
            packageStore === undefined && this.env.isNode && this.store === $
                ? createNodeExtensionPackageStore({
                      verificationOptions: this.verificationOptions,
                  })
                : packageStore || null;
        // Tests and embedders may provide a bounded fetch implementation. The
        // production Node path uses the guarded fetcher from sources.js.
        this.sourceFetcher = sourceFetcher || null;
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

    unregisterAdapter(extensionId, adapter) {
        const canonicalId = this.resolveId(extensionId);
        const current = this.adapters.get(canonicalId);
        if (adapter && current !== adapter) return false;
        return this.adapters.delete(canonicalId);
    }

    setHostBindings(bindings = {}) {
        this.hostBindings = { ...this.hostBindings, ...bindings };
        return this.hostBindings;
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

    findEntry(extensionId, { version } = {}) {
        const canonicalId = this.resolveId(extensionId);
        const state = this.readState();
        const builtInEntries = [
            ...this.bundledCatalog,
            ...this.officialCatalog,
            findCatalogEntry(canonicalId),
        ].filter(
            (entry) =>
                entry &&
                (entry.id === canonicalId ||
                    entry.manifest?.id === canonicalId),
        );
        const sourceEntries = Object.values(state.sources || {}).flatMap(
            (source) =>
                (source.entries || [])
                    .filter((candidate) => candidate.id === canonicalId)
                    .map((candidate) => catalogRelease(candidate, version))
                    .filter(Boolean),
        );
        const versionedBuiltInEntries = version
            ? builtInEntries
                  .map((candidate) => catalogRelease(candidate, version))
                  .filter(Boolean)
            : builtInEntries;
        const selected = [...builtInEntries, ...sourceEntries].reduce(
            preferCatalogEntry,
            null,
        );
        const versionedSelected = [
            ...versionedBuiltInEntries,
            ...sourceEntries,
        ].reduce(preferCatalogEntry, null);
        if (version) return versionedSelected ? clone(versionedSelected) : null;
        if (selected) return clone(selected);
        const retained = state.installed?.[canonicalId];
        if (
            !retained?.manifestSnapshot ||
            retained.source === 'legacy-adoption'
        ) {
            return null;
        }
        const retainedDistribution = retained.distribution || 'community';
        return {
            id: canonicalId,
            manifest: clone(retained.manifestSnapshot),
            distribution: retainedDistribution,
            source: retained.sourceUrl || null,
            sourceId: retained.sourceId || null,
            sourceName: retained.sourceName || null,
            sourceMissing: Boolean(
                retained.sourceId && !state.sources?.[retained.sourceId],
            ),
            packageUrls: clone(retained.packageUrls || {}),
            packageDigests: clone(retained.packageDigests || {}),
        };
    }

    resolveId(extensionId) {
        if (extensionId === 'config-hosting')
            return EXTENSION_IDS.configHosting;
        return extensionId;
    }

    getManifest(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        const installed = this.readState().installed?.[canonicalId];
        if (
            installed?.installationStatus === 'installed' &&
            installed.manifestSnapshot
        ) {
            return normalizeExtensionManifest(installed.manifestSnapshot);
        }
        const entry = this.findEntry(canonicalId);
        return entry
            ? normalizeExtensionManifest(entry.manifest || entry)
            : null;
    }

    readState() {
        const index = stateIndexParts(
            this.store.read(EXTENSION_STATE_INDEX_KEY),
        );
        const legacyValue = this.store.read(LEGACY_EXTENSIONS_KEY);
        const legacyParsed = parseStoredState(legacyValue);
        const legacyState = legacyParsed ? normalizeState(legacyParsed) : null;
        const useLegacyMetadata =
            legacyState &&
            (!index.exists || legacyState.revision > index.state.revision);
        const state = normalizeState(
            useLegacyMetadata ? legacyState : index.state,
        );
        state.installed = {};

        const knownExtensionIds = new Set([
            ...index.extensionIds,
            ...Object.keys(legacyState?.installed || {}),
            ...extensionIdsFromSources(state.sources),
            ...this.bundledCatalog.map((entry) => (entry.manifest || entry).id),
            ...this.officialCatalog.map(
                (entry) => (entry.manifest || entry).id,
            ),
        ]);
        for (const extensionId of knownExtensionIds) {
            const storedRecord = parseExtensionRecord(
                this.store.read(extensionRecordKey(extensionId)),
            );
            const legacyRecord = legacyState?.installed?.[extensionId];
            if (storedRecord || legacyRecord) {
                state.installed[extensionId] = clone(
                    storedRecord || legacyRecord,
                );
            }
        }
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
        if (legacyState) this._migrateLegacyState(state);
        return state;
    }

    _deleteStoreKey(key) {
        if (typeof this.store.delete === 'function') {
            this.store.delete(key);
            return;
        }
        this.store.write(null, key);
    }

    _migrateLegacyState(state) {
        const normalized = normalizeState(state);
        for (const extensionId of Object.keys(normalized.installed).sort()) {
            this.store.write(
                JSON.stringify(normalized.installed[extensionId]),
                extensionRecordKey(extensionId),
            );
        }
        this.store.write(
            JSON.stringify(stateIndexFromState(normalized)),
            EXTENSION_STATE_INDEX_KEY,
        );
        this._deleteStoreKey(LEGACY_EXTENSIONS_KEY);
    }

    persistState(state, { previousState } = {}) {
        const normalized = normalizeState(state);
        const previous = previousState
            ? normalizeState(previousState)
            : createEmptyState();
        const nextIds = Object.keys(normalized.installed).sort();
        const previousIds = new Set(Object.keys(previous.installed));

        for (const extensionId of nextIds) {
            const nextRecord = normalized.installed[extensionId];
            const previousRecord = previous.installed[extensionId];
            const recordMissing =
                this.store.read(extensionRecordKey(extensionId)) === undefined;
            if (
                recordMissing ||
                canonicalJson(previousRecord) !== canonicalJson(nextRecord)
            ) {
                this.store.write(
                    JSON.stringify(nextRecord),
                    extensionRecordKey(extensionId),
                );
            }
            previousIds.delete(extensionId);
        }

        this.store.write(
            JSON.stringify(stateIndexFromState(normalized)),
            EXTENSION_STATE_INDEX_KEY,
        );
        for (const removedExtensionId of previousIds) {
            this._deleteStoreKey(extensionRecordKey(removedExtensionId));
        }
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
        this.persistState(next, { previousState: current });
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
        return this._runtimeAvailability(
            this.readState().installed[canonicalId],
            canonicalId,
        );
    }

    _runtimeAvailability(record, extensionId) {
        const availability = extensionAvailability(record, extensionId);
        const gateBlock = this.runtimeGateBlocks.get(extensionId);
        if (!gateBlock || availability.status !== 'enabled') {
            return availability;
        }
        return {
            status: 'disabled',
            extensionId,
            reasonCode: gateBlock.reasonCode || 'EXTENSION_DISABLED',
            failClosed: true,
        };
    }

    getRecord(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        return this.readState().installed[canonicalId] || null;
    }

    getHealth(extensionId) {
        const canonicalId = this.resolveId(extensionId);
        const availability = this.getAvailability(canonicalId);
        const record = this.getRecord(canonicalId);
        let implementation = null;
        let implementationError = null;
        let packageIntegrity = null;
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
        if (record?.entrypoint && this.packageStore) {
            try {
                const verified =
                    this.packageStore.verifyInstalledRecord(record);
                packageIntegrity = {
                    status: 'verified',
                    packageDigest: verified.packageMetadata.packageDigest,
                    fileCount: Object.keys(
                        verified.packageMetadata.fileDigests || {},
                    ).length,
                };
            } catch (error) {
                packageIntegrity = {
                    status: 'failed',
                    code:
                        error.code ||
                        'EXTENSION_PACKAGE_INTEGRITY_CHECK_FAILED',
                    message: error.message,
                };
            }
        }
        const activeMismatch =
            availability.status === 'enabled' &&
            implementation &&
            implementation.active === false;
        const packageIntegrityFailed = packageIntegrity?.status === 'failed';
        return {
            extensionId: canonicalId,
            status:
                availability.status === 'enabled' &&
                !implementationError &&
                !activeMismatch &&
                !packageIntegrityFailed
                    ? 'healthy'
                    : implementationError ||
                      activeMismatch ||
                      packageIntegrityFailed
                    ? 'unhealthy'
                    : availability.status,
            availability,
            implementation,
            packageIntegrity,
            error: implementationError,
        };
    }

    getPackageAsset(extensionId, relativePath) {
        const canonicalId = this.resolveId(extensionId);
        this.guard(canonicalId);
        const record = this.getRecord(canonicalId);
        if (!record?.entrypoint || !this.packageStore) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_ASSET_UNAVAILABLE',
                `Extension ${canonicalId} has no installed package assets`,
                { extensionId: canonicalId },
            );
        }
        const manifest = this.getManifest(canonicalId);
        const frontend = manifest?.frontend || {};
        const declaredAssets = new Set(
            [
                frontend.entrypoint,
                frontend.style,
                ...Object.values(frontend.locales || {}),
                ...Object.values(frontend.assets || {}).map((asset) =>
                    typeof asset === 'string' ? asset : asset?.path,
                ),
            ].filter(Boolean),
        );
        if (!declaredAssets.has(relativePath)) {
            const error = errorWithCode(
                'EXTENSION_PACKAGE_ASSET_NOT_DECLARED',
                `Extension asset ${relativePath} is not declared by its manifest`,
                { extensionId: canonicalId, path: relativePath },
            );
            error.statusCode = 404;
            throw error;
        }
        return this.packageStore.readVerifiedFile(record, relativePath);
    }

    _catalogEntries(state = this.readState()) {
        const result = [];
        const seen = new Set();
        const append = (entry) => {
            const manifest = entry?.manifest || entry;
            if (!manifest?.id) return;
            const key = catalogEntryKey(manifest.id, manifest.version);
            if (seen.has(key)) return;
            seen.add(key);
            result.push({ ...clone(entry), manifest: clone(manifest) });
        };
        [...this.bundledCatalog, ...this.officialCatalog].forEach(append);
        Object.values(state.sources || {}).forEach((source) =>
            (source.entries || []).forEach(append),
        );
        // A source can disappear after an installation. Keep the immutable
        // manifest/package projection attached to the receipt so the user can
        // still inspect, disable and uninstall the retained extension.
        Object.values(state.installed || {}).forEach((record) => {
            if (
                !record?.manifestSnapshot ||
                record.source === 'legacy-adoption'
            ) {
                return;
            }
            append({
                id: record.extensionId,
                manifest: record.manifestSnapshot,
                distribution: record.distribution || 'community',
                source: record.sourceUrl || null,
                sourceId: record.sourceId || null,
                sourceName: record.sourceName || null,
                packageUrls: record.packageUrls || {},
                packageDigests: record.packageDigests || {},
                sourceMissing: Boolean(
                    record.sourceId && !state.sources?.[record.sourceId],
                ),
            });
        });
        return result;
    }

    _latestCatalogEntries(state = this.readState()) {
        const byId = new Map();
        for (const entry of this._catalogEntries(state)) {
            const manifest = entry?.manifest || entry;
            if (!manifest?.id) continue;
            byId.set(
                manifest.id,
                preferCatalogEntry(byId.get(manifest.id), entry),
            );
        }
        return [...byId.values()];
    }

    getRuntimeManifest() {
        const state = this.readState();
        const consistency = defaultConsistency(this.env);
        const currentManagementMode = managementMode(this.env);
        const restoreIsolation = defaultRestoreIsolation(this.env);
        const entries = this._latestCatalogEntries(state);
        const extensions = entries.map((entry) => {
            const availableManifest = normalizeExtensionManifest(
                entry.manifest || entry,
            );
            const record = state.installed[availableManifest.id];
            const manifest =
                record?.installationStatus === 'installed' &&
                record.manifestSnapshot
                    ? normalizeExtensionManifest(record.manifestSnapshot)
                    : availableManifest;
            const availability = this._runtimeAvailability(record, manifest.id);
            const versionComparison = record
                ? compareVersions(availableManifest.version, record.version)
                : null;
            return {
                id: manifest.id,
                version: manifest.version,
                availableVersion: availableManifest.version,
                updateAvailable:
                    record?.installationStatus === 'installed' &&
                    entry.sourceMissing !== true &&
                    versionComparison === 1,
                rollbackAvailable: verifiedRollbackHistory(record).length > 0,
                rollbackVersions: verifiedRollbackHistory(record).map(
                    (snapshot) => snapshot.version,
                ),
                name: manifest.name,
                kind: manifest.kind,
                distribution: entry.distribution || manifest.distribution,
                sourceId: entry.sourceId || null,
                sourceName: entry.sourceName || null,
                sourceMissing: entry.sourceMissing === true,
                manifest: clone(manifest),
                manifestDigest: record?.manifestDigest || null,
                status: availability.status,
                availability,
                enabled: availability.status === 'enabled',
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
        const state = this.readState();
        const entries = this._latestCatalogEntries(state).sort(
            (left, right) => {
                const leftManifest = catalogManifest(left);
                const rightManifest = catalogManifest(right);
                const idComparison = leftManifest.id.localeCompare(
                    rightManifest.id,
                );
                if (idComparison) return idComparison;
                return (
                    compareVersions(
                        leftManifest.version,
                        rightManifest.version,
                    ) || 0
                );
            },
        );
        const latestById = new Map(
            this._latestCatalogEntries(state).map((entry) => [
                catalogManifest(entry).id,
                entry,
            ]),
        );
        const projectedEntries = entries.map((entry) => {
            const manifest = normalizeExtensionManifest(
                entry.manifest || entry,
            );
            const record = state.installed[manifest.id];
            const catalogSource = entry.sourceId
                ? state.sources?.[entry.sourceId]
                : null;
            const manifestDigest = sha256Hex(canonicalJson(manifest));
            const authorization = this.catalogAuthorizations.get(
                catalogEntryKey(manifest.id, manifest.version),
            );
            const sourceAuthorized = Boolean(
                isSourceDistribution(entry.distribution) &&
                    (entry.sourceMissing === true ||
                        (entry.sourceId &&
                            catalogSource?.verified === true &&
                            entry.manifestDigest === manifestDigest)),
            );
            const catalogAuthorized = Boolean(
                sourceAuthorized ||
                    (authorization &&
                        manifestDigest &&
                        authorization.manifestDigest === manifestDigest),
            );
            const versionComparison = record
                ? compareVersions(manifest.version, record.version)
                : null;
            const latestEntry = latestById.get(manifest.id);
            const latestManifest = catalogManifest(latestEntry);
            const releases = catalogReleaseEntries(entry, {
                includeNonInstallable: true,
            })
                .sort(
                    (left, right) =>
                        compareVersions(
                            (right.manifest || right).version,
                            (left.manifest || left).version,
                        ) || 0,
                )
                .map((release) => {
                    const releaseManifest = normalizeExtensionManifest(
                        release.manifest || release,
                    );
                    return {
                        version: releaseManifest.version,
                        manifest: clone(releaseManifest),
                        distribution:
                            release.distribution ||
                            releaseManifest.distribution ||
                            'community',
                        selectedVariant: release.selectedVariant || null,
                        packageUrls: clone(release.packageUrls || {}),
                        packageDigests: clone(release.packageDigests || {}),
                        installable: release.installable !== false,
                        releasedAt: release.releasedAt || null,
                        gitTag: release.gitTag || null,
                        gitCommit: release.gitCommit || null,
                        latest:
                            releaseManifest.version === latestManifest?.version,
                    };
                });
            return {
                ...clone(manifest),
                id: manifest.id,
                manifest: clone(manifest),
                distribution:
                    entry.distribution || manifest.distribution || 'bundled',
                source: entry.source || catalogSource?.url || null,
                sourceUrl: entry.source || catalogSource?.url || null,
                sourceId: entry.sourceId || null,
                sourceName: entry.sourceName || catalogSource?.name || null,
                sourceMissing: entry.sourceMissing === true,
                defaultEnabled: entry.defaultEnabled === true,
                manifestDigest,
                packageUrls: clone(entry.packageUrls || {}),
                packageDigests: clone(
                    authorization?.packageDigests || entry.packageDigests || {},
                ),
                catalogAuthorized,
                installed: record?.installationStatus === 'installed',
                installedVersion: record?.version || null,
                availableVersion: latestManifest?.version || manifest.version,
                updateAvailable:
                    record?.installationStatus === 'installed' &&
                    entry.sourceMissing !== true &&
                    versionComparison === 1,
                rollbackAvailable: verifiedRollbackHistory(record).length > 0,
                rollbackVersions: verifiedRollbackHistory(record).map(
                    (snapshot) => snapshot.version,
                ),
                releases,
                latest:
                    latestManifest?.version === manifest.version &&
                    latestManifest?.id === manifest.id,
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
            sources: this.getSources(),
            entries: projectedEntries,
        };
    }

    getSources() {
        return Object.values(this.readState().sources || {}).map((source) =>
            publicExtensionSource(source),
        );
    }

    _findSource(sourceId) {
        return this.readState().sources?.[sourceId] || null;
    }

    _assertSourceRevision(expectedRevision) {
        if (expectedRevision === undefined || expectedRevision === null) return;
        const currentRevision = this.readState().revision;
        if (Number(expectedRevision) !== Number(currentRevision)) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state changed; reload before retrying',
                {
                    expectedRevision: Number(expectedRevision),
                    currentRevision,
                },
            );
        }
    }

    _assertCommunityIdAvailable(entries, sourceId) {
        const state = this.readState();
        const builtInIds = new Set(
            [...this.bundledCatalog, ...this.officialCatalog].map(
                (entry) => (entry.manifest || entry).id,
            ),
        );
        const seen = new Set();
        for (const entry of entries || []) {
            if (seen.has(entry.id)) {
                throw errorWithCode(
                    'EXTENSION_SOURCE_ENTRY_DUPLICATE',
                    `Community source contains duplicate extension ${entry.id}`,
                    { extensionId: entry.id },
                );
            }
            seen.add(entry.id);
            if (builtInIds.has(entry.id)) {
                throw errorWithCode(
                    'EXTENSION_SOURCE_ID_RESERVED',
                    `Community source cannot replace built-in extension ${entry.id}`,
                    { extensionId: entry.id },
                );
            }
            const existing = this.findEntry(entry.id);
            const retained = state.installed?.[entry.id];
            if (
                existing &&
                !isSourceDistribution(existing.distribution) &&
                !sourceCanReplaceRemovedInstallation(retained)
            ) {
                throw errorWithCode(
                    'EXTENSION_SOURCE_ID_RESERVED',
                    `Community source cannot replace extension ${entry.id}`,
                    { extensionId: entry.id },
                );
            }
            if (
                existing &&
                isSourceDistribution(existing.distribution) &&
                existing.sourceId !== sourceId
            ) {
                throw errorWithCode(
                    'EXTENSION_SOURCE_ID_CONFLICT',
                    `Community extension ${entry.id} is already provided by another source`,
                    {
                        extensionId: entry.id,
                        existingSourceId: existing.sourceId || null,
                        sourceId,
                    },
                );
            }
        }
    }

    async _loadCommunitySource(url, sourceId) {
        const fetched = await fetchExtensionSourceDocument(url, {
            fetcher: this.sourceFetcher,
        });
        const catalog = normalizeCommunityCatalog(
            fetched.document,
            fetched.url,
            sourceId,
        );
        this._assertCommunityIdAvailable(catalog.entries, sourceId);
        return {
            ...catalog,
            url: fetched.url,
            digest: fetched.digest,
            headers: fetched.headers,
            verified: true,
            verificationMode: 'community-integrity',
        };
    }

    async addSource({ url, name, expectedRevision, idempotencyKey } = {}) {
        if (!this.env.isNode) {
            throw errorWithCode(
                'EXTENSION_SOURCE_MANAGEMENT_UNSUPPORTED',
                'Community extension sources are only available on the Node Host',
            );
        }
        this._assertSourceRevision(expectedRevision);
        const normalizedUrl = normalizeExtensionSourceUrl(url);
        const sourceId = extensionSourceId(normalizedUrl);
        const current = this.readState();
        const existing = current.sources?.[sourceId];
        if (existing && existing.lastIdempotencyKey === idempotencyKey) {
            return publicExtensionSource(existing);
        }
        const loaded = await this._loadCommunitySource(normalizedUrl, sourceId);
        if (existing) {
            assertImmutableSourceVersions(existing.entries, loaded.entries);
        }
        const sourceRecord = {
            id: sourceId,
            name:
                typeof name === 'string' && name.trim()
                    ? name.trim().slice(0, 200)
                    : existing?.name || normalizedUrl,
            url: loaded.url,
            status: 'ready',
            verified: loaded.verified,
            verificationMode: loaded.verificationMode,
            digest: loaded.digest,
            publisher: loaded.publisher ? clone(loaded.publisher) : null,
            entries: clone(loaded.entries),
            sequence: loaded.sequence,
            generatedAt: loaded.generatedAt,
            expiresAt: loaded.expiresAt,
            headers: clone(loaded.headers),
            addedAt: existing?.addedAt || now(),
            updatedAt: now(),
            lastError: null,
            lastIdempotencyKey: idempotencyKey || null,
        };
        const committed = this._commit(
            (state) => {
                state.sources[sourceId] = sourceRecord;
                this._recordAudit(state, {
                    action: existing ? 'refresh-source' : 'add-source',
                    sourceId,
                    result: 'ready',
                    entryCount: sourceRecord.entries.length,
                });
                return state;
            },
            { expectedRevision },
        );
        return publicExtensionSource(committed.sources[sourceId]);
    }

    async refreshSource(sourceId, { expectedRevision, idempotencyKey } = {}) {
        if (!this.env.isNode) {
            throw errorWithCode(
                'EXTENSION_SOURCE_MANAGEMENT_UNSUPPORTED',
                'Community extension sources are only available on the Node Host',
            );
        }
        const existing = this._findSource(sourceId);
        if (!existing) {
            throw errorWithCode(
                'EXTENSION_SOURCE_NOT_FOUND',
                `Extension source ${sourceId} was not found`,
            );
        }
        this._assertSourceRevision(expectedRevision);
        if (existing.lastIdempotencyKey === idempotencyKey) {
            return publicExtensionSource(existing);
        }
        try {
            const loaded = await this._loadCommunitySource(
                existing.url,
                sourceId,
            );
            assertImmutableSourceVersions(existing.entries, loaded.entries);
            const committed = this._commit(
                (state) => {
                    const source = state.sources[sourceId];
                    if (!source) return state;
                    Object.assign(source, {
                        status: 'ready',
                        verified: loaded.verified,
                        verificationMode: loaded.verificationMode,
                        digest: loaded.digest,
                        publisher: loaded.publisher
                            ? clone(loaded.publisher)
                            : null,
                        entries: clone(loaded.entries),
                        sequence: loaded.sequence,
                        generatedAt: loaded.generatedAt,
                        expiresAt: loaded.expiresAt,
                        headers: clone(loaded.headers),
                        updatedAt: now(),
                        lastError: null,
                        lastIdempotencyKey: idempotencyKey || null,
                    });
                    this._recordAudit(state, {
                        action: 'refresh-source',
                        sourceId,
                        result: 'ready',
                        entryCount: source.entries.length,
                    });
                    return state;
                },
                { expectedRevision },
            );
            return publicExtensionSource(committed.sources[sourceId]);
        } catch (error) {
            try {
                const failedState = this._commit(
                    (state) => {
                        const source = state.sources[sourceId];
                        if (source) {
                            source.status = 'error';
                            source.lastError = {
                                code:
                                    error.code ||
                                    'EXTENSION_SOURCE_REFRESH_FAILED',
                                message: error.message,
                            };
                            source.updatedAt = now();
                        }
                        return state;
                    },
                    { expectedRevision },
                );
                error.source = publicExtensionSource(
                    failedState.sources[sourceId],
                );
            } catch (stateError) {
                error.stateError = stateError;
            }
            throw error;
        }
    }

    removeSource(sourceId, { expectedRevision, idempotencyKey } = {}) {
        const current = this.readState();
        const source = current.sources?.[sourceId];
        if (!source) {
            throw errorWithCode(
                'EXTENSION_SOURCE_NOT_FOUND',
                `Extension source ${sourceId} was not found`,
            );
        }
        this._assertSourceRevision(expectedRevision);
        const committed = this._commit(
            (state) => {
                delete state.sources[sourceId];
                this._recordAudit(state, {
                    action: 'remove-source',
                    sourceId,
                    result: 'removed',
                    idempotencyKey: idempotencyKey || null,
                });
                return state;
            },
            { expectedRevision },
        );
        return {
            id: sourceId,
            status: 'removed',
            retainedInstallations: Object.values(committed.installed).filter(
                (record) => record.sourceId === sourceId,
            ).length,
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
            const publisherId = manifest.publisher?.id || null;
            if (!publisherId || manifest.publisher?.verified !== true) {
                throw errorWithCode(
                    'EXTENSION_PUBLISHER_NOT_VERIFIED',
                    'Trusted official extension publisher is not verified',
                    {
                        extensionId: manifest.id,
                        publisherId,
                    },
                );
            }
            if (
                manifest.trust?.level !== 'official-root' ||
                manifest.trust?.allowedPublisher !== publisherId ||
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
        const invoke = (method) => {
            const adapter = this.adapters.get(extensionId);
            if (!adapter || typeof adapter[method] !== 'function') {
                throw errorWithCode(
                    'EXTENSION_IMPLEMENTATION_UNAVAILABLE',
                    `Extension ${extensionId} has no ${method} implementation`,
                    { extensionId, method },
                );
            }
            return adapter[method]();
        };
        const manifest = this.getManifest(extensionId);
        const services = this.hostBindings.createServices?.({
            extensionId,
            manifest,
            manager: this,
            store: this.store,
        });
        return Object.freeze({
            apiVersion: EXTENSION_HOST_API_VERSION,
            extensionId,
            services,
            registerAdapter: (adapter) => {
                if (adapter?.extensionId !== extensionId) {
                    throw errorWithCode(
                        'EXTENSION_ABI_MISMATCH',
                        'Extension adapter identity does not match its package',
                        {
                            extensionId,
                            adapterExtensionId: adapter?.extensionId,
                        },
                    );
                }
                return this.registerAdapter(extensionId, adapter);
            },
            unregisterAdapter: (adapter) =>
                this.unregisterAdapter(extensionId, adapter),
            registerContribution: (contribution) => {
                if (contribution?.extensionId !== extensionId) {
                    throw errorWithCode(
                        'EXTENSION_ABI_MISMATCH',
                        'Extension contribution identity does not match its package',
                        {
                            extensionId,
                            contributionExtensionId:
                                contribution?.extensionId || null,
                        },
                    );
                }
                if (
                    typeof this.hostBindings.registerContribution !== 'function'
                ) {
                    throw errorWithCode(
                        'EXTENSION_CONTRIBUTION_HOST_UNAVAILABLE',
                        'The Host cannot register extension contributions',
                    );
                }
                return this.hostBindings.registerContribution(contribution);
            },
            unregisterContribution: () =>
                this.hostBindings.unregisterContribution?.(extensionId),
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
            this.activeRuntimeModules.set(record.extensionId, runtimeModule);
            this.packageStore.commitActive(record);
            this.runtimeGateBlocks.delete(record.extensionId);
            return result;
        }
        if (
            record.source === 'bundled' &&
            !this.adapters.has(record.extensionId)
        ) {
            this.runtimeGateBlocks.delete(record.extensionId);
            return { active: true, bundled: true };
        }
        const result = facade.activate();
        this.runtimeGateBlocks.delete(record.extensionId);
        return result;
    }

    _deactivateRecord(record) {
        const facade = this._hostFacade(record.extensionId);
        const errors = [];
        this.runtimeGateBlocks.set(record.extensionId, {
            reasonCode: 'EXTENSION_DISABLED',
            blockedAt: now(),
        });
        if (this.packageStore && record.entrypoint) {
            try {
                const runtimeModule = this.activeRuntimeModules.get(
                    record.extensionId,
                );
                if (typeof runtimeModule?.deactivate === 'function') {
                    runtimeModule.deactivate(facade);
                } else {
                    // The Host adapter is trusted and already resident. It is
                    // safer to close it directly than to reload package bytes.
                    facade.deactivate();
                }
            } catch (error) {
                errors.push(error);
            } finally {
                this.activeRuntimeModules.delete(record.extensionId);
                try {
                    this.packageStore.deactivate(record.extensionId, record);
                } catch (error) {
                    errors.push(error);
                }
            }
            return { active: false, errors };
        }
        if (
            record.source === 'bundled' &&
            !this.adapters.has(record.extensionId)
        ) {
            return { active: false, errors };
        }
        try {
            facade.deactivate();
        } catch (error) {
            errors.push(error);
        }
        return { active: false, errors };
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

    _communityPackageInput(entry, document, runtime) {
        const manifest = normalizeExtensionManifest(entry.manifest || entry);
        if (manifest.kind !== 'content') {
            throw errorWithCode(
                'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                'Only content extensions can be installed from community sources',
                { extensionId: manifest.id },
            );
        }
        const compatibility = this._preflightManifest(manifest, runtime);
        const selectedVariant =
            document?.selectedVariant ||
            document?.payload?.selectedVariant ||
            compatibility.selectedVariant ||
            entry.selectedVariant;
        const variant = manifest.variants?.[selectedVariant];
        if (!selectedVariant || !variant) {
            throw errorWithCode(
                'EXTENSION_VARIANT_MISMATCH',
                `No community package variant is available for ${runtime}`,
                { extensionId: manifest.id, runtime, selectedVariant },
            );
        }
        if (variant.containsExecutableCode !== false) {
            throw errorWithCode(
                'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                'Community extension variants must explicitly disable executable code',
                { extensionId: manifest.id, selectedVariant },
            );
        }
        const rawPayload = document?.payload || document;
        if (!rawPayload || typeof rawPayload !== 'object') {
            throw errorWithCode(
                'EXTENSION_PACKAGE_INVALID',
                'Community extension package payload is invalid',
            );
        }
        if (
            canonicalJson(rawPayload.manifest || null) !==
            canonicalJson(manifest)
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_MANIFEST_MISMATCH',
                'Community package manifest does not match its catalog entry',
                { extensionId: manifest.id },
            );
        }
        if (
            rawPayload.schemaVersion !== 1 ||
            rawPayload.selectedVariant !== selectedVariant ||
            canonicalJson(rawPayload.variant || null) !== canonicalJson(variant)
        ) {
            throw errorWithCode(
                'EXTENSION_VARIANT_PROJECTION_MISMATCH',
                'Community package variant does not match its manifest',
                { extensionId: manifest.id, selectedVariant },
            );
        }
        if (
            rawPayload.containsExecutableCode !== false ||
            rawPayload.containsInstallHook !== false
        ) {
            throw errorWithCode(
                'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                'Community package payloads must explicitly disable executable code and install hooks',
                { extensionId: manifest.id, selectedVariant },
            );
        }
        const files = rawPayload.files;
        const fileDigests = rawPayload.fileDigests;
        assertVerifiedPackageFiles(files, fileDigests);
        const projection = {
            schemaVersion: 1,
            manifest,
            selectedVariant,
            variant,
            containsExecutableCode: false,
            containsInstallHook: false,
            files: clone(files),
            fileDigests: clone(fileDigests),
        };
        const packageDigest = extensionPackageDigest(projection);
        const expectedCatalogDigest = sourceEntryPackageDigest(
            entry,
            selectedVariant,
        );
        if (
            rawPayload.packageDigest &&
            rawPayload.packageDigest !== packageDigest
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_DIGEST_INVALID',
                'Community package digest does not match its payload',
                { packageDigest, declared: rawPayload.packageDigest },
            );
        }
        if (expectedCatalogDigest && expectedCatalogDigest !== packageDigest) {
            throw errorWithCode(
                'EXTENSION_SOURCE_PACKAGE_MISMATCH',
                'Community package does not match the catalog digest',
                { expectedPackageDigest: expectedCatalogDigest, packageDigest },
            );
        }
        const expectedImplementation = {
            id: variant.implementationId,
            abi: variant.implementationAbi,
            frontendAssetId: variant.frontendAssetId,
            entrypoint: undefined,
            lanes: receiptImplementationLanes(manifest),
            containsExecutableCode: false,
        };
        const suppliedReceipt = rawPayload.receipt || document?.receipt;
        const receipt = suppliedReceipt
            ? clone(suppliedReceipt)
            : createDigestReceipt({
                  manifest,
                  packageDigest,
                  variant: selectedVariant,
                  implementation: expectedImplementation,
              });
        if (
            receipt?.implementation?.entrypoint != null ||
            receipt?.packageDigest !== packageDigest
        ) {
            throw errorWithCode(
                'EXTENSION_RECEIPT_IMPLEMENTATION_MISMATCH',
                'Community package receipt declares executable implementation metadata',
                { extensionId: manifest.id },
            );
        }
        const signedPayload = {
            ...projection,
            packageDigest,
            receipt,
        };
        const payloadDigest = sha256Hex(canonicalJson(signedPayload));
        if (!payloadDigest) {
            throw errorWithCode(
                'EXTENSION_CRYPTO_UNAVAILABLE',
                'SHA-256 is required to install a community extension',
            );
        }
        const signature = document?.signature || {
            algorithm: 'sha256-digest',
            keyId: `community-${entry.sourceId || 'source'}`,
            digest: payloadDigest,
            value: payloadDigest,
        };
        const packageInput = {
            schemaVersion: 1,
            source: 'community',
            manifest: clone(manifest),
            receipt,
            packageDigest,
            selectedVariant,
            payload: signedPayload,
            signature,
        };
        if (!isCommunityContentPackage(packageInput)) {
            throw errorWithCode(
                'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                'Community package failed the content-only execution contract',
                { extensionId: manifest.id },
            );
        }
        const envelopeResult = verifySignedEnvelope(
            { payload: signedPayload, signature },
            { ...this.verificationOptions, allowDigestOnly: true },
        );
        if (!envelopeResult.valid) {
            throw errorWithCode(
                envelopeResult.reasonCode ||
                    'EXTENSION_PACKAGE_SIGNATURE_INVALID',
                'Community package signature/digest verification failed',
                envelopeResult,
            );
        }
        const receiptResult = verifyReceipt(receipt, manifest, {
            expectedVariant: selectedVariant,
            expectedPackageDigest: packageDigest,
            expectedImplementation,
        });
        if (!receiptResult.valid) {
            throw errorWithCode(
                receiptResult.reasonCode || 'EXTENSION_RECEIPT_INVALID',
                'Community package receipt verification failed',
                receiptResult,
            );
        }
        return {
            manifest,
            packageInput,
            receipt,
            variant,
            compatibility,
            expectedImplementation,
            verification: envelopeResult,
            verificationMode: 'community-integrity',
        };
    }

    _verifyCommunityPackage(extensionId, input = {}) {
        const entry = input.catalogEntry || this.findEntry(extensionId);
        if (!entry || entry.distribution !== 'community') {
            throw errorWithCode(
                'EXTENSION_SOURCE_NOT_FOUND',
                `Community extension ${extensionId} is not present in a source`,
            );
        }
        const runtime = input.runtime || this.runtime;
        if (input.runtime && input.runtime !== this.runtime) {
            throw errorWithCode(
                'EXTENSION_RUNTIME_MISMATCH',
                `Package runtime ${input.runtime} does not match ${this.runtime}`,
            );
        }
        const verified = this._communityPackageInput(
            entry,
            input.package,
            runtime,
        );
        if (input.version && input.version !== verified.manifest.version) {
            throw errorWithCode(
                'EXTENSION_VERSION_UNAVAILABLE',
                `Requested extension version ${input.version} is unavailable`,
                {
                    requestedVersion: input.version,
                    availableVersion: verified.manifest.version,
                },
            );
        }
        return verified;
    }

    async installFromSource(extensionId, input = {}) {
        const canonicalId = this.resolveId(extensionId);
        const entry =
            input.catalogEntry ||
            this.findEntry(canonicalId, { version: input.version });
        const communityPackage = entry?.distribution === 'community';
        const sourceExecutable =
            entry?.distribution === SOURCE_EXECUTABLE_DISTRIBUTION;
        if (!entry) {
            const latest = this.findEntry(canonicalId);
            const error = input.version
                ? errorWithCode(
                      'EXTENSION_VERSION_UNAVAILABLE',
                      `Requested extension version ${input.version} is unavailable`,
                      {
                          extensionId: canonicalId,
                          requestedVersion: input.version,
                          availableVersion:
                              (latest?.manifest || latest)?.version || null,
                      },
                  )
                : errorWithCode(
                      'EXTENSION_SOURCE_NOT_FOUND',
                      `Extension ${canonicalId} is not present in an installed source`,
                      { extensionId: canonicalId, sourceId: null },
                  );
            error.statusCode = 404;
            throw error;
        }
        if (!communityPackage && !sourceExecutable) {
            return this.install(canonicalId, input);
        }
        const source = entry.sourceId ? this._findSource(entry.sourceId) : null;
        if (
            entry.sourceMissing === true ||
            (entry.sourceId && (!source || source.verified !== true))
        ) {
            throw errorWithCode(
                'EXTENSION_SOURCE_NOT_FOUND',
                `Extension ${canonicalId} no longer has an installed source`,
                { extensionId: canonicalId, sourceId: entry.sourceId || null },
            );
        }
        const runtime = input.runtime || this.runtime;
        const selectedVariant =
            entry.selectedVariant ||
            this._preflightManifest(entry.manifest || entry, runtime)
                .selectedVariant;
        const packageUrl = sourceEntryPackageUrl(entry, selectedVariant);
        if (!packageUrl) {
            throw errorWithCode(
                'EXTENSION_SOURCE_PACKAGE_URL_MISSING',
                `Extension ${canonicalId} has no source package URL`,
            );
        }
        const packageDocument = entry.inlinePackage
            ? clone(entry.inlinePackage)
            : (
                  await fetchExtensionSourceDocument(packageUrl, {
                      fetcher: this.sourceFetcher,
                  })
              ).document;
        return this.install(canonicalId, {
            ...input,
            runtime,
            source: communityPackage
                ? 'community'
                : SOURCE_EXECUTABLE_DISTRIBUTION,
            package: packageDocument,
            catalogEntry: entry,
        });
    }

    _verifyLocalPackage(extensionId, input = {}) {
        const catalogEntry =
            input.catalogEntry ||
            this.findEntry(extensionId, { version: input.version });
        const packageInput = input.package;
        const sourceExecutable =
            input.source === SOURCE_EXECUTABLE_DISTRIBUTION &&
            catalogEntry?.distribution === SOURCE_EXECUTABLE_DISTRIBUTION;
        const localExecutable =
            input.source === 'local-upload' &&
            packageInput?.manifest?.kind === 'executable';
        const manifest = localExecutable
            ? normalizeExtensionManifest(packageInput.manifest)
            : catalogEntry
            ? normalizeExtensionManifest(catalogEntry.manifest || catalogEntry)
            : this.getManifest(extensionId);
        if (!manifest) {
            throw errorWithCode(
                'EXTENSION_UNKNOWN',
                `Unknown extension ${extensionId}`,
            );
        }
        const runtime = input.runtime || this.runtime;
        if (input.runtime && input.runtime !== this.runtime) {
            throw errorWithCode(
                'EXTENSION_RUNTIME_MISMATCH',
                `Package runtime ${input.runtime} does not match ${this.runtime}`,
            );
        }
        let compatibility;
        if (sourceExecutable || localExecutable) {
            compatibility = this._preflightManifest(manifest, runtime);
        } else {
            this._assertCatalogReady(manifest);
            compatibility = this._preflightManifest(manifest, runtime);
        }
        const expectedVariant = compatibility.selectedVariant;
        const resolvedPackageInput =
            packageInput || createLocalOfficialPackage(manifest.id, runtime);
        if (!resolvedPackageInput) {
            throw errorWithCode(
                'EXTENSION_SOURCE_PACKAGE_REQUIRED',
                `Install ${manifest.id} from a verified extension source or signed local directory`,
                {
                    extensionId: manifest.id,
                    runtime,
                    localDirectorySupported: runtime === 'node',
                },
            );
        }
        let packageManifest;
        try {
            packageManifest = normalizeExtensionManifest(
                resolvedPackageInput.manifest,
            );
        } catch (error) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_MANIFEST_MISMATCH',
                'Package manifest is invalid',
                { cause: error.message },
            );
        }
        if (canonicalJson(packageManifest) !== canonicalJson(manifest)) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_MANIFEST_MISMATCH',
                'Package manifest does not match the catalog entry after normalization',
            );
        }
        const payload = resolvedPackageInput.payload;
        if (
            !payload ||
            canonicalJson(payload.manifest || null) !==
                canonicalJson(resolvedPackageInput.manifest || null)
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_MANIFEST_MISMATCH',
                'Package payload does not contain the outer package manifest',
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
            resolvedPackageInput.selectedVariant !== expectedVariant ||
            payload.selectedVariant !== expectedVariant
        ) {
            throw errorWithCode(
                'EXTENSION_VARIANT_MISMATCH',
                `Requested extension variant ${input.variant} is unavailable for ${runtime}`,
                {
                    requestedVariant: input.variant,
                    selectedVariant: resolvedPackageInput.selectedVariant,
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
            resolvedPackageInput.schemaVersion !== 1 ||
            payload.schemaVersion !== resolvedPackageInput.schemaVersion
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_SCHEMA_INCOMPATIBLE',
                'Extension package schema is unsupported',
                {
                    packageSchemaVersion: resolvedPackageInput.schemaVersion,
                    payloadSchemaVersion: payload.schemaVersion,
                },
            );
        }
        const expectedImplementation = {
            id: variant.implementationId,
            abi: variant.implementationAbi,
            frontendAssetId: variant.frontendAssetId,
            entrypoint: variant.entrypoint,
            lanes: receiptImplementationLanes(manifest),
            containsExecutableCode: variant.containsExecutableCode === true,
        };
        if (
            canonicalJson(payload.receipt || null) !==
            canonicalJson(resolvedPackageInput.receipt || null)
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_RECEIPT_MISMATCH',
                'Signed package receipt does not match the outer receipt',
            );
        }
        const calculatedPackageDigest = extensionPackageDigest(payload);
        if (
            !isSha256Digest(resolvedPackageInput.packageDigest) ||
            resolvedPackageInput.packageDigest !== payload.packageDigest ||
            resolvedPackageInput.packageDigest !==
                resolvedPackageInput.receipt?.packageDigest ||
            calculatedPackageDigest !== resolvedPackageInput.packageDigest
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_DIGEST_INVALID',
                'Package digest is not closed over the signed payload',
                {
                    packageDigest: resolvedPackageInput.packageDigest || null,
                    payloadPackageDigest: payload.packageDigest || null,
                    receiptPackageDigest:
                        resolvedPackageInput.receipt?.packageDigest || null,
                    calculatedPackageDigest,
                },
            );
        }
        const declaredSourceDigest = sourceExecutable
            ? sourceEntryPackageDigest(catalogEntry, expectedVariant)
            : null;
        if (
            sourceExecutable &&
            declaredSourceDigest !== resolvedPackageInput.packageDigest
        ) {
            throw errorWithCode(
                'EXTENSION_SOURCE_PACKAGE_DIGEST_MISMATCH',
                'Downloaded extension package does not match the source digest',
                {
                    extensionId: manifest.id,
                    version: manifest.version,
                    expectedPackageDigest: declaredSourceDigest,
                    actualPackageDigest: resolvedPackageInput.packageDigest,
                },
            );
        }
        if (!sourceExecutable && !localExecutable) {
            this._assertPackageCatalogAuthorization(
                manifest,
                expectedVariant,
                resolvedPackageInput.packageDigest,
            );
        }
        const files = payload.files;
        const fileDigests = payload.fileDigests;
        assertVerifiedPackageFiles(files, fileDigests);
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
        } else if (
            resolvedPackageInput.receipt?.implementation?.entrypoint != null
        ) {
            throw errorWithCode(
                'EXTENSION_RECEIPT_IMPLEMENTATION_MISMATCH',
                'A non-executable variant cannot declare an entrypoint',
            );
        }
        const envelopeResult = verifySignedEnvelope(
            {
                payload,
                signature: resolvedPackageInput.signature,
            },
            sourceExecutable || localExecutable
                ? { ...this.verificationOptions, allowDigestOnly: true }
                : this.verificationOptions,
        );
        if (!envelopeResult.valid) {
            throw errorWithCode(
                envelopeResult.reasonCode ||
                    'EXTENSION_PACKAGE_SIGNATURE_INVALID',
                'Official package signature/digest verification failed',
                envelopeResult,
            );
        }
        const receiptResult = verifyReceipt(
            resolvedPackageInput.receipt,
            resolvedPackageInput.manifest,
            {
                expectedVariant,
                expectedPackageDigest: resolvedPackageInput.packageDigest,
                expectedImplementation,
            },
        );
        if (!receiptResult.valid) {
            throw errorWithCode(
                receiptResult.reasonCode || 'EXTENSION_RECEIPT_INVALID',
                'Official package receipt verification failed',
                receiptResult,
            );
        }
        if (
            containsExecutableCode &&
            (runtime !== 'node' ||
                (manifest.kind !== 'trusted-official' &&
                    manifest.kind !== 'executable'))
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_EXECUTION_PAYLOAD_FORBIDDEN',
                'Executable extension payloads are only accepted for trusted Host packages or explicitly trusted Node extensions',
            );
        }
        if (
            manifest.kind === 'executable' &&
            (!containsExecutableCode || (!sourceExecutable && !localExecutable))
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_EXECUTION_PAYLOAD_FORBIDDEN',
                'Executable extensions require an explicitly trusted source or local upload',
                { extensionId: manifest.id },
            );
        }
        return {
            manifest,
            packageInput: resolvedPackageInput,
            receipt: resolvedPackageInput.receipt,
            variant,
            compatibility,
            expectedImplementation,
            verification: envelopeResult,
            verificationMode: sourceExecutable
                ? 'source-integrity'
                : localExecutable
                ? 'local-integrity'
                : verificationMode(envelopeResult),
        };
    }

    inspectLocalPackage(packageInput) {
        if (this.runtime !== 'node') {
            const error = errorWithCode(
                'EXTENSION_LOCAL_PACKAGE_UNSUPPORTED',
                'Local extension package inspection is only available on Node',
                { runtime: this.runtime },
            );
            error.statusCode = 501;
            throw error;
        }
        const extensionId = packageInput?.manifest?.id;
        const verified = this._verifyLocalPackage(extensionId, {
            runtime: 'node',
            package: packageInput,
            source: 'local-upload',
        });
        this.packageStore?.validatePackageInput?.(verified.packageInput, {
            allowDigestOnly: verified.verification?.trust === 'integrity-only',
        });
        return {
            extensionId: verified.manifest.id,
            manifest: clone(verified.manifest),
            receipt: clone(verified.receipt),
            selectedVariant: verified.receipt.selectedVariant,
            packageDigest: verified.receipt.packageDigest,
            verificationMode: verified.verificationMode,
            compatibility: clone(verified.compatibility),
        };
    }

    install(extensionId, input = {}) {
        const canonicalId = this.resolveId(extensionId);
        const catalogEntry =
            input.catalogEntry ||
            this.findEntry(canonicalId, { version: input.version });
        if (!catalogEntry && !input.package) {
            const error = errorWithCode(
                'EXTENSION_SOURCE_NOT_FOUND',
                `Extension ${canonicalId} is not present in an installed source`,
                { extensionId: canonicalId, sourceId: null },
            );
            error.statusCode = 404;
            throw error;
        }
        const isCommunity = catalogEntry?.distribution === 'community';
        const isSourceExecutable =
            catalogEntry?.distribution === SOURCE_EXECUTABLE_DISTRIBUTION;
        const taskAction = input.taskAction || 'install';
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
            taskAction,
            input.idempotencyKey,
        );
        if (existingTask) {
            return this._taskResult(
                existingTask,
                currentState.installed[canonicalId],
            );
        }
        if ((isCommunity || isSourceExecutable) && !input.package) {
            throw errorWithCode(
                'EXTENSION_SOURCE_PACKAGE_REQUIRED',
                'Source extensions must be installed through their verified package URL',
            );
        }
        const verified = isCommunity
            ? this._verifyCommunityPackage(canonicalId, input)
            : this._verifyLocalPackage(canonicalId, input);
        const localExecutableInstall =
            input.source === 'local-upload' &&
            verified.manifest.kind === 'executable';
        const previous = currentState.installed[canonicalId];
        if (previous?.installationStatus === 'installed') {
            const versionComparison = compareVersions(
                verified.manifest.version,
                previous.version,
            );
            if (versionComparison === null) {
                throw errorWithCode(
                    'EXTENSION_VERSION_INVALID',
                    'Extension package version cannot be compared with the installed version',
                    {
                        installedVersion: previous.version,
                        packageVersion: verified.manifest.version,
                    },
                );
            }
            if (versionComparison < 0 && input.allowDowngrade !== true) {
                throw errorWithCode(
                    'EXTENSION_VERSION_DOWNGRADE_FORBIDDEN',
                    'Select an explicit remote version or use local rollback to restore an older extension version',
                    {
                        installedVersion: previous.version,
                        packageVersion: verified.manifest.version,
                    },
                );
            }
            if (versionComparison === 0) {
                if (previous.packageDigest !== verified.receipt.packageDigest) {
                    throw errorWithCode(
                        'EXTENSION_VERSION_IMMUTABLE',
                        'An installed extension version cannot be replaced with different package content',
                        {
                            extensionId: canonicalId,
                            version: previous.version,
                            installedPackageDigest: previous.packageDigest,
                            requestedPackageDigest:
                                verified.receipt.packageDigest,
                        },
                    );
                }
                let noOpResult;
                this._commit(
                    (state) => {
                        const record = state.installed[canonicalId];
                        const task = this._createTask(state, {
                            extensionId: canonicalId,
                            action: taskAction,
                            idempotencyKey: input.idempotencyKey,
                        });
                        const status =
                            taskAction === 'update'
                                ? 'current'
                                : 'already-installed';
                        this._finishTask(state, task, {
                            extensionId: canonicalId,
                            status,
                            noOp: true,
                        });
                        this._recordAudit(state, {
                            action: taskAction,
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
        }
        const stagedPackage = this.packageStore
            ? this.packageStore.stage(verified.packageInput, {
                  allowCommunityContent: isCommunity,
                  allowDigestOnly:
                      verified.verification?.trust === 'integrity-only',
              })
            : null;
        const shouldReactivatePrevious = previous?.enabled === true;
        if (shouldReactivatePrevious) this._deactivateRecord(previous);
        let result;
        try {
            this._commit(
                (state) => {
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action: taskAction,
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
                        manifestSnapshot: clone(verified.manifest),
                        distribution: localExecutableInstall
                            ? LOCAL_EXECUTABLE_DISTRIBUTION
                            : catalogEntry?.distribution || 'store',
                        sourceId: localExecutableInstall
                            ? null
                            : catalogEntry?.sourceId || null,
                        sourceUrl: localExecutableInstall
                            ? null
                            : catalogEntry?.source || null,
                        sourceName: localExecutableInstall
                            ? null
                            : catalogEntry?.sourceName || null,
                        packageUrls: clone(
                            localExecutableInstall
                                ? {}
                                : catalogEntry?.packageUrls || {},
                        ),
                        packageDigests: clone(
                            localExecutableInstall
                                ? {}
                                : catalogEntry?.packageDigests || {},
                        ),
                        adoption: clone(
                            input.adoption || previousRecord?.adoption,
                        ),
                        adoptionStatus:
                            input.adoption || previousRecord?.adoption
                                ? 'completed'
                                : undefined,
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
                        source:
                            input.source ||
                            (isCommunity ? 'community' : 'official-local'),
                        rollbackHistory:
                            previousRecord?.installationStatus === 'installed'
                                ? appendRollbackSnapshot(
                                      previousRecord.rollbackHistory,
                                      previousRecord,
                                  )
                                : [],
                    };
                    state.installed[canonicalId] = record;
                    state.dataGeneration += 1;
                    const resultStatus =
                        taskAction === 'update'
                            ? 'updated-disabled'
                            : 'installed-disabled';
                    this._finishTask(state, task, {
                        extensionId: canonicalId,
                        status: resultStatus,
                        selectedVariant: record.selectedVariant,
                        packageDigest: record.packageDigest,
                    });
                    this._recordAudit(state, {
                        action: taskAction,
                        extensionId: canonicalId,
                        packageDigest: record.packageDigest,
                        manifestDigest: record.manifestDigest,
                        result: resultStatus,
                    });
                    result = {
                        taskId: task.id,
                        status: resultStatus,
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
        if (enabled && before.distribution === 'community') {
            throw errorWithCode(
                'EXTENSION_CONTENT_ONLY',
                'Community content extensions cannot be enabled as backend runtimes',
                { extensionId: canonicalId },
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
        if (
            before.enabled === enabled &&
            !(enabled && this.runtimeGateBlocks.has(canonicalId))
        ) {
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
                    if (!requiresCodeCleanup) record.rollbackHistory = [];
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
                record.rollbackHistory = [];
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

    async update(extensionId, input = {}) {
        const canonicalId = this.resolveId(extensionId);
        const initialState = this.readState();
        if (
            input.expectedRevision !== undefined &&
            Number(input.expectedRevision) !== Number(initialState.revision)
        ) {
            throw errorWithCode(
                'EXTENSION_CONSISTENCY_CONFLICT',
                'Extension state changed; reload before retrying',
                {
                    expectedRevision: Number(input.expectedRevision),
                    currentRevision: initialState.revision,
                },
            );
        }
        const before = initialState.installed[canonicalId];
        if (!before || before.installationStatus !== 'installed') {
            throw errorWithCode(
                'EXTENSION_NOT_INSTALLED',
                `Extension ${canonicalId} is not installed`,
            );
        }
        const existingTask = this._findIdempotentTask(
            initialState,
            canonicalId,
            'update',
            input.idempotencyKey,
        );
        if (existingTask) return this._taskResult(existingTask, before);

        const sourceId =
            before.sourceId ||
            Object.values(initialState.sources || {}).find((source) =>
                (source.entries || []).some(
                    (entry) => entry.id === canonicalId,
                ),
            )?.id;
        if (!sourceId) {
            throw errorWithCode(
                'EXTENSION_UPDATE_SOURCE_REQUIRED',
                'Extension updates require an installed extension source',
                { extensionId: canonicalId },
            );
        }
        await this.refreshSource(sourceId, {
            expectedRevision: input.expectedRevision,
            idempotencyKey: input.idempotencyKey
                ? `update-refresh:${canonicalId}:${input.idempotencyKey}`
                : undefined,
        });
        const refreshedState = this.readState();
        const source = refreshedState.sources?.[sourceId];
        const sourceCatalogEntry = (source?.entries || [])
            .filter((entry) => entry.id === canonicalId)
            .reduce(preferCatalogEntry, null);
        const catalogEntry = input.version
            ? catalogRelease(sourceCatalogEntry, input.version)
            : sourceCatalogEntry;
        if (!catalogEntry || source?.verified !== true) {
            if (input.version && sourceCatalogEntry) {
                throw errorWithCode(
                    'EXTENSION_VERSION_UNAVAILABLE',
                    `Requested extension version ${input.version} is unavailable`,
                    {
                        extensionId: canonicalId,
                        sourceId,
                        requestedVersion: input.version,
                        availableVersion: (
                            sourceCatalogEntry.manifest || sourceCatalogEntry
                        ).version,
                    },
                );
            }
            throw errorWithCode(
                'EXTENSION_SOURCE_NOT_FOUND',
                `Extension ${canonicalId} is no longer available from its source`,
                { extensionId: canonicalId, sourceId },
            );
        }
        const availableManifest = normalizeExtensionManifest(
            catalogEntry.manifest || catalogEntry,
        );
        if (input.version && input.version !== availableManifest.version) {
            throw errorWithCode(
                'EXTENSION_VERSION_UNAVAILABLE',
                `Requested extension version ${input.version} is unavailable`,
                {
                    requestedVersion: input.version,
                    availableVersion: availableManifest.version,
                },
            );
        }
        const comparison = compareVersions(
            availableManifest.version,
            before.version,
        );
        if (comparison === null) {
            throw errorWithCode(
                'EXTENSION_VERSION_INVALID',
                'Extension source version cannot be compared with the installed version',
                {
                    installedVersion: before.version,
                    availableVersion: availableManifest.version,
                },
            );
        }
        if (comparison < 0 && input.version) {
            const installedStorageSchemaVersion = Number(
                before.manifestSnapshot?.storage?.schemaVersion,
            );
            const targetStorageSchemaVersion = Number(
                availableManifest.storage?.schemaVersion,
            );
            if (
                Number.isInteger(installedStorageSchemaVersion) &&
                Number.isInteger(targetStorageSchemaVersion) &&
                targetStorageSchemaVersion < installedStorageSchemaVersion
            ) {
                throw errorWithCode(
                    'EXTENSION_STORAGE_SCHEMA_DOWNGRADE_FORBIDDEN',
                    'The selected extension version declares an older storage schema and cannot safely read current data',
                    {
                        extensionId: canonicalId,
                        installedVersion: before.version,
                        targetVersion: availableManifest.version,
                        installedStorageSchemaVersion,
                        targetStorageSchemaVersion,
                    },
                );
            }
        }
        if (comparison === 0 || (comparison < 0 && !input.version)) {
            let noOpResult;
            this._commit(
                (state) => {
                    const record = state.installed[canonicalId];
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action: 'update',
                        idempotencyKey: input.idempotencyKey,
                    });
                    this._finishTask(state, task, {
                        extensionId: canonicalId,
                        status: 'current',
                        noOp: true,
                        installedVersion: before.version,
                        availableVersion: availableManifest.version,
                    });
                    this._recordAudit(state, {
                        action: 'update',
                        extensionId: canonicalId,
                        result: 'current-no-op',
                    });
                    noOpResult = {
                        taskId: task.id,
                        status: 'current',
                        noOp: true,
                        record: publicRecord(record),
                    };
                    return state;
                },
                { expectedRevision: refreshedState.revision },
            );
            const completedTask = this.getTask(noOpResult.taskId);
            if (completedTask) noOpResult.task = clone(completedTask);
            return noOpResult;
        }

        const installed = await this.installFromSource(canonicalId, {
            ...input,
            allowDowngrade: comparison < 0 && Boolean(input.version),
            expectedRevision: refreshedState.revision,
            taskAction: 'update',
            catalogEntry,
        });
        if (installed.noOp) return installed;
        const updatedRecord = this.getRecord(canonicalId);
        if (before.enabled !== true) {
            const cleanupWarning = cleanupObsoleteVersionPackages(
                this.packageStore,
                before,
                updatedRecord,
            );
            if (cleanupWarning) installed.cleanupWarning = cleanupWarning;
            return installed;
        }

        let activated = false;
        try {
            this._activateRecord(updatedRecord);
            activated = true;
            let result;
            const committed = this._commit(
                (state) => {
                    const record = state.installed[canonicalId];
                    if (
                        !record ||
                        record.packageDigest !== updatedRecord.packageDigest
                    ) {
                        throw errorWithCode(
                            'EXTENSION_CONSISTENCY_CONFLICT',
                            'Updated extension state changed before activation completed',
                            { extensionId: canonicalId },
                        );
                    }
                    const task = state.tasks.find(
                        (candidate) => candidate.id === installed.taskId,
                    );
                    record.enabled = true;
                    record.codeStatus = this.env.isNode
                        ? 'verified-package-active'
                        : 'embedded-active';
                    record.updatedAt = now();
                    if (task) {
                        this._finishTask(state, task, {
                            extensionId: canonicalId,
                            status: 'updated-enabled',
                            fromVersion: before.version,
                            version: record.version,
                            packageDigest: record.packageDigest,
                        });
                    }
                    this._recordAudit(state, {
                        action: 'update',
                        extensionId: canonicalId,
                        result: 'updated-enabled',
                        fromVersion: before.version,
                        version: record.version,
                    });
                    result = {
                        taskId: installed.taskId,
                        status: 'updated-enabled',
                        record: publicRecord(record),
                    };
                    return state;
                },
                { expectedRevision: this.readState().revision },
            );
            const task = committed.tasks.find(
                (candidate) => candidate.id === installed.taskId,
            );
            if (task) result.task = clone(task);
            const cleanupWarning = cleanupObsoleteVersionPackages(
                this.packageStore,
                before,
                this.getRecord(canonicalId),
            );
            if (cleanupWarning) result.cleanupWarning = cleanupWarning;
            return result;
        } catch (error) {
            if (activated || updatedRecord) {
                try {
                    this._deactivateRecord(updatedRecord);
                } catch (deactivationError) {
                    error.deactivationError = deactivationError;
                }
            }
            let restored = false;
            try {
                if (this.packageStore && before.entrypoint) {
                    this.packageStore.verifyInstalledRecord(before);
                }
                this._activateRecord(before);
                restored = true;
            } catch (rollbackError) {
                error.rollbackError = rollbackError;
            }
            try {
                this._commit((state) => {
                    const task = state.tasks.find(
                        (candidate) => candidate.id === installed.taskId,
                    );
                    const restoredRecord = clone(before);
                    restoredRecord.enabled = restored;
                    restoredRecord.codeStatus = restored
                        ? this.env.isNode
                            ? 'verified-package-active'
                            : 'embedded-active'
                        : this.env.isNode
                        ? 'verified-package-inactive'
                        : 'embedded-inactive';
                    restoredRecord.updatedAt = now();
                    state.installed[canonicalId] = restoredRecord;
                    if (task) {
                        this._finishTask(
                            state,
                            task,
                            {
                                extensionId: canonicalId,
                                status: restored
                                    ? 'update-failed-restored'
                                    : 'update-failed-disabled',
                                restoredVersion: before.version,
                            },
                            error,
                        );
                    }
                    this._recordAudit(state, {
                        action: 'update',
                        extensionId: canonicalId,
                        result: restored
                            ? 'activation-failed-restored'
                            : 'activation-failed-disabled',
                        reasonCode: error.code || 'EXTENSION_ACTIVATION_FAILED',
                    });
                    return state;
                });
            } catch (stateError) {
                error.stateError = stateError;
            }
            try {
                this.packageStore?.removeVersion?.(updatedRecord);
            } catch (cleanupError) {
                error.cleanupError = cleanupError;
            }
            error.details = {
                ...(error.details || {}),
                extensionId: canonicalId,
                attemptedVersion: updatedRecord?.version || null,
                restoredVersion: restored ? before.version : null,
                restored,
            };
            throw error;
        }
    }

    rollback(extensionId, input = {}) {
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
        const existingTask = this._findIdempotentTask(
            currentState,
            canonicalId,
            'rollback',
            input.idempotencyKey,
        );
        if (existingTask) return this._taskResult(existingTask, before);
        const history = verifiedRollbackHistory(before);
        let targetIndex = history.length - 1;
        if (input.version) {
            targetIndex = -1;
            for (let index = history.length - 1; index >= 0; index -= 1) {
                if (history[index].version === input.version) {
                    targetIndex = index;
                    break;
                }
            }
        }
        if (targetIndex < 0) {
            throw errorWithCode(
                'EXTENSION_ROLLBACK_UNAVAILABLE',
                'No verified rollback version is available',
                {
                    extensionId: canonicalId,
                    requestedVersion: input.version || null,
                    rollbackVersions: history.map(
                        (snapshot) => snapshot.version,
                    ),
                },
            );
        }
        const target = clone(history[targetIndex]);
        this._preflightManifest(target.manifestSnapshot, this.runtime);
        if (target.packageDirectory && !this.packageStore) {
            throw errorWithCode(
                'EXTENSION_ROLLBACK_PACKAGE_UNAVAILABLE',
                'The verified rollback package store is unavailable',
                { extensionId: canonicalId, version: target.version },
            );
        }
        if (this.packageStore && target.entrypoint) {
            this.packageStore.verifyInstalledRecord(target);
        }

        const shouldEnable = before.enabled === true;
        if (shouldEnable) this._deactivateRecord(before);
        let targetActivated = false;
        try {
            if (shouldEnable) {
                this._activateRecord(target);
                targetActivated = true;
            }
            let result;
            const committed = this._commit(
                (state) => {
                    const task = this._createTask(state, {
                        extensionId: canonicalId,
                        action: 'rollback',
                        idempotencyKey: input.idempotencyKey,
                    });
                    const restoredRecord = {
                        ...clone(target),
                        rollbackHistory: clone(history.slice(0, targetIndex)),
                        enabled: shouldEnable,
                        codeStatus: shouldEnable
                            ? this.env.isNode
                                ? 'verified-package-active'
                                : 'embedded-active'
                            : this.env.isNode
                            ? 'verified-package-inactive'
                            : 'embedded-inactive',
                        updatedAt: now(),
                    };
                    state.installed[canonicalId] = restoredRecord;
                    state.dataGeneration += 1;
                    const status = shouldEnable
                        ? 'rolled-back-enabled'
                        : 'rolled-back-disabled';
                    this._finishTask(state, task, {
                        extensionId: canonicalId,
                        status,
                        fromVersion: before.version,
                        version: restoredRecord.version,
                    });
                    this._recordAudit(state, {
                        action: 'rollback',
                        extensionId: canonicalId,
                        result: status,
                        fromVersion: before.version,
                        version: restoredRecord.version,
                    });
                    result = {
                        taskId: task.id,
                        status,
                        record: publicRecord(restoredRecord),
                    };
                    return state;
                },
                { expectedRevision: input.expectedRevision },
            );
            const task = committed.tasks.find(
                (candidate) => candidate.id === result.taskId,
            );
            if (task) result.task = clone(task);
            try {
                this.packageStore?.removeVersion?.(before);
                for (const discarded of history.slice(targetIndex + 1)) {
                    this.packageStore?.removeVersion?.(discarded);
                }
            } catch (cleanupError) {
                result.cleanupWarning = {
                    code:
                        cleanupError.code || 'EXTENSION_PACKAGE_CLEANUP_FAILED',
                    message: cleanupError.message,
                };
            }
            return result;
        } catch (error) {
            if (targetActivated) {
                try {
                    this._deactivateRecord(target);
                } catch (deactivationError) {
                    error.deactivationError = deactivationError;
                }
            }
            if (shouldEnable) {
                try {
                    this._activateRecord(before);
                } catch (restoreError) {
                    error.restoreError = restoreError;
                }
            }
            throw error;
        }
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
        for (const entry of this._latestCatalogEntries()) {
            const manifest = entry.manifest || entry;
            if (this.getAvailability(manifest.id).status === 'enabled') {
                for (const feature of manifest.contributes?.features || []) {
                    flags[feature] = true;
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

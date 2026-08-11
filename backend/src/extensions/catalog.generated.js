/*
 * Deterministic catalog source for the first Extension Host iteration.
 *
 * The file name intentionally matches the future build-generated catalog.
 * Entries contain data/entrypoint keys only; they never contain an arbitrary
 * filesystem path or executable source supplied by a remote catalog.
 */
import configHostingManifest from './config-hosting/manifest.json';
import configHostingReceiptProjection from './config-hosting/receipt.json';
import {
    canonicalJson,
    cloneExtensionValue,
    normalizeExtensionManifest,
} from './contracts';
import {
    createDigestReceipt,
    extensionPackageDigest,
    sha256Hex,
} from './signature';

const GENERATED_AT = '2026-08-10T00:00:00.000Z';
const RELEASED_AT = Date.parse(GENERATED_AT);
const CATALOG_EXPIRES_AT = Date.parse('2036-08-10T00:00:00.000Z');
const LEGACY_RELEASE_KEY_ID = 'substore-release-root-2026-01';
const LEGACY_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuY9XBfpDWyzzWwgUTMJAZVOSE+dud0zndNIwqav59DM=
-----END PUBLIC KEY-----
`;
const CURRENT_RELEASE_KEY_ID = 'substore-release-root-2026-08';
const CURRENT_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA6BoRDh3POOZxZ5fLZdo09IjMyPSAvgCCCOXWzb1k+ao=
-----END PUBLIC KEY-----
`;
const CATALOG_RELEASE_KEY_ID = 'substore-catalog-root-2026-08-v3';
const CATALOG_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAasFowkkY6KFbjst83yaYEmI+4iITNozbMZvQrMyGBUE=
-----END PUBLIC KEY-----
`;
const OFFICIAL_PACKAGE_SIGNATURES = Object.freeze({
    'org.substore.config-hosting': Object.freeze({
        keyId: CURRENT_RELEASE_KEY_ID,
        variants: Object.freeze({
            node: 'DNBQZGZSYwaS3zgfHIa04xKdzc7Th7/2o0Zrz6jBTy95+n2lheF8GxfDOhNzyPtkdU1MJ1LadhL27nXJ4rnPCQ==',
            qx: 'jPiml9J9YMbPgy4I4JK7reXoex7ass6ECEQ/DDhsgaeF8m3ebZqO6JgbgIhDILL7cu38YVruxBsvfMi+6YSbBQ==',
            loon: 'IfGmSovhIFyK0pD8X6ZBqFhCNUdsQR9rilKGg0I5ddFiMT94LHASteYk/fsThkKoyDgeTusp7Nuhd7PhCb+9DQ==',
            surge: 'T7KNSHVl38+gcS1hR07N/OXjPbd8YdGSgyQVeWpZldYfAyba/WMP0sg5Z4yjri9DdrrmfFPoO+3ynXUcLCO9CA==',
            'default-script-runtime':
                'JCWdCg95+OtApGxMgvpFKKgNfH1FQXDO8puHoJzNS7KKD9imNNwuw56nNsX5JSUTal0TkTD6fgwCCTzY/BklBA==',
        }),
    }),
});

export const officialExtensionTrustedKeys = Object.freeze({
    [LEGACY_RELEASE_KEY_ID]: LEGACY_RELEASE_PUBLIC_KEY,
    [CURRENT_RELEASE_KEY_ID]: CURRENT_RELEASE_PUBLIC_KEY,
    [CATALOG_RELEASE_KEY_ID]: CATALOG_RELEASE_PUBLIC_KEY,
});
const CONFIG_HOSTING_NODE_ENTRYPOINT = `'use strict';

const extensionId = 'org.substore.config-hosting';

module.exports = Object.freeze({
    extensionId,
    implementationAbi: 'config-hosting@1',
    activate(host) {
        if (!host || host.apiVersion !== '1.0.0' || host.extensionId !== extensionId) {
            const error = new Error('Config hosting Host API is incompatible');
            error.code = 'EXTENSION_HOST_API_INCOMPATIBLE';
            throw error;
        }
        return host.activate();
    },
    deactivate(host) {
        return host && typeof host.deactivate === 'function'
            ? host.deactivate()
            : undefined;
    },
});
`;

const NODE_ENTRYPOINTS = Object.freeze({
    'org.substore.config-hosting': CONFIG_HOSTING_NODE_ENTRYPOINT,
});

export const bundledExtensionCatalog = Object.freeze([]);

export const officialExtensionCatalog = Object.freeze([
    Object.freeze({
        manifest: Object.freeze(
            normalizeExtensionManifest(configHostingManifest),
        ),
        receiptProjection: Object.freeze(
            cloneExtensionValue(configHostingReceiptProjection),
        ),
        distribution: 'trusted-official-package',
        source: 'local-official-seed',
        defaultEnabled: false,
    }),
]);

export const embeddedExtensionImplementations = Object.freeze({
    'org.substore.config-hosting': Object.freeze({
        implementationAbi: 'config-hosting@1',
        frontendImplementationAbi: 'config-hosting-ui@1',
        lanes: Object.freeze({
            simple: Object.freeze({
                product: 'sub-store-0',
                implementationId: 'org.substore.config-hosting@1/simple',
            }),
            parser: Object.freeze({
                product: 'sub-store-1',
                implementationId: 'org.substore.config-hosting@1/parser',
            }),
            scheduled: Object.freeze({
                product: 'cron-sync-artifacts',
                implementationId: 'org.substore.config-hosting@1/scheduled',
            }),
        }),
    }),
});

const catalogPayload = Object.freeze({
    schemaVersion: 1,
    sequence: 4,
    channel: 'stable',
    generatedAt: GENERATED_AT,
    expiresAt: CATALOG_EXPIRES_AT,
    entries: [...bundledExtensionCatalog, ...officialExtensionCatalog].map(
        (entry) => ({
            id: entry.manifest.id,
            version: entry.manifest.version,
            name: entry.manifest.name,
            description: entry.manifest.description,
            kind: entry.manifest.kind,
            distribution:
                entry.distribution || entry.manifest.distribution || 'bundled',
            publisher: entry.manifest.publisher,
            manifestDigest: sha256Hex(canonicalJson(entry.manifest)),
            packageDigests:
                entry.distribution === 'trusted-official-package'
                    ? Object.fromEntries(
                          Object.keys(entry.manifest.variants || {}).map(
                              (selectedVariant) => [
                                  selectedVariant,
                                  extensionPackageDigest(
                                      createPackageProjection(
                                          entry,
                                          selectedVariant,
                                      ),
                                  ),
                              ],
                          ),
                      )
                    : undefined,
            source: entry.source,
        }),
    ),
});

const catalogDigest = sha256Hex(canonicalJson(catalogPayload));

export const signedExtensionCatalog = Object.freeze({
    payload: catalogPayload,
    expiresAt: CATALOG_EXPIRES_AT,
    signature: Object.freeze({
        algorithm: 'ed25519',
        keyId: CATALOG_RELEASE_KEY_ID,
        digest: catalogDigest,
        value: 'H/i9hNxnRxiw+JeyBpQsKJbNo+Jp/4s4Zl6ZR/3QOUK0VZ8Lte1T7DTWjniyT0DCAfhDjoLpzaia/58DV7VrBw==',
    }),
});

function runtimeVariant(entry, runtime) {
    if (runtime === 'node') return 'node';
    if (entry.manifest.variants[runtime]) return runtime;
    return 'default-script-runtime';
}

function createPackageProjection(entry, selectedVariant) {
    const variant = entry.manifest.variants[selectedVariant];
    const containsExecutableCode = variant.containsExecutableCode === true;
    const files = containsExecutableCode
        ? { 'backend/index.cjs': NODE_ENTRYPOINTS[entry.manifest.id] }
        : {};
    const fileDigests = Object.fromEntries(
        Object.entries(files).map(([name, content]) => [
            name,
            sha256Hex(content),
        ]),
    );
    return {
        schemaVersion: 1,
        manifest: entry.manifest,
        selectedVariant,
        variant,
        containsExecutableCode,
        containsInstallHook: false,
        files,
        fileDigests,
    };
}

export function findCatalogEntry(id) {
    return [...bundledExtensionCatalog, ...officialExtensionCatalog].find(
        (entry) => entry.manifest.id === id,
    );
}

export function listCatalogEntries() {
    return [...bundledExtensionCatalog, ...officialExtensionCatalog].map(
        (entry) => {
            const signedEntry = catalogPayload.entries.find(
                (candidate) =>
                    candidate.id === entry.manifest.id &&
                    candidate.version === entry.manifest.version,
            );
            return {
                id: entry.manifest.id,
                manifest: cloneExtensionValue(entry.manifest),
                distribution:
                    entry.distribution ||
                    entry.manifest.distribution ||
                    'bundled',
                source: entry.source,
                defaultEnabled: entry.defaultEnabled === true,
                manifestDigest: signedEntry?.manifestDigest || null,
                packageDigests: cloneExtensionValue(
                    signedEntry?.packageDigests || {},
                ),
            };
        },
    );
}

/** Build deterministic packages only for extensions shipped by the Host. */
export function createLocalOfficialPackage(id, runtime) {
    const entry = officialExtensionCatalog.find(
        (candidate) => candidate.manifest.id === id,
    );
    if (!entry) return null;
    const selectedVariant = runtimeVariant(entry, runtime);
    const variant = entry.manifest.variants[selectedVariant];
    const packageProjection = createPackageProjection(entry, selectedVariant);
    const { containsExecutableCode } = packageProjection;
    const packageDigest = extensionPackageDigest(packageProjection);
    const receipt = createDigestReceipt({
        manifest: entry.manifest,
        packageDigest,
        variant: selectedVariant,
        implementation: {
            id: variant.implementationId,
            abi: variant.implementationAbi,
            frontendAssetId: variant.frontendAssetId,
            entrypoint: containsExecutableCode
                ? 'backend/index.cjs'
                : undefined,
            lanes:
                embeddedExtensionImplementations[id]?.lanes ||
                entry.manifest.scriptExecutionLanes,
            containsExecutableCode,
        },
        now: RELEASED_AT,
    });
    const signedPayload = {
        ...packageProjection,
        packageDigest,
        receipt,
    };
    const envelopeDigest = sha256Hex(canonicalJson(signedPayload));
    const signature = OFFICIAL_PACKAGE_SIGNATURES[id];
    return {
        schemaVersion: 1,
        source: 'local-official-seed',
        manifest: cloneExtensionValue(entry.manifest),
        receipt,
        packageDigest,
        selectedVariant,
        payload: cloneExtensionValue(signedPayload),
        signature: {
            algorithm: 'ed25519',
            keyId: signature.keyId,
            digest: envelopeDigest,
            value: signature.variants[selectedVariant],
        },
    };
}

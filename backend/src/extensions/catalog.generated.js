/*
 * Deterministic catalog source for the first Extension Host iteration.
 *
 * The file name intentionally matches the future build-generated catalog.
 * Entries contain data/entrypoint keys only; they never contain an arbitrary
 * filesystem path or executable source supplied by a remote catalog.
 */
import configGeneratorManifest from './official-packages/org.substore.config-generator/manifest.json';
import configGeneratorReceiptProjection from './official-packages/org.substore.config-generator/receipt.json';
import configGeneratorEmbeddedMetadata from './official-packages/org.substore.config-generator/embedded.json';
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
const CONFIG_GENERATOR_RELEASE_KEY_ID =
    'substore-release-root-2026-08-config-generator-v4';
const CONFIG_GENERATOR_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8bbHIOo0ISnmcmnaYCeY5wGn7WwIS1X7A5fPKPGtajw=
-----END PUBLIC KEY-----
`;
const CONFIG_GENERATOR_NODE_PACKAGE_DIGEST =
    configGeneratorEmbeddedMetadata.packageDigest;
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
    'org.substore.config-generator': Object.freeze({
        keyId: CONFIG_GENERATOR_RELEASE_KEY_ID,
        variants: Object.freeze({
            node: 'RZAjxl0HELj3TbVTMyr+UrO0thPbbToZq8hpnpDOYu5iT6wjUSs/RnYtgWwstZp0eNHLPVSGVP2rkPbOifZMBw==',
            qx: 'gV2jFyD0uqrS9H3x8xS2ApHenRMU4ImgALY1UWCv0dnSJ2Qh6RvRxFbSw4SRJy8nXoNJpsFAkFmsDoSl09eZAQ==',
            loon: '0hWtL7rKZ6aPnux446k/LbcwbOo+D67XLSModtuSbKfWzkazWcuZ9BTRCXCk4cY8rUYbpNZry3dm/T7HGnSaBg==',
            surge: '/yBlCSDnLMDTXWkRZ0BV5ii2PY2puetRbDAjcUF61VxaLay0Gpgl/oIwUCWQkkNko5pJDMpR6+h4yR4cKhO0CQ==',
            'default-script-runtime':
                'G5b9BNwzFTEqP7i/J8pbNf2zzVMth3bB0D1RIoxmY0EWpR22GDSFNYAYEI7WMw4+ccdsf7wop852icGZ2447Cw==',
        }),
    }),
});

export const officialExtensionTrustedKeys = Object.freeze({
    [LEGACY_RELEASE_KEY_ID]: LEGACY_RELEASE_PUBLIC_KEY,
    [CURRENT_RELEASE_KEY_ID]: CURRENT_RELEASE_PUBLIC_KEY,
    [CONFIG_GENERATOR_RELEASE_KEY_ID]: CONFIG_GENERATOR_RELEASE_PUBLIC_KEY,
});
// Bind each trusted executable extension to its own release key set. Trusting
// a public key globally is not enough: without this additional identity
// binding, a key issued for one official extension could sign another
// allowlisted extension. New package versions may reuse an authorized key
// without requiring their manifest and package digest to be embedded in a new
// Host build; key rotation still requires an explicit Host update.
export const officialExtensionReleaseKeyIds = Object.freeze({
    'org.substore.config-generator': Object.freeze([
        CONFIG_GENERATOR_RELEASE_KEY_ID,
    ]),
    'org.substore.config-hosting': Object.freeze([CURRENT_RELEASE_KEY_ID]),
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
            normalizeExtensionManifest(configGeneratorManifest),
        ),
        receiptProjection: Object.freeze(
            cloneExtensionValue(configGeneratorReceiptProjection),
        ),
        distribution: 'trusted-official-package',
        source: 'local-official-seed',
        defaultEnabled: false,
    }),
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
    'org.substore.config-generator': Object.freeze({
        implementationAbi: configGeneratorEmbeddedMetadata.implementationAbi,
        artifactSha256: configGeneratorEmbeddedMetadata.artifactSha256,
        sourceTreeSha256: configGeneratorEmbeddedMetadata.sourceTreeSha256,
        lanes: Object.freeze(
            Object.fromEntries(
                Object.entries(configGeneratorEmbeddedMetadata.lanes).map(
                    ([laneId, lane]) => [
                        laneId,
                        Object.freeze({
                            product: lane.product,
                            implementationId: lane.implementationId,
                        }),
                    ],
                ),
            ),
        ),
    }),
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
    sequence: 3,
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
                                  entry.manifest.id ===
                                      'org.substore.config-generator' &&
                                  selectedVariant === 'node'
                                      ? CONFIG_GENERATOR_NODE_PACKAGE_DIGEST
                                      : extensionPackageDigest(
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
        keyId: CONFIG_GENERATOR_RELEASE_KEY_ID,
        digest: catalogDigest,
        value: 'YDdneqp3BakswDo8ww9NBqqGkbKuqvItaR1gGj0ODG5ZXPqyYGxAEQc61ZssO7xTm/1rFQGYk3HsLMExL9VaBw==',
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

/**
 * Build deterministic embedded/runtime packages. The config-generator Node
 * package is intentionally remote-only and must arrive through a verified
 * collection source; script runtimes keep a signed embedded receipt.
 */
export function createLocalOfficialPackage(id, runtime) {
    const entry = officialExtensionCatalog.find(
        (candidate) => candidate.manifest.id === id,
    );
    if (!entry) return null;
    if (id === 'org.substore.config-generator' && runtime === 'node') {
        return null;
    }
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

/*
 * Deterministic catalog source for the first Extension Host iteration.
 *
 * The file name intentionally matches the future build-generated catalog.
 * Entries contain data/entrypoint keys only; they never contain an arbitrary
 * filesystem path or executable source supplied by a remote catalog.
 */
import configGeneratorManifest from './config-generator/manifest.json';
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

const GENERATED_AT = '2026-08-07T00:00:00.000Z';
const RELEASED_AT = Date.parse(GENERATED_AT);
const CATALOG_EXPIRES_AT = Date.parse('2036-08-07T00:00:00.000Z');
const OFFICIAL_RELEASE_KEY_ID = 'substore-release-root-2026-01';
const OFFICIAL_RELEASE_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuY9XBfpDWyzzWwgUTMJAZVOSE+dud0zndNIwqav59DM=
-----END PUBLIC KEY-----
`;
const OFFICIAL_PACKAGE_SIGNATURES = Object.freeze({
    node: 'Q6ZAuyuIZAnTyWDLtqmrGg/zOy/YCUNDnLREsl9zrvG8/ZRPs85FAkwNV4Kf+XroekO/k61YRF16gh3+bUfaDA==',
    qx: 'FCkSe5mGkARNO7zIqvqCqfnWTJy6qWNMS98jjILRL+wP8qQ5Cw1js+3lC7mRbt0SYKMmkfHsyHxJMp/RnKX8Dw==',
    loon: '+gb00sgsyU5uZ/qdIdVCjTBrWBj6awAoT3G50siNZ58x7rwnf2+VVhx8fCyYWFI4uBt9B4oM+rx/a3Cj9lPuDQ==',
    surge: '48I3GlWnVLrkY2vxNAfampi4iwU9Kk0rPXUcoFoBbj3G92zXQdSYCaZv3UyvgW3i1TAKd6mlZ1z4cJakkxt5DA==',
    'default-script-runtime':
        'cVsr5056ogfgSeyzX/otknrTPMT5UchjT9ZGUXAcXU1ca96CDXPET70Yv5yAVNK0sQr0IY6snm/tK3iQHhsdDw==',
});

export const officialExtensionTrustedKeys = Object.freeze({
    [OFFICIAL_RELEASE_KEY_ID]: OFFICIAL_RELEASE_PUBLIC_KEY,
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

export const bundledExtensionCatalog = Object.freeze([
    Object.freeze({
        manifest: Object.freeze(
            normalizeExtensionManifest(configGeneratorManifest),
        ),
        entrypointKey: 'configGeneratorBackend',
        defaultEnabled: true,
        source: 'bundled',
    }),
]);

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
    sequence: 1,
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
        keyId: OFFICIAL_RELEASE_KEY_ID,
        digest: catalogDigest,
        value: 'IqG6GwgMWDOtPGyd6pvNLlUA1mw00wkwW8Mqq5ukQKdmOVoZn28S1S+5idlT79KWb6z13j4Medb9cqDlcI6NBg==',
    }),
});

function runtimeVariant(runtime) {
    if (runtime === 'node') return 'node';
    if (configHostingManifest.variants[runtime]) return runtime;
    return 'default-script-runtime';
}

function createPackageProjection(entry, selectedVariant) {
    const variant = entry.manifest.variants[selectedVariant];
    const containsExecutableCode = selectedVariant === 'node';
    const files = containsExecutableCode
        ? { 'backend/index.cjs': CONFIG_HOSTING_NODE_ENTRYPOINT }
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
 * Build the deterministic local official package used by the first installer
 * iteration. Node variants contain a narrowly allowlisted CJS trampoline; the
 * signed envelope binds the exact manifest, variant, file map and receipt.
 */
export function createLocalOfficialPackage(id, runtime) {
    const entry = officialExtensionCatalog.find(
        (candidate) => candidate.manifest.id === id,
    );
    if (!entry) return null;
    const selectedVariant = runtimeVariant(runtime);
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
            keyId: OFFICIAL_RELEASE_KEY_ID,
            digest: envelopeDigest,
            value: OFFICIAL_PACKAGE_SIGNATURES[selectedVariant],
        },
    };
}

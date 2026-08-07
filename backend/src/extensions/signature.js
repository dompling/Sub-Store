import { canonicalJson, cloneExtensionValue } from './contracts';
import { hex_md5 } from '@/vendor/md5';

const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

function nodeCrypto() {
    // Keep Node-only imports out of proxy-app bundles. This mirrors the
    // established dynamic require convention used by open-api.js.
    try {
        if (eval('typeof process === "undefined"')) return null;
        return eval('require("crypto")');
    } catch (e) {
        return null;
    }
}

function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (typeof value === 'string') {
        if (typeof TextEncoder !== 'undefined') {
            return new TextEncoder().encode(value);
        }
        const crypto = nodeCrypto();
        if (crypto) return Uint8Array.from(Buffer.from(value, 'utf8'));
    }
    if (value && typeof value.byteLength === 'number') {
        return new Uint8Array(value);
    }
    return toBytes(`${value ?? ''}`);
}

export function sha256Hex(value) {
    const crypto = nodeCrypto();
    if (crypto) {
        return crypto.createHash('sha256').update(toBytes(value)).digest('hex');
    }
    // Proxy script hosts do not expose a synchronous SHA-256 primitive. Do not
    // label the fallback as SHA-256; callers that require a cryptographic
    // package verification fail closed in that environment. MD5 is retained
    // solely for deterministic local catalog diagnostics.
    return null;
}

export function isSha256Digest(value) {
    return typeof value === 'string' && SHA256_HEX_RE.test(value);
}

/**
 * The content-addressed package projection deliberately excludes the receipt
 * and packageDigest fields. The receipt points at this digest, while the signed
 * envelope contains both the projection and the resulting receipt without
 * introducing a circular hash dependency.
 */
export function extensionPackageProjection(payload = {}) {
    return {
        schemaVersion: payload.schemaVersion,
        manifest: cloneExtensionValue(payload.manifest),
        selectedVariant: payload.selectedVariant,
        variant: cloneExtensionValue(payload.variant),
        containsExecutableCode: payload.containsExecutableCode === true,
        containsInstallHook: payload.containsInstallHook === true,
        files: cloneExtensionValue(payload.files || {}),
        fileDigests: cloneExtensionValue(payload.fileDigests || {}),
    };
}

export function extensionPackageDigest(payload) {
    return sha256Hex(canonicalJson(extensionPackageProjection(payload)));
}

export function diagnosticDigest(value) {
    return hex_md5(typeof value === 'string' ? value : canonicalJson(value));
}

function equalText(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string') return false;
    const crypto = nodeCrypto();
    if (crypto) {
        const a = Buffer.from(left);
        const b = Buffer.from(right);
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    }
    return left === right;
}

function decodeBase64(value) {
    const crypto = nodeCrypto();
    if (crypto) return Buffer.from(value, 'base64');
    if (typeof atob === 'function') {
        const raw = atob(value);
        return Uint8Array.from(raw, (char) => char.charCodeAt(0));
    }
    return null;
}

/**
 * Verify a signed catalog envelope without loading or evaluating package
 * code. Ed25519 is the production path; digest-only envelopes are explicitly
 * opt-in for local, offline development packages and are never treated as a
 * publisher signature.
 */
export function verifySignedEnvelope(
    envelope,
    {
        trustedKeys = {},
        revokedKeyIds = [],
        now = Date.now(),
        allowDigestOnly = false,
    } = {},
) {
    const result = {
        valid: false,
        trust: 'untrusted',
        digest: null,
        keyId: envelope?.signature?.keyId || null,
        reasonCode: null,
    };
    if (!envelope || typeof envelope !== 'object' || !envelope.payload) {
        result.reasonCode = 'EXTENSION_SIGNATURE_ENVELOPE_INVALID';
        return result;
    }
    const signature = envelope.signature;
    if (!signature || typeof signature !== 'object') {
        result.reasonCode = 'EXTENSION_SIGNATURE_MISSING';
        return result;
    }
    if (Number.isFinite(envelope.expiresAt) && now > envelope.expiresAt) {
        result.reasonCode = 'EXTENSION_CATALOG_EXPIRED';
        return result;
    }
    const serialized = canonicalJson(envelope.payload);
    const digest = sha256Hex(serialized);
    result.digest = digest;
    if (!digest) {
        result.reasonCode = 'EXTENSION_CRYPTO_UNAVAILABLE';
        return result;
    }
    if (signature.digest && !equalText(signature.digest, digest)) {
        result.reasonCode = 'EXTENSION_DIGEST_MISMATCH';
        return result;
    }

    const keyId = signature.keyId;
    if (keyId && revokedKeyIds.includes(keyId)) {
        result.reasonCode = 'EXTENSION_SIGNING_KEY_REVOKED';
        return result;
    }

    if (signature.algorithm === 'sha256-digest') {
        if (
            !allowDigestOnly ||
            !equalText(signature.value || signature.digest, digest)
        ) {
            result.reasonCode = 'EXTENSION_DIGEST_SIGNATURE_UNTRUSTED';
            return result;
        }
        result.valid = true;
        result.trust = 'integrity-only';
        return result;
    }

    if (signature.algorithm !== 'ed25519' || !keyId) {
        result.reasonCode = 'EXTENSION_SIGNATURE_ALGORITHM_UNSUPPORTED';
        return result;
    }
    const publicKey = trustedKeys[keyId];
    const crypto = nodeCrypto();
    const signatureBytes = decodeBase64(signature.value || '');
    if (!publicKey || !crypto || !signatureBytes) {
        result.reasonCode = 'EXTENSION_SIGNING_KEY_UNTRUSTED';
        return result;
    }
    try {
        const verified = crypto.verify(
            null,
            Buffer.from(serialized),
            publicKey,
            Buffer.from(signatureBytes),
        );
        if (!verified) {
            result.reasonCode = 'EXTENSION_SIGNATURE_INVALID';
            return result;
        }
    } catch (e) {
        result.reasonCode = 'EXTENSION_SIGNATURE_INVALID';
        return result;
    }
    result.valid = true;
    result.trust = 'trusted';
    return result;
}

export function verifyManifestDigest(manifest, expectedDigest) {
    const digest = sha256Hex(canonicalJson(manifest));
    return {
        valid: Boolean(
            digest && expectedDigest && equalText(digest, expectedDigest),
        ),
        digest,
    };
}

export function createDigestReceipt({
    manifest,
    packageDigest,
    variant,
    publisher = manifest?.publisher,
    implementation = {},
    now = Date.now(),
}) {
    const manifestDigest = sha256Hex(canonicalJson(manifest));
    const receipt = {
        schemaVersion: 1,
        extensionId: manifest.id,
        version: manifest.version,
        publisher: cloneExtensionValue(publisher),
        selectedVariant: variant,
        manifestDigest,
        packageDigest: packageDigest || manifestDigest,
        implementation: cloneExtensionValue(implementation),
        installedAt: now,
    };
    receipt.receiptDigest = sha256Hex(canonicalJson(receipt));
    return receipt;
}

export function verifyReceipt(
    receipt,
    manifest,
    { expectedVariant, expectedPackageDigest, expectedImplementation } = {},
) {
    const result = {
        valid: false,
        reasonCode: null,
        manifestDigest: null,
    };
    if (!receipt || receipt.schemaVersion !== 1 || !manifest) {
        result.reasonCode = 'EXTENSION_RECEIPT_INVALID';
        return result;
    }
    if (
        receipt.extensionId !== manifest.id ||
        receipt.version !== manifest.version
    ) {
        result.reasonCode = 'EXTENSION_RECEIPT_ID_VERSION_MISMATCH';
        return result;
    }
    if (
        canonicalJson(receipt.publisher || null) !==
        canonicalJson(manifest.publisher || null)
    ) {
        result.reasonCode = 'EXTENSION_RECEIPT_PUBLISHER_MISMATCH';
        return result;
    }
    if (expectedVariant && receipt.selectedVariant !== expectedVariant) {
        result.reasonCode = 'EXTENSION_RECEIPT_VARIANT_MISMATCH';
        return result;
    }
    if (!isSha256Digest(receipt.manifestDigest)) {
        result.reasonCode = 'EXTENSION_RECEIPT_MANIFEST_DIGEST_INVALID';
        return result;
    }
    if (!isSha256Digest(receipt.packageDigest)) {
        result.reasonCode = 'EXTENSION_RECEIPT_PACKAGE_DIGEST_INVALID';
        return result;
    }
    if (
        expectedPackageDigest &&
        receipt.packageDigest !== expectedPackageDigest
    ) {
        result.reasonCode = 'EXTENSION_RECEIPT_PACKAGE_DIGEST_MISMATCH';
        return result;
    }
    const digestResult = verifyManifestDigest(manifest, receipt.manifestDigest);
    result.manifestDigest = digestResult.digest;
    if (!digestResult.valid) {
        result.reasonCode = 'EXTENSION_RECEIPT_MANIFEST_DIGEST_MISMATCH';
        return result;
    }
    if (expectedImplementation) {
        const actual = receipt.implementation || {};
        for (const field of [
            'id',
            'abi',
            'frontendAssetId',
            'entrypoint',
            'containsExecutableCode',
        ]) {
            if (
                canonicalJson(actual[field]) !==
                canonicalJson(expectedImplementation[field])
            ) {
                result.reasonCode = 'EXTENSION_RECEIPT_IMPLEMENTATION_MISMATCH';
                return result;
            }
        }
        if (
            canonicalJson(actual.lanes || {}) !==
            canonicalJson(expectedImplementation.lanes || {})
        ) {
            result.reasonCode = 'EXTENSION_RECEIPT_IMPLEMENTATION_MISMATCH';
            return result;
        }
    }
    if (!isSha256Digest(receipt.receiptDigest)) {
        result.reasonCode = 'EXTENSION_RECEIPT_DIGEST_INVALID';
        return result;
    }
    const { receiptDigest, ...unsigned } = receipt;
    const calculated = sha256Hex(canonicalJson(unsigned));
    if (!calculated || !equalText(calculated, receiptDigest)) {
        result.reasonCode = 'EXTENSION_RECEIPT_DIGEST_MISMATCH';
        return result;
    }
    result.valid = true;
    return result;
}

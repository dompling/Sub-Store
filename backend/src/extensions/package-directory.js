import { canonicalJson, cloneExtensionValue } from './contracts';
import { extensionPackageDigest, isSha256Digest, sha256Hex } from './signature';
import {
    MAX_PACKAGE_BYTES,
    MAX_PACKAGE_FILE_BYTES,
    MAX_PACKAGE_FILES,
} from './package-store';

export const EXTENSION_DIRECTORY_MIME =
    'application/vnd.substore.extension-directory+json';
export const EXTENSION_DIRECTORY_FORMAT = 'substore-extension-directory-v1';

const DIRECTORY_SCHEMA_VERSION = 1;
const METADATA_FILES = new Set([
    'manifest.json',
    'receipt.json',
    'package.json',
]);
const DANGEROUS_SEGMENTS = new Set(['__proto__', 'constructor', 'prototype']);
const MAX_PATH_BYTES = 1024;
const MAX_SEGMENT_BYTES = 255;
const WINDOWS_ABSOLUTE_RE = /^[a-zA-Z]:\//;

function errorWithCode(code, message, details, statusCode = 400) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    if (details !== undefined) error.details = details;
    return error;
}

function isRecord(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
        return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
}

function utf8Bytes(value) {
    if (typeof Buffer !== 'undefined') {
        return Buffer.byteLength(value, 'utf8');
    }
    if (typeof TextEncoder === 'function') {
        return new TextEncoder().encode(value).byteLength;
    }
    return unescape(encodeURIComponent(value)).length;
}

function containsControlCharacter(value) {
    for (const character of value) {
        const codePoint = character.codePointAt(0);
        if (codePoint <= 0x1f || codePoint === 0x7f) return true;
    }
    return false;
}

function assertSafePath(value) {
    if (
        typeof value !== 'string' ||
        !value ||
        value.startsWith('/') ||
        WINDOWS_ABSOLUTE_RE.test(value) ||
        value.includes('\\') ||
        containsControlCharacter(value) ||
        utf8Bytes(value) > MAX_PATH_BYTES
    ) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_PATH_INVALID',
            'Extension directory contains an unsafe path',
            { path: value },
        );
    }
    const segments = value.split('/');
    if (
        segments.some(
            (segment) =>
                !segment ||
                segment === '.' ||
                segment === '..' ||
                utf8Bytes(segment) > MAX_SEGMENT_BYTES ||
                DANGEROUS_SEGMENTS.has(segment.toLowerCase()),
        )
    ) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_PATH_INVALID',
            'Extension directory contains an unsafe path segment',
            { path: value },
        );
    }
    return value;
}

function parseMetadata(files, name) {
    if (!Object.prototype.hasOwnProperty.call(files, name)) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_METADATA_MISSING',
            `Extension directory is missing ${name}`,
            { file: name },
        );
    }
    let value;
    try {
        value = JSON.parse(files[name]);
    } catch (cause) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_METADATA_INVALID',
            `Extension directory ${name} is not valid JSON`,
            { file: name, reason: cause?.message },
        );
    }
    if (!isRecord(value)) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_METADATA_INVALID',
            `Extension directory ${name} must contain a JSON object`,
            { file: name },
        );
    }
    return value;
}

/**
 * Convert a browser-selected text directory into the exact signed package
 * envelope consumed by ExtensionManager. The transport may describe where it
 * came from, but source and payloadDigest are deliberately recomputed/ignored.
 */
export function normalizeExtensionPackageDirectory(
    directory,
    { expectedExtensionId } = {},
) {
    if (!isRecord(directory) || directory.schemaVersion !== 1) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_SCHEMA_INVALID',
            'Extension directory schema is unsupported',
            { schemaVersion: directory?.schemaVersion },
        );
    }
    if (directory.format !== EXTENSION_DIRECTORY_FORMAT) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_FORMAT_INVALID',
            'Extension directory format is unsupported',
            { format: directory.format },
        );
    }
    if (!isRecord(directory.files)) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_FILES_INVALID',
            'Extension directory files must be a path-to-text map',
        );
    }

    const files = Object.create(null);
    const collisionIndex = new Map();
    for (const [path, content] of Object.entries(directory.files)) {
        assertSafePath(path);
        const collisionKey = path.normalize('NFC').toLowerCase();
        const existing = collisionIndex.get(collisionKey);
        if (existing && existing !== path) {
            throw errorWithCode(
                'EXTENSION_DIRECTORY_PATH_COLLISION',
                'Extension directory contains colliding paths',
                { paths: [existing, path] },
            );
        }
        collisionIndex.set(collisionKey, path);
        if (typeof content !== 'string') {
            throw errorWithCode(
                'EXTENSION_DIRECTORY_TEXT_REQUIRED',
                'Extension directory version 1 accepts UTF-8 text files only',
                { path },
            );
        }
        const byteLength = utf8Bytes(content);
        if (byteLength > MAX_PACKAGE_FILE_BYTES) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_FILE_LIMIT_EXCEEDED',
                'Extension directory contains an oversized file',
                {
                    path,
                    byteLength,
                    maxFileBytes: MAX_PACKAGE_FILE_BYTES,
                },
                413,
            );
        }
        files[path] = content;
    }
    if (Object.keys(files).length > MAX_PACKAGE_FILES + METADATA_FILES.size) {
        throw errorWithCode(
            'EXTENSION_PACKAGE_FILE_LIMIT_EXCEEDED',
            'Extension directory contains too many files',
            {
                fileCount: Object.keys(files).length,
                maxFiles: MAX_PACKAGE_FILES + METADATA_FILES.size,
            },
            413,
        );
    }

    const manifest = parseMetadata(files, 'manifest.json');
    const receipt = parseMetadata(files, 'receipt.json');
    const packageMetadata = parseMetadata(files, 'package.json');
    const extensionId = manifest.id;
    if (
        typeof extensionId !== 'string' ||
        !extensionId ||
        receipt.extensionId !== extensionId ||
        (expectedExtensionId && expectedExtensionId !== extensionId)
    ) {
        throw errorWithCode(
            'EXTENSION_PACKAGE_ID_MISMATCH',
            'Extension route, manifest and receipt IDs must match',
            {
                expectedExtensionId: expectedExtensionId || null,
                manifestExtensionId: extensionId || null,
                receiptExtensionId: receipt.extensionId || null,
            },
            409,
        );
    }
    if (
        packageMetadata.schemaVersion !== DIRECTORY_SCHEMA_VERSION ||
        typeof packageMetadata.selectedVariant !== 'string' ||
        !packageMetadata.selectedVariant ||
        !isRecord(packageMetadata.variant) ||
        typeof packageMetadata.containsExecutableCode !== 'boolean' ||
        typeof packageMetadata.containsInstallHook !== 'boolean' ||
        !isRecord(packageMetadata.fileDigests) ||
        !isRecord(packageMetadata.signature) ||
        !isSha256Digest(packageMetadata.packageDigest)
    ) {
        throw errorWithCode(
            'EXTENSION_DIRECTORY_METADATA_INVALID',
            'Extension directory package metadata is incomplete',
        );
    }

    const payloadFiles = Object.create(null);
    const fileDigests = Object.create(null);
    let totalBytes = 0;
    for (const [path, content] of Object.entries(files)) {
        if (METADATA_FILES.has(path)) continue;
        const byteLength = utf8Bytes(content);
        totalBytes += byteLength;
        if (
            byteLength > MAX_PACKAGE_FILE_BYTES ||
            totalBytes > MAX_PACKAGE_BYTES
        ) {
            throw errorWithCode(
                'EXTENSION_PACKAGE_FILE_LIMIT_EXCEEDED',
                'Extension directory exceeds package size limits',
                {
                    path,
                    byteLength,
                    totalBytes,
                    maxFileBytes: MAX_PACKAGE_FILE_BYTES,
                    maxPackageBytes: MAX_PACKAGE_BYTES,
                },
                413,
            );
        }
        payloadFiles[path] = content;
        fileDigests[path] = sha256Hex(content);
    }
    if (Object.keys(payloadFiles).length > MAX_PACKAGE_FILES) {
        throw errorWithCode(
            'EXTENSION_PACKAGE_FILE_LIMIT_EXCEEDED',
            'Extension directory contains too many package files',
            {
                fileCount: Object.keys(payloadFiles).length,
                maxFiles: MAX_PACKAGE_FILES,
            },
            413,
        );
    }

    const normalizedFiles = Object.fromEntries(Object.entries(payloadFiles));
    const normalizedDigests = Object.fromEntries(Object.entries(fileDigests));
    if (
        canonicalJson(packageMetadata.fileDigests) !==
        canonicalJson(normalizedDigests)
    ) {
        throw errorWithCode(
            'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH',
            'Extension directory file digests do not match package metadata',
            undefined,
            409,
        );
    }

    const packagePayload = {
        schemaVersion: DIRECTORY_SCHEMA_VERSION,
        manifest: cloneExtensionValue(manifest),
        selectedVariant: packageMetadata.selectedVariant,
        variant: cloneExtensionValue(packageMetadata.variant),
        containsExecutableCode: packageMetadata.containsExecutableCode === true,
        containsInstallHook: packageMetadata.containsInstallHook === true,
        files: normalizedFiles,
        fileDigests: normalizedDigests,
    };
    const packageDigest = extensionPackageDigest(packagePayload);
    if (
        !packageDigest ||
        packageDigest !== packageMetadata.packageDigest ||
        receipt.packageDigest !== packageDigest
    ) {
        throw errorWithCode(
            'EXTENSION_PACKAGE_DIGEST_INVALID',
            'Extension directory package digest does not match its contents',
            {
                expectedPackageDigest: packageMetadata.packageDigest,
                actualPackageDigest: packageDigest,
                receiptPackageDigest: receipt.packageDigest || null,
            },
            409,
        );
    }

    const signedPayload = {
        ...packagePayload,
        packageDigest,
        receipt: cloneExtensionValue(receipt),
    };
    const packageInput = {
        schemaVersion: DIRECTORY_SCHEMA_VERSION,
        source: 'local-upload',
        manifest: cloneExtensionValue(manifest),
        receipt: cloneExtensionValue(receipt),
        packageDigest,
        selectedVariant: packageMetadata.selectedVariant,
        payload: signedPayload,
        signature: cloneExtensionValue(packageMetadata.signature),
    };

    return {
        packageInput,
        summary: {
            extensionId,
            manifest: cloneExtensionValue(manifest),
            receipt: cloneExtensionValue(receipt),
            selectedVariant: packageMetadata.selectedVariant,
            packageDigest,
            fileCount: Object.keys(normalizedFiles).length,
            totalBytes,
        },
    };
}

export default normalizeExtensionPackageDirectory;

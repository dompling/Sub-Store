/*
 * Community extension source handling.
 *
 * Sources are deliberately data-only.  This module fetches JSON documents,
 * normalizes their catalog entries and applies the network boundary used by
 * the Extension Host.  It never evaluates a downloaded file and it does not
 * accept credentials embedded in source URLs.
 */
import {
    canonicalJson,
    cloneExtensionValue,
    normalizeExtensionManifest,
} from './contracts';
import { diagnosticDigest, isSha256Digest, sha256Hex } from './signature';

export const EXTENSION_SOURCE_SCHEMA_VERSION = 1;
export const MAX_EXTENSION_SOURCE_BYTES = 4 * 1024 * 1024;
export const MAX_EXTENSION_SOURCE_ENTRIES = 128;
export const MAX_EXTENSION_SOURCE_REDIRECTS = 3;
export const MAX_EXTENSION_SOURCE_URL_LENGTH = 2048;
export const SOURCE_EXECUTABLE_DISTRIBUTION = 'source-executable';

function nodeModule(name) {
    try {
        if (eval('typeof process === "undefined"')) return null;
        return eval(`require("${name}")`);
    } catch (error) {
        return null;
    }
}

function sourceError(code, message, details = {}, statusCode = 409) {
    const error = new Error(message || code);
    error.code = code;
    error.details = details;
    error.statusCode = statusCode;
    return error;
}

function isLoopbackHost(hostname) {
    const value = `${hostname || ''}`.toLowerCase().replace(/^\[|\]$/g, '');
    return (
        value === 'localhost' ||
        value === 'localhost.localdomain' ||
        value === '::1' ||
        value === '127.0.0.1' ||
        value === '0.0.0.0'
    );
}

function assertLoopbackBoundary(parsed, allowLoopback) {
    if (isLoopbackHost(parsed.hostname) && !allowLoopback) {
        throw sourceError(
            'EXTENSION_SOURCE_SSRF_BLOCKED',
            'Remote extension sources cannot access loopback targets',
            { hostname: parsed.hostname },
            403,
        );
    }
}

function ipv4ToNumber(value) {
    const parts = `${value}`.split('.').map((part) => Number(part));
    if (
        parts.length !== 4 ||
        parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)
    )
        return null;
    return parts.reduce((result, part) => result * 256 + part, 0);
}

function isProxySyntheticIpv4Address(address) {
    const value = ipv4ToNumber(address);
    return (
        value !== null &&
        value >= ipv4ToNumber('198.18.0.0') &&
        value <= ipv4ToNumber('198.19.255.255')
    );
}

function isSafeHttpsProxySyntheticResolution(parsed, address) {
    const net = nodeModule('net');
    return (
        parsed.protocol === 'https:' &&
        !net?.isIP?.(parsed.hostname) &&
        isProxySyntheticIpv4Address(address)
    );
}

function isPrivateAddress(address) {
    const net = nodeModule('net');
    const kind = net?.isIP?.(address) || 0;
    if (kind === 4) {
        const value = ipv4ToNumber(address);
        if (value === null) return true;
        const ranges = [
            [ipv4ToNumber('0.0.0.0'), ipv4ToNumber('0.255.255.255')],
            [ipv4ToNumber('10.0.0.0'), ipv4ToNumber('10.255.255.255')],
            [ipv4ToNumber('100.64.0.0'), ipv4ToNumber('100.127.255.255')],
            [ipv4ToNumber('127.0.0.0'), ipv4ToNumber('127.255.255.255')],
            [ipv4ToNumber('169.254.0.0'), ipv4ToNumber('169.254.255.255')],
            [ipv4ToNumber('172.16.0.0'), ipv4ToNumber('172.31.255.255')],
            [ipv4ToNumber('192.0.0.0'), ipv4ToNumber('192.0.0.255')],
            [ipv4ToNumber('192.168.0.0'), ipv4ToNumber('192.168.255.255')],
            [ipv4ToNumber('198.18.0.0'), ipv4ToNumber('198.19.255.255')],
            [ipv4ToNumber('198.51.100.0'), ipv4ToNumber('198.51.100.255')],
            [ipv4ToNumber('203.0.113.0'), ipv4ToNumber('203.0.113.255')],
            [ipv4ToNumber('224.0.0.0'), ipv4ToNumber('255.255.255.255')],
        ];
        return ranges.some(([start, end]) => value >= start && value <= end);
    }
    if (kind === 6) {
        const normalized = `${address}`.toLowerCase();
        return (
            normalized === '::' ||
            normalized === '::1' ||
            normalized.startsWith('fc') ||
            normalized.startsWith('fd') ||
            normalized.startsWith('fe8') ||
            normalized.startsWith('fe9') ||
            normalized.startsWith('fea') ||
            normalized.startsWith('feb') ||
            normalized.startsWith('ff') ||
            normalized.startsWith('::ffff:')
        );
    }
    return false;
}

function assertNoUrlCredentials(parsed) {
    if (parsed.username || parsed.password) {
        throw sourceError(
            'EXTENSION_SOURCE_CREDENTIALS_FORBIDDEN',
            'Extension source URLs must not contain username or password credentials',
            { origin: `${parsed.protocol}//${parsed.host}` },
            400,
        );
    }
}

/** Normalize direct JSON URLs and GitHub blob/raw links to a stable URL. */
export function normalizeExtensionSourceUrl(rawValue) {
    const raw = `${rawValue || ''}`.trim();
    if (!raw || raw.length > MAX_EXTENSION_SOURCE_URL_LENGTH) {
        throw sourceError(
            'EXTENSION_SOURCE_URL_INVALID',
            'Extension source URL is empty or too long',
            { maxLength: MAX_EXTENSION_SOURCE_URL_LENGTH },
            400,
        );
    }
    let parsed;
    try {
        parsed = new URL(raw);
    } catch (error) {
        throw sourceError(
            'EXTENSION_SOURCE_URL_INVALID',
            'Extension source URL is invalid',
            {},
            400,
        );
    }
    assertNoUrlCredentials(parsed);
    const protocol = parsed.protocol.toLowerCase();
    if (protocol !== 'https:' && protocol !== 'http:') {
        throw sourceError(
            'EXTENSION_SOURCE_PROTOCOL_FORBIDDEN',
            'Extension source URL must use HTTP(S)',
            { protocol },
            400,
        );
    }
    if (protocol === 'http:' && !isLoopbackHost(parsed.hostname)) {
        throw sourceError(
            'EXTENSION_SOURCE_HTTPS_REQUIRED',
            'Non-loopback extension sources must use HTTPS',
            { hostname: parsed.hostname },
            400,
        );
    }

    const githubHost = parsed.hostname.toLowerCase();
    const parts = parsed.pathname.split('/').filter(Boolean);
    if (
        githubHost === 'github.com' &&
        parts.length >= 5 &&
        (parts[2] === 'blob' || parts[2] === 'raw')
    ) {
        const search = parsed.search;
        const owner = parts[0];
        const repo = parts[1];
        const ref = parts[3];
        const file = parts.slice(4).join('/');
        parsed = new URL(
            `https://raw.githubusercontent.com/${owner}/${repo}/${ref}/${file}`,
        );
        // GitHub query parameters can carry a channel or immutable version.
        // Retain them while intentionally dropping fragments.
        parsed.search = search;
    }
    const rawParts = parsed.pathname.split('/').filter(Boolean);
    if (
        parsed.hostname.toLowerCase() === 'raw.githubusercontent.com' &&
        rawParts.length >= 6 &&
        rawParts[2] === 'refs' &&
        rawParts[3] === 'heads' &&
        (rawParts[4] === 'main' || rawParts[4] === 'master')
    ) {
        parsed.pathname = `/${[
            rawParts[0],
            rawParts[1],
            rawParts[4],
            ...rawParts.slice(5),
        ].join('/')}`;
    }
    parsed.hash = '';
    return parsed.toString();
}

export function extensionSourceId(url) {
    return `source-${sha256Hex(url) || diagnosticDigest(url)}`;
}

function nodeFetch() {
    if (typeof fetch === 'function') return fetch;
    const undici = nodeModule('undici');
    return undici?.fetch || null;
}

function assertDeclaredResponseBodySize(response) {
    const declared = Number(response?.headers?.get?.('content-length'));
    if (Number.isFinite(declared) && declared > MAX_EXTENSION_SOURCE_BYTES) {
        throw sourceError(
            'EXTENSION_SOURCE_TOO_LARGE',
            'Extension source response exceeds the size limit',
            { maxBytes: MAX_EXTENSION_SOURCE_BYTES },
            413,
        );
    }
}

function assertResponseBodySize(response, body) {
    assertDeclaredResponseBodySize(response);
    const bytes =
        typeof body === 'string'
            ? Buffer.byteLength(body, 'utf8')
            : body?.byteLength || 0;
    if (bytes > MAX_EXTENSION_SOURCE_BYTES) {
        throw sourceError(
            'EXTENSION_SOURCE_TOO_LARGE',
            'Extension source response exceeds the size limit',
            { maxBytes: MAX_EXTENSION_SOURCE_BYTES },
            413,
        );
    }
}

async function readResponseBody(response) {
    assertDeclaredResponseBodySize(response);
    const reader = response?.body?.getReader?.();
    if (!reader) {
        const body = await response.text();
        assertResponseBodySize(response, body);
        return body;
    }
    const chunks = [];
    let totalBytes = 0;
    let streamComplete = false;
    while (!streamComplete) {
        const { done, value } = await reader.read();
        streamComplete = done;
        if (streamComplete) break;
        const chunk =
            value instanceof Uint8Array ? value : new Uint8Array(value || 0);
        totalBytes += chunk.byteLength;
        if (totalBytes > MAX_EXTENSION_SOURCE_BYTES) {
            try {
                await reader.cancel();
            } catch (error) {
                // The size error is authoritative even when stream cleanup
                // fails on an already-closed response.
            }
            throw sourceError(
                'EXTENSION_SOURCE_TOO_LARGE',
                'Extension source response exceeds the size limit',
                { maxBytes: MAX_EXTENSION_SOURCE_BYTES },
                413,
            );
        }
        chunks.push(chunk);
    }
    const bytes = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    if (typeof TextDecoder === 'function')
        return new TextDecoder().decode(bytes);
    const buffer = nodeModule('buffer')?.Buffer;
    if (buffer) return buffer.from(bytes).toString('utf8');
    throw sourceError(
        'EXTENSION_SOURCE_FETCH_UNAVAILABLE',
        'UTF-8 response decoding is unavailable',
        {},
        503,
    );
}

async function assertSafeNetworkTarget(
    url,
    { skipDns = false, allowLoopback = false } = {},
) {
    const parsed = new URL(url);
    assertNoUrlCredentials(parsed);
    if (parsed.protocol === 'http:' && !isLoopbackHost(parsed.hostname)) {
        throw sourceError(
            'EXTENSION_SOURCE_HTTPS_REQUIRED',
            'Non-loopback extension sources must use HTTPS',
            { hostname: parsed.hostname },
            400,
        );
    }
    assertLoopbackBoundary(parsed, allowLoopback);
    if (isLoopbackHost(parsed.hostname)) return;
    const net = nodeModule('net');
    if (net?.isIP?.(parsed.hostname) && isPrivateAddress(parsed.hostname)) {
        throw sourceError(
            'EXTENSION_SOURCE_SSRF_BLOCKED',
            'Extension source target resolves to a private network address',
            { hostname: parsed.hostname },
            403,
        );
    }
    if (skipDns) return;
    const dns = nodeModule('dns');
    try {
        const addresses = await dns.promises.lookup(parsed.hostname, {
            all: true,
            verbatim: true,
        });
        if (
            !addresses?.length ||
            addresses.some(
                (item) =>
                    isPrivateAddress(item.address) &&
                    !isSafeHttpsProxySyntheticResolution(parsed, item.address),
            )
        ) {
            throw sourceError(
                'EXTENSION_SOURCE_SSRF_BLOCKED',
                'Extension source target resolves to a private network address',
                { hostname: parsed.hostname },
                403,
            );
        }
    } catch (error) {
        if (error?.code?.startsWith('EXTENSION_SOURCE_')) throw error;
        throw sourceError(
            'EXTENSION_SOURCE_DNS_FAILED',
            'Extension source hostname could not be resolved',
            { hostname: parsed.hostname },
            502,
        );
    }
}

function parseResponseHeaders(response) {
    return {
        contentType: response?.headers?.get?.('content-type') || null,
        etag: response?.headers?.get?.('etag') || null,
        lastModified: response?.headers?.get?.('last-modified') || null,
    };
}

/** Fetch a JSON source document with bounded redirects and response size. */
export async function fetchExtensionSourceDocument(
    rawUrl,
    { fetcher, timeoutMs = 10000 } = {},
) {
    let currentUrl = normalizeExtensionSourceUrl(rawUrl);
    // Loopback is a narrow, explicit development exception. A remote source
    // must not acquire that privilege through redirects.
    const allowLoopback = isLoopbackHost(new URL(currentUrl).hostname);
    const request = fetcher || nodeFetch();
    if (typeof request !== 'function')
        throw sourceError(
            'EXTENSION_SOURCE_FETCH_UNAVAILABLE',
            'Node fetch is unavailable',
            {},
            503,
        );
    for (
        let redirect = 0;
        redirect <= MAX_EXTENSION_SOURCE_REDIRECTS;
        redirect += 1
    ) {
        await assertSafeNetworkTarget(currentUrl, {
            skipDns: Boolean(fetcher),
            allowLoopback,
        });
        let response;
        const controller =
            typeof AbortController === 'function'
                ? new AbortController()
                : null;
        const timer = controller
            ? setTimeout(() => controller.abort(), timeoutMs)
            : null;
        try {
            response = await request(currentUrl, {
                redirect: 'manual',
                headers: {
                    accept: 'application/json',
                    'user-agent': 'Sub-Store-Extension-Host/1',
                },
                signal: controller?.signal,
            });
        } catch (error) {
            if (timer) clearTimeout(timer);
            throw sourceError(
                'EXTENSION_SOURCE_FETCH_FAILED',
                'Extension source could not be fetched',
                { url: currentUrl, cause: error.message },
                502,
            );
        }
        try {
            if (response?.status >= 300 && response?.status < 400) {
                const location = response.headers?.get?.('location');
                if (!location)
                    throw sourceError(
                        'EXTENSION_SOURCE_REDIRECT_INVALID',
                        'Extension source redirect has no location',
                        { url: currentUrl },
                        502,
                    );
                if (redirect === MAX_EXTENSION_SOURCE_REDIRECTS)
                    throw sourceError(
                        'EXTENSION_SOURCE_REDIRECT_LIMIT',
                        'Extension source redirect limit exceeded',
                        { maxRedirects: MAX_EXTENSION_SOURCE_REDIRECTS },
                        502,
                    );
                currentUrl = normalizeExtensionSourceUrl(
                    new URL(location, currentUrl).toString(),
                );
                continue;
            }
            if (!response?.ok)
                throw sourceError(
                    'EXTENSION_SOURCE_FETCH_FAILED',
                    `Extension source returned HTTP ${response?.status || 0}`,
                    { url: currentUrl, status: response?.status || 0 },
                    502,
                );
            let body;
            try {
                body = await readResponseBody(response);
            } catch (error) {
                if (error?.code === 'EXTENSION_SOURCE_TOO_LARGE') throw error;
                throw sourceError(
                    'EXTENSION_SOURCE_FETCH_FAILED',
                    'Extension source response could not be read',
                    { url: currentUrl, cause: error.message },
                    502,
                );
            }
            let document;
            try {
                document = JSON.parse(body);
            } catch (error) {
                throw sourceError(
                    'EXTENSION_SOURCE_DOCUMENT_INVALID',
                    'Extension source must return a JSON document',
                    { url: currentUrl },
                    422,
                );
            }
            return {
                url: currentUrl,
                document,
                digest: sha256Hex(body) || diagnosticDigest(body),
                headers: parseResponseHeaders(response),
            };
        } finally {
            if (timer) clearTimeout(timer);
        }
    }
    throw sourceError(
        'EXTENSION_SOURCE_REDIRECT_LIMIT',
        'Extension source redirect limit exceeded',
        {},
        502,
    );
}

function packageUrlForEntry(entry, variant) {
    const maps = [
        entry.packageUrls,
        entry.packageURLS,
        entry.packages,
        entry.variants,
    ];
    for (const map of maps) {
        if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
        const candidate = map[variant] || map.default || map.node;
        if (typeof candidate === 'string') return candidate;
        if (candidate && typeof candidate === 'object')
            return (
                candidate.url || candidate.packageUrl || candidate.href || null
            );
    }
    return entry.packageUrl || entry.packageURL || entry.url || null;
}

function packageDigestForEntry(entry, variant) {
    const maps = [entry.packageDigests, entry.packageDIGESTS, entry.packages];
    for (const map of maps) {
        if (!map || typeof map !== 'object' || Array.isArray(map)) continue;
        const candidate = map[variant] || map.default || map.node;
        if (typeof candidate === 'string' && isSha256Digest(candidate))
            return candidate;
        if (candidate && isSha256Digest(candidate.digest))
            return candidate.digest;
    }
    if (isSha256Digest(entry.packageDigest)) return entry.packageDigest;
    return null;
}

function extractEntries(document) {
    if (Array.isArray(document))
        return { payload: { entries: document }, envelope: null };
    if (!document || typeof document !== 'object')
        throw sourceError(
            'EXTENSION_SOURCE_CATALOG_INVALID',
            'Extension source catalog must be an object or array',
            {},
            422,
        );
    if (document.payload && Array.isArray(document.payload.entries))
        return { payload: document.payload, envelope: document };
    if (Array.isArray(document.entries))
        return { payload: document, envelope: null };
    if (document.manifest || document.id)
        return { payload: { entries: [document] }, envelope: null };
    throw sourceError(
        'EXTENSION_SOURCE_CATALOG_INVALID',
        'Extension source catalog does not contain entries',
        {},
        422,
    );
}

function normalizeSourcePublisher(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value))
        return null;
    const id = typeof value.id === 'string' ? value.id.trim() : '';
    const name = typeof value.name === 'string' ? value.name.trim() : '';
    return id && name ? { id, name } : null;
}

export function normalizeCommunityCatalog(document, sourceUrl, sourceId) {
    const { payload, envelope } = extractEntries(document);
    const publisher = normalizeSourcePublisher(payload.publisher);
    const sourceAllowsLoopback = isLoopbackHost(new URL(sourceUrl).hostname);
    if (payload.schemaVersion != null && Number(payload.schemaVersion) !== 1)
        throw sourceError(
            'EXTENSION_SOURCE_CATALOG_SCHEMA_UNSUPPORTED',
            'Unsupported community extension catalog schema',
            { schemaVersion: payload.schemaVersion },
            422,
        );
    const rawEntries = payload.entries || [];
    if (rawEntries.length > MAX_EXTENSION_SOURCE_ENTRIES)
        throw sourceError(
            'EXTENSION_SOURCE_TOO_MANY_ENTRIES',
            'Extension source contains too many entries',
            { maxEntries: MAX_EXTENSION_SOURCE_ENTRIES },
            413,
        );
    const entries = [];
    for (const rawEntry of rawEntries) {
        const manifestInput = rawEntry?.manifest || rawEntry;
        if (
            manifestInput?.kind !== 'content' &&
            manifestInput?.kind !== 'executable'
        ) {
            throw sourceError(
                'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                'Extension sources accept content or executable extensions',
                { extensionId: manifestInput?.id || null },
                422,
            );
        }
        let manifest;
        try {
            manifest = normalizeExtensionManifest(manifestInput);
        } catch (error) {
            throw sourceError(
                'EXTENSION_SOURCE_MANIFEST_INVALID',
                'Community extension manifest is invalid',
                { cause: error.message },
                422,
            );
        }
        if (manifest.kind !== 'content' && manifest.kind !== 'executable')
            throw sourceError(
                'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                'Extension source manifest kind is not installable',
                { extensionId: manifest.id },
                422,
            );
        const executable = manifest.kind === 'executable';
        const variants = Object.keys(manifest.variants || {});
        if (!variants.length)
            throw sourceError(
                'EXTENSION_SOURCE_VARIANT_MISSING',
                'Community extension must declare at least one package variant',
                { extensionId: manifest.id },
                422,
            );
        for (const variantName of variants) {
            if (
                !executable &&
                manifest.variants[variantName]?.containsExecutableCode === true
            )
                throw sourceError(
                    'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
                    'Community extension variants cannot contain executable code',
                    { extensionId: manifest.id, variant: variantName },
                    422,
                );
        }
        if (executable && !variants.includes('node'))
            throw sourceError(
                'EXTENSION_SOURCE_VARIANT_MISSING',
                'Executable extensions must declare a Node package variant',
                { extensionId: manifest.id },
                422,
            );
        const nodeVariant = manifest.variants?.node;
        if (
            executable &&
            (nodeVariant?.containsExecutableCode !== true ||
                typeof nodeVariant?.entrypoint !== 'string' ||
                !nodeVariant.entrypoint)
        )
            throw sourceError(
                'EXTENSION_SOURCE_EXECUTABLE_CONTRACT_INVALID',
                'Executable extensions must declare a digest-bound Node entrypoint',
                { extensionId: manifest.id },
                422,
            );
        const selectedVariant = executable
            ? 'node'
            : variants.includes('node')
            ? 'node'
            : variants[0];
        const rawPackageUrl =
            rawEntry?.payload || rawEntry?.files
                ? sourceUrl
                : packageUrlForEntry(rawEntry, selectedVariant);
        if (!rawPackageUrl)
            throw sourceError(
                'EXTENSION_SOURCE_PACKAGE_URL_MISSING',
                'Community extension entry does not provide a package URL',
                { extensionId: manifest.id },
                422,
            );
        let packageUrl;
        try {
            packageUrl = normalizeExtensionSourceUrl(
                new URL(rawPackageUrl, sourceUrl).toString(),
            );
            assertLoopbackBoundary(new URL(packageUrl), sourceAllowsLoopback);
        } catch (error) {
            throw sourceError(
                error.code || 'EXTENSION_SOURCE_PACKAGE_URL_INVALID',
                error.message,
                { extensionId: manifest.id },
                error.statusCode || 422,
            );
        }
        const packageDigest = packageDigestForEntry(rawEntry, selectedVariant);
        if (!packageDigest) {
            throw sourceError(
                'EXTENSION_SOURCE_PACKAGE_DIGEST_MISSING',
                'Community extension entries must declare an immutable SHA-256 package digest',
                { extensionId: manifest.id, selectedVariant },
                422,
            );
        }
        const inlinePackage =
            rawEntry?.payload || rawEntry?.files
                ? cloneExtensionValue(rawEntry)
                : null;
        entries.push({
            id: manifest.id,
            version: manifest.version,
            name: manifest.name,
            description: manifest.description,
            kind: manifest.kind,
            distribution: executable
                ? SOURCE_EXECUTABLE_DISTRIBUTION
                : 'community',
            source: sourceUrl,
            sourceId,
            sourceName: rawEntry.sourceName || rawEntry.publisher?.name || null,
            manifest: cloneExtensionValue(manifest),
            manifestDigest:
                sha256Hex(canonicalJson(manifest)) ||
                diagnosticDigest(canonicalJson(manifest)),
            packageUrls: { [selectedVariant]: packageUrl },
            packageDigests: { [selectedVariant]: packageDigest },
            selectedVariant,
            catalogEntryDigest:
                sha256Hex(canonicalJson(rawEntry)) ||
                diagnosticDigest(canonicalJson(rawEntry)),
            ...(inlinePackage ? { inlinePackage } : {}),
        });
    }
    return {
        schemaVersion: 1,
        sequence: Number.isInteger(payload.sequence) ? payload.sequence : 0,
        generatedAt: payload.generatedAt || null,
        expiresAt: payload.expiresAt || null,
        publisher,
        entries,
        envelope: envelope
            ? {
                  signature: cloneExtensionValue(envelope.signature),
                  expiresAt: envelope.expiresAt || null,
              }
            : null,
    };
}

export function publicExtensionSource(source) {
    if (!source) return null;
    const entries = (source.entries || []).map((entry) => {
        const publicEntry = { ...(entry || {}) };
        delete publicEntry.inlinePackage;
        return cloneExtensionValue(publicEntry);
    });
    return {
        id: source.id,
        name: source.name || source.url,
        url: source.url,
        status: source.status || 'ready',
        verified: source.verified === true,
        verificationMode: source.verificationMode || 'community-unsigned',
        digest: source.digest || null,
        publisher: normalizeSourcePublisher(source.publisher),
        entryCount: Array.isArray(source.entries) ? source.entries.length : 0,
        entries,
        addedAt: source.addedAt || null,
        updatedAt: source.updatedAt || null,
        lastError: source.lastError
            ? cloneExtensionValue(source.lastError)
            : null,
    };
}

export function sourceEntryPackageUrl(entry, variant) {
    return packageUrlForEntry(entry, variant);
}

export function sourceEntryPackageDigest(entry, variant) {
    return packageDigestForEntry(entry, variant);
}

export function isCommunityContentPackage(packageInput) {
    const manifest = packageInput?.manifest;
    const payload = packageInput?.payload;
    const variant =
        payload?.variant ||
        manifest?.variants?.[
            payload?.selectedVariant || packageInput?.selectedVariant
        ];
    return Boolean(
        manifest?.kind === 'content' &&
            payload &&
            payload.containsExecutableCode === false &&
            payload.containsInstallHook === false &&
            variant &&
            variant.containsExecutableCode === false &&
            !packageInput?.receipt?.implementation?.entrypoint,
    );
}

import { expect } from 'chai';
import { describe, it } from 'mocha';
import {
    canonicalJson,
    normalizeExtensionManifest,
} from '@/extensions/contracts';
import { initializeExtensionHost } from '@/extensions/host';
import {
    ExtensionManager,
    resetExtensionManagerForTests,
} from '@/extensions/manager';
import {
    createDigestReceipt,
    extensionPackageDigest,
    sha256Hex,
} from '@/extensions/signature';
import {
    MAX_EXTENSION_SOURCE_BYTES,
    extensionSourceId,
    fetchExtensionSourceDocument,
    normalizeCommunityCatalog,
    normalizeExtensionSourceUrl,
    publicExtensionSource,
} from '@/extensions/sources';
import { createNodeExtensionPackageStore } from '@/extensions/package-store';
import { clearExtensionRegistryForTests } from '@/extensions/registry';
import { registerExtensionControlRoutes } from '@/restful/extensions';
import dns from 'dns';
import fs from 'fs';
import os from 'os';
import path from 'path';

const EXECUTABLE_EXTENSION_ID = 'org.example.executable-extension';
const EXECUTABLE_SOURCE_URL = 'https://example.test/extensions/catalog.json';

function createStore(initial) {
    const values =
        initial === undefined
            ? {}
            : { '#sub-store-extensions': JSON.stringify(initial) };
    return {
        read(key) {
            return Object.prototype.hasOwnProperty.call(values, key)
                ? values[key]
                : undefined;
        },
        write(value, key) {
            values[key] = value;
        },
        delete(key) {
            delete values[key];
        },
    };
}

function response(value) {
    return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        async text() {
            return JSON.stringify(value);
        },
    };
}

function createRouteApp() {
    const handlers = new Map();
    const app = {};
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
        app[method] = (route, ...routeHandlers) => {
            handlers.set(
                `${method.toUpperCase()} ${route}`,
                routeHandlers[routeHandlers.length - 1],
            );
            return app;
        };
    }
    return { app, handlers };
}

function createApiResponse() {
    return {
        statusCode: 200,
        body: null,
        headers: {},
        status(code) {
            this.statusCode = code;
            return this;
        },
        set(key, value) {
            this.headers[key] = value;
            return this;
        },
        json(body) {
            this.body = body;
            return this;
        },
        end() {
            this.ended = true;
        },
    };
}

function contentFixture({
    version = '1.0.0',
    content = '{"hello":"world"}',
} = {}) {
    const manifest = normalizeExtensionManifest({
        schemaVersion: 1,
        id: 'com.example.content-extension',
        kind: 'content',
        name: 'Community content',
        description: 'A data-only extension',
        version,
        publisher: { id: 'com.example', name: 'Example publisher' },
        host: { apiVersion: '1.0.0' },
        variants: {
            node: {
                delivery: 'content-package',
                packageKind: 'json-content',
                implementationId: 'com.example.content@1/node',
                implementationAbi: 'content@1',
                containsExecutableCode: false,
            },
        },
    });
    const files = { 'content.json': content };
    const fileDigests = { 'content.json': sha256Hex(files['content.json']) };
    const projection = {
        schemaVersion: 1,
        manifest,
        selectedVariant: 'node',
        variant: manifest.variants.node,
        containsExecutableCode: false,
        containsInstallHook: false,
        files,
        fileDigests,
    };
    const packageDigest = extensionPackageDigest(projection);
    const receipt = createDigestReceipt({
        manifest,
        packageDigest,
        variant: 'node',
        implementation: {
            id: manifest.variants.node.implementationId,
            abi: manifest.variants.node.implementationAbi,
            frontendAssetId: undefined,
            entrypoint: undefined,
            lanes: {},
            containsExecutableCode: false,
        },
    });
    const payload = { ...projection, packageDigest, receipt };
    const payloadDigest = sha256Hex(canonicalJson(payload));
    const packageDocument = {
        schemaVersion: 1,
        manifest,
        selectedVariant: 'node',
        payload,
        receipt,
        packageDigest,
        signature: {
            algorithm: 'sha256-digest',
            keyId: 'community-test',
            digest: payloadDigest,
            value: payloadDigest,
        },
    };
    const catalog = {
        schemaVersion: 1,
        entries: [
            {
                manifest,
                packageUrls: { node: 'https://example.test/content.json' },
                packageDigests: { node: packageDigest },
            },
        ],
    };
    return { manifest, packageDigest, catalog, packageDocument };
}

function clone(value) {
    return JSON.parse(JSON.stringify(value));
}

function executableRelease({
    version = '1.1.0',
    packageUrl = `https://example.test/extensions/executable-${version}.json`,
    backendEntrypoint,
    storageSchemaVersion,
} = {}) {
    const implementationAbi = 'example-executable@1';
    // Keep the package manifest in its authored form. Source ingestion adds
    // optional normalized defaults (permissions/contributes/lanes), and the
    // Host must compare those forms semantically without changing the bytes
    // covered by the package and receipt digests.
    const manifest = {
        schemaVersion: 1,
        id: EXECUTABLE_EXTENSION_ID,
        kind: 'executable',
        distribution: 'store',
        name: 'Example executable extension',
        description: 'Synthetic executable package used by Host tests',
        version,
        publisher: { id: 'org.example', name: 'Example publisher' },
        host: {
            apiVersion: '1.0.0',
            runtimes: ['node'],
            implementationAbi,
        },
        variants: {
            node: {
                implementationId: `${EXECUTABLE_EXTENSION_ID}@1/node`,
                implementationAbi,
                entrypoint: 'backend/index.cjs',
                containsExecutableCode: true,
            },
        },
        scriptExecutionLanes: {
            simple: {
                product: 'sub-store-0',
                implementationId: `${EXECUTABLE_EXTENSION_ID}@1/simple`,
                routes: ['status'],
            },
        },
        ...(storageSchemaVersion == null
            ? {}
            : { storage: { schemaVersion: storageSchemaVersion } }),
    };
    const files = {
        'backend/index.cjs':
            backendEntrypoint ||
            `'use strict';
module.exports = Object.freeze({
    extensionId: '${EXECUTABLE_EXTENSION_ID}',
    implementationAbi: '${implementationAbi}',
    activate() { return { active: true }; },
    deactivate() { return { active: false }; },
});
`,
    };
    const fileDigests = Object.fromEntries(
        Object.entries(files).map(([name, content]) => [
            name,
            sha256Hex(content),
        ]),
    );
    const projection = {
        schemaVersion: 1,
        manifest,
        selectedVariant: 'node',
        variant: manifest.variants.node,
        containsExecutableCode: true,
        containsInstallHook: false,
        files,
        fileDigests,
    };
    const packageDigest = extensionPackageDigest(projection);
    const receipt = createDigestReceipt({
        manifest,
        packageDigest,
        variant: 'node',
        implementation: {
            id: manifest.variants.node.implementationId,
            abi: implementationAbi,
            entrypoint: 'backend/index.cjs',
            lanes: {
                simple: {
                    product: 'sub-store-0',
                    implementationId: `${EXECUTABLE_EXTENSION_ID}@1/simple`,
                },
            },
            containsExecutableCode: true,
        },
        now: Date.parse('2026-08-11T00:00:00.000Z'),
    });
    const payload = { ...projection, packageDigest, receipt };
    const payloadDigest = sha256Hex(canonicalJson(payload));
    const packageDocument = {
        schemaVersion: 1,
        source: 'org.example.extensions',
        manifest,
        selectedVariant: 'node',
        payload,
        receipt,
        packageDigest,
        signature: {
            algorithm: 'sha256-digest',
            digest: payloadDigest,
            value: payloadDigest,
        },
    };
    const catalog = {
        schemaVersion: 1,
        id: 'org.example.extensions',
        name: 'Example Extensions',
        sequence: 1,
        publisher: { id: 'org.example', name: 'Example publisher' },
        entries: [
            {
                id: manifest.id,
                version: manifest.version,
                name: manifest.name,
                description: manifest.description,
                kind: manifest.kind,
                sourceName: 'Example Extensions',
                manifest,
                packageUrl,
                packageDigest,
                packageUrls: { node: packageUrl },
                packageDigests: { node: packageDigest },
            },
        ],
    };
    return {
        catalog,
        packageDocument,
        packageUrl,
        packageDigest,
        sourceUrl: EXECUTABLE_SOURCE_URL,
    };
}

function resealCommunityPackage(document) {
    const payload = document.payload;
    const packageDigest = extensionPackageDigest(payload);
    payload.packageDigest = packageDigest;
    payload.receipt.packageDigest = packageDigest;
    const unsignedReceipt = clone(payload.receipt);
    delete unsignedReceipt.receiptDigest;
    payload.receipt.receiptDigest = sha256Hex(canonicalJson(unsignedReceipt));
    document.packageDigest = packageDigest;
    document.receipt = clone(payload.receipt);
    const payloadDigest = sha256Hex(canonicalJson(payload));
    document.signature = {
        algorithm: 'sha256-digest',
        keyId: 'community-test',
        digest: payloadDigest,
        value: payloadDigest,
    };
    return packageDigest;
}

describe('Community extension sources', function () {
    it('normalizes immutable release history while keeping one source entry per extension', function () {
        const v1 = executableRelease({ version: '1.1.0' });
        const v2 = executableRelease({ version: '1.2.0' });
        const catalog = clone(v2.catalog);
        catalog.entries[0].releases = [
            {
                ...clone(v2.catalog.entries[0]),
                releasedAt: '2026-08-12T01:00:00.000Z',
                gitTag: `${EXECUTABLE_EXTENSION_ID}@1.2.0`,
                gitCommit: '2'.repeat(40),
            },
            {
                ...clone(v1.catalog.entries[0]),
                releasedAt: '2026-08-11T01:00:00.000Z',
                gitTag: `${EXECUTABLE_EXTENSION_ID}@1.1.0`,
                gitCommit: '1'.repeat(40),
            },
        ];

        const normalized = normalizeCommunityCatalog(
            catalog,
            v2.sourceUrl,
            'source-history',
        );
        expect(normalized.entries).to.have.length(1);
        expect(normalized.entries[0]).to.include({
            id: EXECUTABLE_EXTENSION_ID,
            version: '1.2.0',
        });
        expect(
            normalized.entries[0].releases.map((release) => release.version),
        ).to.deep.equal(['1.2.0', '1.1.0']);
        expect(normalized.entries[0].releases[0]).to.include({
            releasedAt: '2026-08-12T01:00:00.000Z',
            gitTag: `${EXECUTABLE_EXTENSION_ID}@1.2.0`,
            gitCommit: '2'.repeat(40),
            installable: true,
        });
    });

    it('keeps provenance-only releases visible but rejects mutable duplicate versions', function () {
        const v1 = executableRelease({ version: '1.1.0' });
        const v2 = executableRelease({ version: '1.2.0' });
        const catalog = clone(v2.catalog);
        const provenanceOnly = clone(v1.catalog.entries[0]);
        provenanceOnly.installable = false;
        provenanceOnly.distribution = 'store';
        provenanceOnly.manifest.kind = 'trusted-official';
        provenanceOnly.manifest.distribution = 'store';
        provenanceOnly.releasedAt = '2026-08-10T01:00:00.000Z';
        catalog.entries[0].releases = [
            clone(v2.catalog.entries[0]),
            provenanceOnly,
        ];

        const normalized = normalizeCommunityCatalog(
            catalog,
            v2.sourceUrl,
            'source-history',
        );
        expect(normalized.entries[0].releases[1]).to.include({
            version: '1.1.0',
            installable: false,
            distribution: 'store',
        });

        const mutated = clone(catalog);
        mutated.entries[0].releases[0].packageDigest = '0'.repeat(64);
        mutated.entries[0].releases[0].packageDigests.node = '0'.repeat(64);
        expect(() =>
            normalizeCommunityCatalog(mutated, v2.sourceUrl, 'source-history'),
        ).to.throw('immutable content');

        const installabilityDrift = clone(catalog);
        installabilityDrift.entries[0].releases = [
            clone(v2.catalog.entries[0]),
            { ...clone(v2.catalog.entries[0]), installable: false },
            provenanceOnly,
        ];
        expect(() =>
            normalizeCommunityCatalog(
                installabilityDrift,
                v2.sourceUrl,
                'source-history',
            ),
        ).to.throw('immutable content');
    });

    it('normalizes GitHub blob links and rejects URL credentials/private HTTP', function () {
        expect(
            normalizeExtensionSourceUrl(
                'https://github.com/example/repo/blob/main/catalog.json?channel=beta#fragment',
            ),
        ).to.equal(
            'https://raw.githubusercontent.com/example/repo/main/catalog.json?channel=beta',
        );
        expect(
            normalizeExtensionSourceUrl(
                'https://raw.githubusercontent.com/example/repo/refs/heads/main/repository/catalog.json',
            ),
        ).to.equal(
            'https://raw.githubusercontent.com/example/repo/main/repository/catalog.json',
        );
        expect(() =>
            normalizeExtensionSourceUrl(
                'https://user:pass@example.com/catalog.json',
            ),
        ).to.throw('credentials');
        expect(() =>
            normalizeExtensionSourceUrl('http://example.com/catalog.json'),
        ).to.throw('HTTPS');
    });

    it('preserves only an explicit valid top-level catalog publisher', function () {
        const fixture = contentFixture();
        const sourceUrl = 'https://example.test/catalog.json';
        const catalog = clone(fixture.catalog);
        catalog.publisher = {
            id: ' com.example.catalog ',
            name: ' Example catalog ',
            homepage: 'https://example.test',
        };
        expect(
            normalizeCommunityCatalog(catalog, sourceUrl, 'source-test')
                .publisher,
        ).to.deep.equal({
            id: 'com.example.catalog',
            name: 'Example catalog',
        });

        const envelope = {
            payload: catalog,
            signature: { algorithm: 'test', value: 'not-verified-here' },
        };
        expect(
            normalizeCommunityCatalog(envelope, sourceUrl, 'source-test')
                .publisher,
        ).to.deep.equal({
            id: 'com.example.catalog',
            name: 'Example catalog',
        });

        const entryAttributedCatalog = clone(fixture.catalog);
        entryAttributedCatalog.entries[0].sourceName = 'Entry source';
        entryAttributedCatalog.entries[0].publisher = {
            id: 'com.example.entry',
            name: 'Entry publisher',
        };
        expect(
            normalizeCommunityCatalog(
                entryAttributedCatalog,
                'https://github.com/example/catalog.json',
                'source-test',
            ).publisher,
        ).to.equal(null);

        for (const publisher of [
            undefined,
            null,
            [],
            'Example publisher',
            { id: 'com.example' },
            { name: 'Example publisher' },
            { id: ' ', name: 'Example publisher' },
            { id: 'com.example', name: ' ' },
        ]) {
            const invalidCatalog = clone(fixture.catalog);
            if (publisher !== undefined) invalidCatalog.publisher = publisher;
            expect(
                normalizeCommunityCatalog(
                    invalidCatalog,
                    sourceUrl,
                    'source-test',
                ).publisher,
            ).to.equal(null);
        }

        expect(
            publicExtensionSource({
                id: 'source-test',
                url: sourceUrl,
                publisher: {
                    id: ' com.example.catalog ',
                    name: ' Example catalog ',
                    verified: true,
                },
            }).publisher,
        ).to.deep.equal({
            id: 'com.example.catalog',
            name: 'Example catalog',
        });
        expect(
            publicExtensionSource({
                id: 'source-test',
                url: sourceUrl,
                publisher: { name: 'Example catalog' },
            }).publisher,
        ).to.equal(null);
    });

    it('rejects catalogs without an immutable package digest', function () {
        const fixture = contentFixture();
        const catalog = clone(fixture.catalog);
        delete catalog.entries[0].packageDigests;
        expect(() =>
            normalizeCommunityCatalog(
                catalog,
                'https://example.test/catalog.json',
                'source-test',
            ),
        ).to.throw('package digest');
    });

    it('does not let a remote source pivot into a loopback target', async function () {
        const requested = [];
        let error;
        try {
            await fetchExtensionSourceDocument(
                'https://example.test/catalog.json',
                {
                    fetcher: async (url) => {
                        requested.push(url);
                        if (requested.length === 1) {
                            return {
                                ok: false,
                                status: 302,
                                headers: {
                                    get(name) {
                                        return name === 'location'
                                            ? 'http://127.0.0.1/private.json'
                                            : null;
                                    },
                                },
                            };
                        }
                        return response({ schemaVersion: 1, entries: [] });
                    },
                },
            );
        } catch (caught) {
            error = caught;
        }
        expect(error).to.have.property('code', 'EXTENSION_SOURCE_SSRF_BLOCKED');
        expect(requested).to.deep.equal(['https://example.test/catalog.json']);
    });

    it('rejects loopback package URLs declared by a remote catalog', function () {
        const fixture = contentFixture();
        const catalog = clone(fixture.catalog);
        catalog.entries[0].packageUrls.node =
            'http://127.0.0.1/private-package.json';
        expect(() =>
            normalizeCommunityCatalog(
                catalog,
                'https://example.test/catalog.json',
                'source-test',
            ),
        ).to.throw('loopback');
    });

    it('keeps explicitly configured loopback sources available for local development', async function () {
        const fixture = contentFixture();
        const sourceUrl = 'http://127.0.0.1/catalog.json';
        const packageUrl = 'http://127.0.0.1/content.json';
        fixture.catalog.entries[0].packageUrls.node = packageUrl;
        const fetched = await fetchExtensionSourceDocument(sourceUrl, {
            fetcher: async () => response(fixture.catalog),
        });
        const catalog = normalizeCommunityCatalog(
            fetched.document,
            sourceUrl,
            'source-local',
        );
        expect(catalog.entries[0].packageUrls.node).to.equal(packageUrl);
    });

    it('allows HTTPS sources through proxy fake-IP DNS without admitting private targets', async function () {
        const originalLookup = dns.promises.lookup;
        const originalFetch = global.fetch;
        const requested = [];
        try {
            dns.promises.lookup = async () => [
                { address: '198.18.1.18', family: 4 },
            ];
            global.fetch = async (url) => {
                requested.push(url);
                return response({ schemaVersion: 1, entries: [] });
            };

            const remoteUrl =
                'https://raw.githubusercontent.com/example/repo/main/catalog.json';
            const fetched = await fetchExtensionSourceDocument(remoteUrl);
            expect(fetched.document).to.deep.equal({
                schemaVersion: 1,
                entries: [],
            });
            expect(requested).to.deep.equal([remoteUrl]);

            dns.promises.lookup = async () => [
                { address: '10.0.0.8', family: 4 },
            ];
            let privateError;
            try {
                await fetchExtensionSourceDocument(
                    'https://private.example.test/catalog.json',
                );
            } catch (error) {
                privateError = error;
            }
            expect(privateError).to.have.property(
                'code',
                'EXTENSION_SOURCE_SSRF_BLOCKED',
            );

            let literalError;
            try {
                await fetchExtensionSourceDocument(
                    'https://198.18.1.18/catalog.json',
                );
            } catch (error) {
                literalError = error;
            }
            expect(literalError).to.have.property(
                'code',
                'EXTENSION_SOURCE_SSRF_BLOCKED',
            );
            expect(requested).to.have.length(1);
        } finally {
            dns.promises.lookup = originalLookup;
            global.fetch = originalFetch;
        }
    });

    it('aborts streamed source responses at the configured size limit', async function () {
        let reads = 0;
        let cancelled = false;
        let error;
        try {
            await fetchExtensionSourceDocument(
                'https://example.test/catalog.json',
                {
                    fetcher: async () => ({
                        ok: true,
                        status: 200,
                        headers: { get: () => null },
                        body: {
                            getReader() {
                                return {
                                    async read() {
                                        reads += 1;
                                        if (reads === 1) {
                                            return {
                                                done: false,
                                                value: new Uint8Array(
                                                    MAX_EXTENSION_SOURCE_BYTES +
                                                        1,
                                                ),
                                            };
                                        }
                                        return { done: true };
                                    },
                                    async cancel() {
                                        cancelled = true;
                                    },
                                };
                            },
                        },
                    }),
                },
            );
        } catch (caught) {
            error = caught;
        }
        expect(error).to.have.property('code', 'EXTENSION_SOURCE_TOO_LARGE');
        expect(cancelled).to.equal(true);
    });

    it('keeps the source timeout active while reading a streamed body', async function () {
        let requestSignal;
        const fetchPromise = fetchExtensionSourceDocument(
            'https://example.test/catalog.json',
            {
                timeoutMs: 5,
                fetcher: async (url, options) => {
                    requestSignal = options.signal;
                    return {
                        ok: true,
                        status: 200,
                        headers: { get: () => null },
                        body: {
                            getReader() {
                                return {
                                    read() {
                                        return new Promise(
                                            (resolve, reject) => {
                                                if (requestSignal.aborted) {
                                                    reject(
                                                        new Error('aborted'),
                                                    );
                                                    return;
                                                }
                                                requestSignal.addEventListener(
                                                    'abort',
                                                    () =>
                                                        reject(
                                                            new Error(
                                                                'aborted',
                                                            ),
                                                        ),
                                                    { once: true },
                                                );
                                            },
                                        );
                                    },
                                };
                            },
                        },
                    };
                },
            },
        );
        const result = await Promise.race([
            fetchPromise.then(
                () => ({ error: null }),
                (error) => ({ error }),
            ),
            new Promise((resolve) =>
                setTimeout(() => resolve({ timedOut: true }), 200),
            ),
        ]);
        expect(result).not.to.have.property('timedOut');
        expect(result.error).to.have.property(
            'code',
            'EXTENSION_SOURCE_FETCH_FAILED',
        );
    });

    it('persists a verified content-only source and retains its manifest after source removal', async function () {
        const fixture = contentFixture();
        const sourceUrl = 'https://example.test/catalog.json';
        fixture.catalog.publisher = {
            id: 'com.example.catalog',
            name: 'Example catalog',
        };
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(
                    url === sourceUrl
                        ? fixture.catalog
                        : fixture.packageDocument,
                ),
        });
        const source = await manager.addSource({
            url: sourceUrl,
            name: 'Example',
        });
        expect(source).to.include({
            id: extensionSourceId(sourceUrl),
            name: 'Example',
            verified: true,
        });
        expect(source.publisher).to.deep.equal({
            id: 'com.example.catalog',
            name: 'Example catalog',
        });
        expect(manager.getSources()[0].publisher).to.deep.equal(
            source.publisher,
        );
        expect(
            manager
                .getCatalog()
                .entries.find((entry) => entry.id === fixture.manifest.id),
        ).to.include({
            sourceId: source.id,
            sourceName: 'Example',
            sourceUrl,
        });
        expect(
            manager.getCatalog().entries.map((entry) => entry.id),
        ).to.include(fixture.manifest.id);
        const installed = await manager.installFromSource(fixture.manifest.id);
        expect(installed.record).to.include({
            extensionId: fixture.manifest.id,
            distribution: 'community',
            sourceId: source.id,
        });
        expect(() => manager.enable(fixture.manifest.id)).to.throw(
            'content extensions cannot be enabled',
        );
        manager.removeSource(source.id);
        expect(manager.getManifest(fixture.manifest.id).id).to.equal(
            fixture.manifest.id,
        );
        expect(
            manager
                .getCatalog()
                .entries.find((entry) => entry.id === fixture.manifest.id),
        ).to.include({
            sourceMissing: true,
        });
        const removed = manager.uninstall(fixture.manifest.id);
        expect(removed.status).to.equal('reinstall-required');
    });

    it('updates catalog publisher metadata only after a successful refresh', async function () {
        const fixture = contentFixture();
        const sourceUrl = 'https://example.test/catalog.json';
        let activeCatalog = clone(fixture.catalog);
        activeCatalog.publisher = {
            id: 'com.example.first',
            name: 'First publisher',
        };
        let fetchError = null;
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => {
                if (fetchError) throw fetchError;
                return response(activeCatalog);
            },
        });

        const source = await manager.addSource({ url: sourceUrl });
        expect(source.publisher).to.deep.equal({
            id: 'com.example.first',
            name: 'First publisher',
        });

        activeCatalog = clone(fixture.catalog);
        activeCatalog.publisher = {
            id: 'com.example.second',
            name: 'Second publisher',
        };
        expect(
            (await manager.refreshSource(source.id)).publisher,
        ).to.deep.equal({
            id: 'com.example.second',
            name: 'Second publisher',
        });

        activeCatalog = clone(fixture.catalog);
        expect((await manager.refreshSource(source.id)).publisher).to.equal(
            null,
        );

        activeCatalog.publisher = {
            id: 'com.example.restored',
            name: 'Restored publisher',
        };
        await manager.refreshSource(source.id);
        fetchError = new Error('catalog offline');
        let refreshError;
        try {
            await manager.refreshSource(source.id);
        } catch (error) {
            refreshError = error;
        }
        expect(refreshError).to.have.property(
            'code',
            'EXTENSION_SOURCE_FETCH_FAILED',
        );
        expect(refreshError.source.publisher).to.deep.equal({
            id: 'com.example.restored',
            name: 'Restored publisher',
        });
        expect(manager.getSources()[0].publisher).to.deep.equal(
            refreshError.source.publisher,
        );
    });

    it('lets a verified source replace a removed local installation while retaining its data', async function () {
        const repository = executableRelease();
        const manifest = repository.packageDocument.manifest;
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-source-after-local-'),
        );
        const store = createStore({
            schemaVersion: 1,
            revision: 1,
            storeRevision: 1,
            dataGeneration: 0,
            installed: {
                [EXECUTABLE_EXTENSION_ID]: {
                    extensionId: EXECUTABLE_EXTENSION_ID,
                    version: manifest.version,
                    kind: manifest.kind,
                    manifestSnapshot: clone(manifest),
                    selectedVariant: 'node',
                    implementation: {
                        id: manifest.variants.node.implementationId,
                        abi: manifest.variants.node.implementationAbi,
                        entrypoint: manifest.variants.node.entrypoint,
                        containsExecutableCode: true,
                    },
                    distribution: 'local-executable',
                    source: 'local-upload',
                    sourceId: null,
                    sourceUrl: null,
                    installationStatus: 'removed',
                    dataStatus: 'retained',
                    retainedReason: 'user-uninstalled',
                    enabled: false,
                    codeStatus: 'removed',
                    compatibilityStatus: 'compatible',
                    verificationMode: 'local-integrity',
                },
            },
            sources: {},
            migrations: {},
            tasks: [],
            audit: [],
        });
        try {
            const manager = new ExtensionManager({
                store,
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url === repository.sourceUrl
                            ? repository.catalog
                            : repository.packageDocument,
                    ),
            });

            expect(manager.getAvailability(EXECUTABLE_EXTENSION_ID)).to.include(
                {
                    status: 'reinstall-required',
                    retainedReason: 'user-uninstalled',
                },
            );

            const source = await manager.addSource({
                url: repository.sourceUrl,
                name: 'Example source',
            });
            expect(manager.findEntry(EXECUTABLE_EXTENSION_ID)).to.include({
                distribution: 'source-executable',
                sourceId: source.id,
            });

            const installed = await manager.installFromSource(
                EXECUTABLE_EXTENSION_ID,
            );
            expect(installed.record).to.include({
                distribution: 'source-executable',
                sourceId: source.id,
                dataStatus: 'active',
                codeStatus: 'verified-package-installed',
            });
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('installs a digest executable only after its source is added and keeps it verifiable', async function () {
        const repository = executableRelease();
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-source-executable-'),
        );
        try {
            resetExtensionManagerForTests();
            clearExtensionRegistryForTests();
            const host = initializeExtensionHost({
                reset: true,
                store: createStore(undefined),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url === repository.sourceUrl
                            ? repository.catalog
                            : repository.packageDocument,
                    ),
                adoptLegacy: false,
                restoreEnabled: false,
            });
            const manager = host.manager;

            expect(
                manager.getCatalog().entries.map((entry) => entry.id),
            ).to.not.include(EXECUTABLE_EXTENSION_ID);
            expect(
                manager
                    .getRuntimeManifest()
                    .extensions.map((entry) => entry.id),
            ).to.not.include(EXECUTABLE_EXTENSION_ID);
            expect(manager.findEntry(EXECUTABLE_EXTENSION_ID)).to.equal(null);

            let missingSourceError;
            try {
                await manager.installFromSource(EXECUTABLE_EXTENSION_ID);
            } catch (error) {
                missingSourceError = error;
            }
            expect(missingSourceError).to.include({
                code: 'EXTENSION_SOURCE_NOT_FOUND',
            });

            const source = await manager.addSource({
                url: repository.sourceUrl,
                name: 'Example source',
            });
            expect(source.publisher).to.deep.equal({
                id: 'org.example',
                name: 'Example publisher',
            });
            expect(source.entries).to.have.length(1);
            expect(source.entries[0]).to.include({
                id: EXECUTABLE_EXTENSION_ID,
                distribution: 'source-executable',
                source: repository.sourceUrl,
            });
            expect(source.entries[0].packageUrls.node).to.equal(
                repository.packageUrl,
            );

            const catalogEntry = manager
                .getCatalog()
                .entries.find((entry) => entry.id === EXECUTABLE_EXTENSION_ID);
            expect(catalogEntry).to.include({
                sourceId: source.id,
                sourceName: 'Example Extensions',
                sourceUrl: repository.sourceUrl,
                distribution: 'source-executable',
            });
            expect(catalogEntry.packageUrls.node).to.equal(
                repository.packageUrl,
            );
            expect(manager.findEntry(EXECUTABLE_EXTENSION_ID)).to.include({
                distribution: 'source-executable',
                sourceId: source.id,
            });

            const { app, handlers } = createRouteApp();
            registerExtensionControlRoutes(app, manager);
            const installResponse = createApiResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: EXECUTABLE_EXTENSION_ID },
                    body: {},
                    headers: {},
                    extensionAdmin: true,
                },
                installResponse,
            );
            expect(installResponse.statusCode).to.equal(201);
            const installed = installResponse.body.data;
            expect(installed.record).to.include({
                extensionId: EXECUTABLE_EXTENSION_ID,
                verificationMode: 'source-integrity',
                sourceId: source.id,
                sourceUrl: repository.sourceUrl,
                codeStatus: 'verified-package-installed',
            });
            expect(
                manager.getRecord(EXECUTABLE_EXTENSION_ID).packageDirectory,
            ).to.be.a('string');

            expect(manager.enable(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'enabled',
            );
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'healthy',
            );
            expect(manager.disable(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'disabled',
            );
            expect(
                manager.getAvailability(EXECUTABLE_EXTENSION_ID).status,
            ).to.equal('disabled');

            const uninstalled = manager.uninstall(EXECUTABLE_EXTENSION_ID);
            expect(uninstalled.status).to.equal('reinstall-required');
            expect(uninstalled.record.codeStatus).to.equal('removed');

            const reinstalled = await manager.installFromSource(
                EXECUTABLE_EXTENSION_ID,
            );
            expect(reinstalled.status).to.equal('installed-disabled');
            expect(manager.enable(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'enabled',
            );
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'healthy',
            );
            manager.disable(EXECUTABLE_EXTENSION_ID);
            manager.uninstall(EXECUTABLE_EXTENSION_ID);
        } finally {
            clearExtensionRegistryForTests();
            resetExtensionManagerForTests();
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('updates an enabled digest executable, rolls back, and restores after activation failure', async function () {
        const repository = executableRelease();
        const v2 = executableRelease({
            version: '1.2.0',
        });
        const v3 = executableRelease({
            version: '1.3.0',
            backendEntrypoint: `'use strict';
module.exports = Object.freeze({
    extensionId: '${EXECUTABLE_EXTENSION_ID}',
    implementationAbi: 'example-executable@1',
    activate() {
        const error = new Error('simulated activation failure');
        error.code = 'TEST_EXTENSION_ACTIVATION_FAILED';
        throw error;
    },
    deactivate() { return { active: false }; },
});
`,
        });
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-version-management-'),
        );
        const store = createStore(undefined);
        const preservedProjects = [
            { name: 'Keep me', target: 'Surge', rules: [] },
        ];
        store.write(preservedProjects, 'externalExtensionData');
        let activeCatalog = repository.catalog;
        const packages = new Map([
            [repository.packageUrl, repository.packageDocument],
            [v2.packageUrl, v2.packageDocument],
            [v3.packageUrl, v3.packageDocument],
        ]);
        try {
            resetExtensionManagerForTests();
            clearExtensionRegistryForTests();
            const host = initializeExtensionHost({
                reset: true,
                store,
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url === repository.sourceUrl
                            ? activeCatalog
                            : packages.get(url),
                    ),
                adoptLegacy: false,
                restoreEnabled: false,
            });
            const manager = host.manager;
            const source = await manager.addSource({
                url: repository.sourceUrl,
            });
            await manager.installFromSource(EXECUTABLE_EXTENSION_ID);
            manager.enable(EXECUTABLE_EXTENSION_ID);

            activeCatalog = v2.catalog;
            const updated = await manager.update(EXECUTABLE_EXTENSION_ID);
            expect(updated.status).to.equal('updated-enabled');
            expect(updated.record).to.include({
                version: '1.2.0',
                enabled: true,
                rollbackAvailable: true,
            });
            expect(updated.record.rollbackVersions).to.deep.equal(['1.1.0']);
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'healthy',
            );
            expect(store.read('externalExtensionData')).to.deep.equal(
                preservedProjects,
            );
            expect(
                manager
                    .getCatalog()
                    .entries.find(
                        (entry) => entry.id === EXECUTABLE_EXTENSION_ID,
                    ),
            ).to.include({
                installedVersion: '1.2.0',
                availableVersion: '1.2.0',
                updateAvailable: false,
                rollbackAvailable: true,
            });

            const current = await manager.update(EXECUTABLE_EXTENSION_ID);
            expect(current).to.include({ status: 'current', noOp: true });
            expect(current.record).to.include({
                version: '1.2.0',
                enabled: true,
            });

            manager.removeSource(source.id);
            const rolledBack = manager.rollback(EXECUTABLE_EXTENSION_ID);
            expect(rolledBack.status).to.equal('rolled-back-enabled');
            expect(rolledBack.record).to.include({
                version: '1.1.0',
                enabled: true,
                rollbackAvailable: false,
            });
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'healthy',
            );
            expect(store.read('externalExtensionData')).to.deep.equal(
                preservedProjects,
            );
            await manager.addSource({ url: repository.sourceUrl });
            expect(
                manager
                    .getCatalog()
                    .entries.find(
                        (entry) => entry.id === EXECUTABLE_EXTENSION_ID,
                    ),
            ).to.include({
                installedVersion: '1.1.0',
                availableVersion: '1.2.0',
                updateAvailable: true,
            });

            activeCatalog = v3.catalog;
            let activationError;
            try {
                await manager.update(EXECUTABLE_EXTENSION_ID);
            } catch (error) {
                activationError = error;
            }
            expect(activationError).to.have.property(
                'code',
                'TEST_EXTENSION_ACTIVATION_FAILED',
            );
            expect(activationError.details).to.include({
                attemptedVersion: '1.3.0',
                restoredVersion: '1.1.0',
                restored: true,
            });
            expect(manager.getRecord(EXECUTABLE_EXTENSION_ID)).to.include({
                version: '1.1.0',
                enabled: true,
            });
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'healthy',
            );
            expect(store.read('externalExtensionData')).to.deep.equal(
                preservedProjects,
            );
        } finally {
            clearExtensionRegistryForTests();
            resetExtensionManagerForTests();
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('installs, downgrades, upgrades, and reinstalls exact remote release versions', async function () {
        const v1 = executableRelease({ version: '1.1.0' });
        const v2 = executableRelease({ version: '1.2.0' });
        const v3 = executableRelease({ version: '1.3.0' });
        let activeCatalog = clone(v3.catalog);
        activeCatalog.entries[0].releases = [v3, v2, v1].map(
            (release, index) => ({
                ...clone(release.catalog.entries[0]),
                releasedAt: `2026-08-${12 - index}T01:00:00.000Z`,
                gitTag: `${EXECUTABLE_EXTENSION_ID}@${release.packageDocument.manifest.version}`,
            }),
        );
        const packages = new Map(
            [v1, v2, v3].map((release) => [
                release.packageUrl,
                release.packageDocument,
            ]),
        );
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-remote-release-selection-'),
        );
        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url === v3.sourceUrl
                            ? activeCatalog
                            : packages.get(url),
                    ),
            });
            await manager.addSource({ url: v3.sourceUrl });

            expect(manager.findEntry(EXECUTABLE_EXTENSION_ID)).to.include({
                version: '1.3.0',
            });
            expect(
                manager.findEntry(EXECUTABLE_EXTENSION_ID, {
                    version: '1.2.0',
                }),
            ).to.include({ version: '1.2.0' });
            expect(
                manager
                    .getCatalog()
                    .entries.find(
                        (entry) => entry.id === EXECUTABLE_EXTENSION_ID,
                    )
                    .releases.map((release) => release.version),
            ).to.deep.equal(['1.3.0', '1.2.0', '1.1.0']);

            const { app, handlers } = createRouteApp();
            registerExtensionControlRoutes(app, manager);
            const installResponse = createApiResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: EXECUTABLE_EXTENSION_ID },
                    body: { version: '1.2.0' },
                    headers: {},
                    extensionAdmin: true,
                },
                installResponse,
            );
            expect(installResponse.statusCode).to.equal(201);
            expect(installResponse.body.data.record.version).to.equal('1.2.0');

            manager.enable(EXECUTABLE_EXTENSION_ID);

            const downgraded = await manager.update(EXECUTABLE_EXTENSION_ID, {
                version: '1.1.0',
            });
            expect(downgraded).to.include({ status: 'updated-enabled' });
            expect(downgraded.record).to.include({
                version: '1.1.0',
                enabled: true,
            });

            const upgraded = await manager.update(EXECUTABLE_EXTENSION_ID);
            expect(upgraded.record).to.include({
                version: '1.3.0',
                enabled: true,
            });

            const reinstalledCurrent = await manager.update(
                EXECUTABLE_EXTENSION_ID,
                {
                    version: '1.3.0',
                    reinstall: true,
                },
            );
            expect(reinstalledCurrent).to.include({
                status: 'updated-enabled',
            });
            expect(reinstalledCurrent).to.not.have.property('noOp');
            expect(reinstalledCurrent.record).to.include({
                version: '1.3.0',
                enabled: true,
            });
            expect(reinstalledCurrent.record.rollbackVersions).to.not.include(
                '1.3.0',
            );

            const currentRecord = manager.getRecord(EXECUTABLE_EXTENSION_ID);
            fs.writeFileSync(
                currentRecord.entrypoint,
                'module.exports = { tampered: true };',
                'utf8',
            );
            expect(() => manager.getHealth(EXECUTABLE_EXTENSION_ID)).to.not
                .throw;
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'unhealthy',
            );
            const repairedCurrent = await manager.update(
                EXECUTABLE_EXTENSION_ID,
                {
                    version: '1.3.0',
                    reinstall: true,
                },
            );
            expect(repairedCurrent).to.include({ status: 'updated-enabled' });
            expect(manager.getHealth(EXECUTABLE_EXTENSION_ID).status).to.equal(
                'healthy',
            );

            activeCatalog = clone(v2.catalog);
            activeCatalog.entries[0].releases = [
                clone(v2.catalog.entries[0]),
                clone(v1.catalog.entries[0]),
            ];
            const noDowngrade = await manager.update(EXECUTABLE_EXTENSION_ID);
            expect(noDowngrade).to.include({ status: 'current', noOp: true });
            expect(noDowngrade.record.version).to.equal('1.3.0');

            manager.disable(EXECUTABLE_EXTENSION_ID);
            manager.uninstall(EXECUTABLE_EXTENSION_ID);
            const reinstalled = await manager.installFromSource(
                EXECUTABLE_EXTENSION_ID,
                { version: '1.2.0' },
            );
            expect(reinstalled.record.version).to.equal('1.2.0');
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('does not install provenance-only releases and guards storage schema downgrades', async function () {
        const v1 = executableRelease({
            version: '1.1.0',
            storageSchemaVersion: 1,
        });
        const v2 = executableRelease({
            version: '1.2.0',
            storageSchemaVersion: 2,
        });
        const catalog = clone(v2.catalog);
        catalog.entries[0].releases = [
            clone(v2.catalog.entries[0]),
            { ...clone(v1.catalog.entries[0]), installable: false },
        ];
        const packages = new Map([
            [v1.packageUrl, v1.packageDocument],
            [v2.packageUrl, v2.packageDocument],
        ]);
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(url === v2.sourceUrl ? catalog : packages.get(url)),
        });
        await manager.addSource({ url: v2.sourceUrl });
        expect(
            manager.findEntry(EXECUTABLE_EXTENSION_ID, {
                version: '1.1.0',
            }),
        ).to.equal(null);
        let unavailableError;
        try {
            await manager.installFromSource(EXECUTABLE_EXTENSION_ID, {
                version: '1.1.0',
            });
        } catch (error) {
            unavailableError = error;
        }
        expect(unavailableError).to.have.property(
            'code',
            'EXTENSION_VERSION_UNAVAILABLE',
        );

        const installableCatalog = clone(v2.catalog);
        installableCatalog.entries[0].releases = [
            clone(v2.catalog.entries[0]),
            clone(v1.catalog.entries[0]),
        ];
        const schemaManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(
                    url === v2.sourceUrl
                        ? installableCatalog
                        : packages.get(url),
                ),
        });
        await schemaManager.addSource({ url: v2.sourceUrl });
        await schemaManager.installFromSource(EXECUTABLE_EXTENSION_ID);
        let schemaError;
        try {
            await schemaManager.update(EXECUTABLE_EXTENSION_ID, {
                version: '1.1.0',
            });
        } catch (error) {
            schemaError = error;
        }
        expect(schemaError).to.have.property(
            'code',
            'EXTENSION_STORAGE_SCHEMA_DOWNGRADE_FORBIDDEN',
        );
        expect(schemaError.details).to.include({
            installedVersion: '1.2.0',
            targetVersion: '1.1.0',
            installedStorageSchemaVersion: 2,
            targetStorageSchemaVersion: 1,
        });
    });

    it('keeps only three verified rollback packages and removes the pruned version from disk', async function () {
        const repository = executableRelease();
        const releases = ['1.2.0', '1.3.0', '1.4.0', '1.5.0'].map((version) =>
            executableRelease({
                version,
            }),
        );
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-version-history-'),
        );
        let activeCatalog = repository.catalog;
        const packages = new Map([
            [repository.packageUrl, repository.packageDocument],
            ...releases.map((release) => [
                release.packageUrl,
                release.packageDocument,
            ]),
        ]);
        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url === repository.sourceUrl
                            ? activeCatalog
                            : packages.get(url),
                    ),
            });
            await manager.addSource({ url: repository.sourceUrl });
            await manager.installFromSource(EXECUTABLE_EXTENSION_ID);
            const packageDirectories = new Map([
                [
                    '1.1.0',
                    manager.getRecord(EXECUTABLE_EXTENSION_ID).packageDirectory,
                ],
            ]);

            for (const release of releases) {
                activeCatalog = release.catalog;
                const updated = await manager.update(EXECUTABLE_EXTENSION_ID);
                expect(updated.status).to.equal('updated-disabled');
                expect(updated).not.to.have.property('cleanupWarning');
                const record = manager.getRecord(EXECUTABLE_EXTENSION_ID);
                packageDirectories.set(record.version, record.packageDirectory);
            }

            const current = manager.getRecord(EXECUTABLE_EXTENSION_ID);
            expect(current.version).to.equal('1.5.0');
            expect(
                current.rollbackHistory.map(({ version }) => version),
            ).to.deep.equal(['1.2.0', '1.3.0', '1.4.0']);
            expect(fs.existsSync(packageDirectories.get('1.1.0'))).to.equal(
                false,
            );
            for (const version of ['1.2.0', '1.3.0', '1.4.0', '1.5.0']) {
                expect(
                    fs.existsSync(packageDirectories.get(version)),
                    `expected ${version} package to remain available`,
                ).to.equal(true);
            }
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('does not expose unverifiable rollback history for community content updates', async function () {
        const v1 = contentFixture();
        const v2 = contentFixture({
            version: '1.1.0',
            content: '{"hello":"updated"}',
        });
        const sourceUrl = 'https://example.test/content-catalog.json';
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-content-update-'),
        );
        let activeFixture = v1;
        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url === sourceUrl
                            ? activeFixture.catalog
                            : activeFixture.packageDocument,
                    ),
            });
            await manager.addSource({ url: sourceUrl });
            await manager.installFromSource(v1.manifest.id);
            const previous = manager.getRecord(v1.manifest.id);
            expect(fs.existsSync(previous.packageDirectory)).to.equal(true);

            activeFixture = v2;
            const updated = await manager.update(v1.manifest.id);
            expect(updated.status).to.equal('updated-disabled');
            expect(updated).not.to.have.property('cleanupWarning');
            expect(updated.record).to.include({
                version: '1.1.0',
                rollbackAvailable: false,
            });
            expect(updated.record.rollbackVersions).to.deep.equal([]);
            const current = manager.getRecord(v1.manifest.id);
            expect(current.rollbackHistory).to.deep.equal([]);
            expect(fs.existsSync(previous.packageDirectory)).to.equal(false);
            expect(fs.existsSync(current.packageDirectory)).to.equal(true);
            expect(() => manager.rollback(v1.manifest.id)).to.throw(
                'No verified rollback version is available',
            );
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('rejects an immutable source version whose package digest changes during refresh', async function () {
        const fixture = contentFixture();
        const sourceUrl = 'https://example.test/immutable-catalog.json';
        let activeCatalog = fixture.catalog;
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(activeCatalog),
        });
        const source = await manager.addSource({ url: sourceUrl });
        const changedPackage = clone(fixture.packageDocument);
        changedPackage.payload.files['content.json'] = '{"hello":"changed"}';
        const changedDigest = resealCommunityPackage(changedPackage);
        activeCatalog = clone(fixture.catalog);
        activeCatalog.entries[0].packageDigest = changedDigest;
        activeCatalog.entries[0].packageDigests.node = changedDigest;

        let refreshError;
        try {
            await manager.refreshSource(source.id);
        } catch (error) {
            refreshError = error;
        }
        expect(refreshError).to.have.property(
            'code',
            'EXTENSION_SOURCE_VERSION_MUTATED',
        );
        expect(manager.getSources()[0].entries[0].packageDigests.node).to.equal(
            fixture.packageDigest,
        );
    });

    it('rejects installability and package URL drift for historical releases during refresh', async function () {
        const v1 = executableRelease({ version: '1.1.0' });
        const v2 = executableRelease({ version: '1.2.0' });
        const sourceUrl = v2.sourceUrl;
        let activeCatalog = clone(v2.catalog);
        activeCatalog.entries[0].releases = [
            clone(v2.catalog.entries[0]),
            { ...clone(v1.catalog.entries[0]), installable: false },
        ];
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(activeCatalog),
        });
        const source = await manager.addSource({ url: sourceUrl });
        const originalRelease = manager
            .getSources()[0]
            .entries[0].releases.find((release) => release.version === '1.1.0');

        activeCatalog = clone(activeCatalog);
        activeCatalog.entries[0].releases[1].installable = true;
        let installabilityError;
        try {
            await manager.refreshSource(source.id);
        } catch (error) {
            installabilityError = error;
        }
        expect(installabilityError).to.have.property(
            'code',
            'EXTENSION_SOURCE_VERSION_MUTATED',
        );

        activeCatalog = clone(v2.catalog);
        activeCatalog.entries[0].releases = [
            clone(v2.catalog.entries[0]),
            {
                ...clone(v1.catalog.entries[0]),
                installable: false,
                packageUrls: {
                    node: 'https://example.test/extensions/moved-1.1.0.json',
                },
            },
        ];
        let urlError;
        try {
            await manager.refreshSource(source.id);
        } catch (error) {
            urlError = error;
        }
        expect(urlError).to.have.property(
            'code',
            'EXTENSION_SOURCE_VERSION_MUTATED',
        );
        expect(
            manager
                .getSources()[0]
                .entries[0].releases.find(
                    (release) => release.version === '1.1.0',
                ),
        ).to.deep.equal(originalRelease);
    });

    it('rejects executable source digest drift and package tampering', async function () {
        const repository = executableRelease();
        const changedDigestCatalog = clone(repository.catalog);
        changedDigestCatalog.entries[0].packageDigest = '0'.repeat(64);
        changedDigestCatalog.entries[0].packageDigests.node = '0'.repeat(64);
        const digestManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(
                    url === repository.sourceUrl
                        ? changedDigestCatalog
                        : repository.packageDocument,
                ),
        });
        await digestManager.addSource({ url: repository.sourceUrl });
        let digestError;
        try {
            await digestManager.installFromSource(EXECUTABLE_EXTENSION_ID);
        } catch (error) {
            digestError = error;
        }
        expect(digestError).to.have.property(
            'code',
            'EXTENSION_SOURCE_PACKAGE_DIGEST_MISMATCH',
        );

        const tamperedPackage = clone(repository.packageDocument);
        tamperedPackage.payload.files['backend/index.cjs'] += '\n// tampered';
        const packageManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(
                    url === repository.sourceUrl
                        ? repository.catalog
                        : tamperedPackage,
                ),
        });
        await packageManager.addSource({ url: repository.sourceUrl });
        let packageError;
        try {
            await packageManager.installFromSource(EXECUTABLE_EXTENSION_ID);
        } catch (error) {
            packageError = error;
        }
        expect(packageError).to.have.property(
            'code',
            'EXTENSION_PACKAGE_DIGEST_INVALID',
        );
        expect(packageManager.getRecord(EXECUTABLE_EXTENSION_ID)).to.equal(
            null,
        );

        const forbiddenCatalog = clone(repository.catalog);
        forbiddenCatalog.entries[0].manifest.kind = 'trusted-official';
        const forbiddenManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(forbiddenCatalog),
        });
        let forbiddenError;
        try {
            await forbiddenManager.addSource({ url: repository.sourceUrl });
        } catch (error) {
            forbiddenError = error;
        }
        expect(forbiddenError).to.have.property(
            'code',
            'EXTENSION_COMMUNITY_EXECUTION_FORBIDDEN',
        );
    });

    it('installs an inline content package from a catalog snapshot without refetching it', async function () {
        const fixture = contentFixture();
        const inlineCatalog = {
            schemaVersion: 1,
            entries: [fixture.packageDocument],
        };
        let fetchCount = 0;
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => {
                fetchCount += 1;
                return response(inlineCatalog);
            },
        });
        await manager.addSource({
            url: 'https://example.test/inline-catalog.json',
        });
        const installed = await manager.installFromSource(fixture.manifest.id);
        expect(installed.record.extensionId).to.equal(fixture.manifest.id);
        expect(fetchCount).to.equal(1);
        expect(manager.getSources()[0].entries[0]).not.to.have.property(
            'inlinePackage',
        );
    });

    it('stages an unsigned community content package without loading executable code', async function () {
        const fixture = contentFixture();
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-source-'),
        );
        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
                sourceFetcher: async (url) =>
                    response(
                        url.endsWith('catalog.json')
                            ? fixture.catalog
                            : fixture.packageDocument,
                    ),
            });
            const source = await manager.addSource({
                url: 'https://example.test/catalog.json',
            });
            const result = await manager.installFromSource(fixture.manifest.id);
            expect(result.record.packageDirectory).to.equal(undefined);
            expect(manager.getRecord(fixture.manifest.id).codeStatus).to.equal(
                'verified-package-installed',
            );
            expect(manager.removeSource(source.id).status).to.equal('removed');
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('rejects duplicate community extension ids across different sources', async function () {
        const fixture = contentFixture();
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(fixture.catalog),
        });
        await manager.addSource({ url: 'https://example.test/one.json' });
        let error;
        try {
            await manager.addSource({ url: 'https://example.test/two.json' });
        } catch (caught) {
            error = caught;
        }
        expect(error).to.have.property('code', 'EXTENSION_SOURCE_ID_CONFLICT');
    });

    it('verifies file digests and receipt closure without a package store', async function () {
        const fixture = contentFixture();
        const packageDocument = clone(fixture.packageDocument);
        packageDocument.payload.files['content.json'] = '{"tampered":true}';
        const packageDigest = resealCommunityPackage(packageDocument);
        const catalog = clone(fixture.catalog);
        catalog.entries[0].packageDigests.node = packageDigest;
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(
                    url.endsWith('catalog.json') ? catalog : packageDocument,
                ),
        });
        await manager.addSource({ url: 'https://example.test/catalog.json' });
        let fileError;
        try {
            await manager.installFromSource(fixture.manifest.id);
        } catch (caught) {
            fileError = caught;
        }
        expect(fileError).to.have.property(
            'code',
            'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH',
        );

        const receiptFixture = contentFixture();
        const receiptDocument = clone(receiptFixture.packageDocument);
        receiptDocument.payload.receipt.receiptDigest = '0'.repeat(64);
        receiptDocument.receipt = clone(receiptDocument.payload.receipt);
        const payloadDigest = sha256Hex(canonicalJson(receiptDocument.payload));
        receiptDocument.signature.digest = payloadDigest;
        receiptDocument.signature.value = payloadDigest;
        const receiptManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async (url) =>
                response(
                    url.endsWith('catalog.json')
                        ? receiptFixture.catalog
                        : receiptDocument,
                ),
        });
        await receiptManager.addSource({
            url: 'https://example.test/catalog.json',
        });
        let receiptError;
        try {
            await receiptManager.installFromSource(receiptFixture.manifest.id);
        } catch (caught) {
            receiptError = caught;
        }
        expect(receiptError).to.have.property(
            'code',
            'EXTENSION_RECEIPT_DIGEST_MISMATCH',
        );
    });
});

import { expect } from 'chai';
import { describe, it } from 'mocha';
import {
    EXTENSION_IDS,
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
import dns from 'dns';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

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

function staticConfigGeneratorRepository() {
    const repositoryRoot = path.resolve(
        process.cwd(),
        'src/test/fixtures/extensions/repository',
    );
    const catalog = JSON.parse(
        fs.readFileSync(path.join(repositoryRoot, 'catalog.json'), 'utf8'),
    );
    const sourceUrl =
        'https://raw.githubusercontent.com/dompling/Sub-Store-Extensions/main/repository/catalog.json';
    const packageUrl = new URL(
        catalog.entries[0].packageUrl,
        sourceUrl,
    ).toString();
    const packageDocument = JSON.parse(
        fs.readFileSync(
            path.join(
                repositoryRoot,
                catalog.entries[0].packageUrl.replace(/^\.\//, ''),
            ),
            'utf8',
        ),
    );
    return { catalog, packageDocument, packageUrl, sourceUrl };
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

function signedConfigGeneratorRelease(
    repository,
    {
        version,
        keyId,
        privateKey,
        packageUrl = `https://example.test/config-generator-${version}.json`,
        backendEntrypoint,
    },
) {
    const packageDocument = clone(repository.packageDocument);
    const manifest = normalizeExtensionManifest({
        ...packageDocument.manifest,
        version,
        frontend: {
            ...packageDocument.manifest.frontend,
            embeddedBasePath: `extensions/${EXTENSION_IDS.configGenerator}/${version}`,
        },
    });
    const payload = packageDocument.payload;
    payload.manifest = clone(manifest);
    payload.variant = clone(manifest.variants.node);
    if (backendEntrypoint) {
        payload.files['backend/index.cjs'] = backendEntrypoint;
    }
    payload.fileDigests = Object.fromEntries(
        Object.entries(payload.files).map(([name, content]) => [
            name,
            sha256Hex(content),
        ]),
    );
    const packageDigest = extensionPackageDigest(payload);
    const receipt = createDigestReceipt({
        manifest,
        packageDigest,
        variant: 'node',
        implementation: clone(
            repository.packageDocument.receipt.implementation,
        ),
        now: Date.parse('2026-08-11T00:00:00.000Z'),
    });
    payload.packageDigest = packageDigest;
    payload.receipt = clone(receipt);
    const serializedPayload = canonicalJson(payload);
    const payloadDigest = sha256Hex(serializedPayload);
    packageDocument.manifest = clone(manifest);
    packageDocument.packageDigest = packageDigest;
    packageDocument.receipt = clone(receipt);
    packageDocument.signature = {
        algorithm: 'ed25519',
        keyId,
        digest: payloadDigest,
        value: crypto
            .sign(null, Buffer.from(serializedPayload), privateKey)
            .toString('base64'),
    };

    const catalog = clone(repository.catalog);
    const entry = catalog.entries[0];
    Object.assign(entry, {
        id: manifest.id,
        version: manifest.version,
        name: manifest.name,
        description: manifest.description,
        kind: manifest.kind,
        manifest: clone(manifest),
        packageUrl,
        packageDigest,
        packageUrls: { node: packageUrl },
        packageDigests: { node: packageDigest },
    });
    return { catalog, packageDocument, packageUrl };
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
    it('normalizes GitHub blob links and rejects URL credentials/private HTTP', function () {
        expect(
            normalizeExtensionSourceUrl(
                'https://github.com/example/repo/blob/main/catalog.json?channel=beta#fragment',
            ),
        ).to.equal(
            'https://raw.githubusercontent.com/example/repo/main/catalog.json?channel=beta',
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

    it('installs the signed config-generator mirror through its complete lifecycle', async function () {
        const repository = staticConfigGeneratorRepository();
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-official-mirror-'),
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

            const source = await manager.addSource({
                url: repository.sourceUrl,
                name: 'GitHub official mirror',
            });
            expect(source.publisher).to.deep.equal({
                id: 'org.substore',
                name: 'Sub-Store',
            });
            expect(source.entries).to.have.length(1);
            expect(source.entries[0]).to.include({
                id: EXTENSION_IDS.configGenerator,
                distribution: 'trusted-official-mirror',
                source: repository.sourceUrl,
            });
            expect(source.entries[0].packageUrls.node).to.equal(
                repository.packageUrl,
            );

            const catalogEntry = manager
                .getCatalog()
                .entries.find(
                    (entry) => entry.id === EXTENSION_IDS.configGenerator,
                );
            expect(catalogEntry).to.include({
                sourceId: source.id,
                sourceName: 'Sub-Store Extensions',
                sourceUrl: repository.sourceUrl,
            });
            expect(catalogEntry.packageUrls.node).to.equal(
                repository.packageUrl,
            );
            expect(manager.findEntry(EXTENSION_IDS.configGenerator)).to.include(
                { remotePackage: true, sourceId: source.id },
            );

            const installed = await manager.installFromSource(
                EXTENSION_IDS.configGenerator,
            );
            expect(installed.record).to.include({
                extensionId: EXTENSION_IDS.configGenerator,
                verificationMode: 'trusted-signature',
                sourceId: source.id,
                sourceUrl: repository.sourceUrl,
                codeStatus: 'verified-package-installed',
            });
            expect(
                manager.getRecord(EXTENSION_IDS.configGenerator)
                    .packageDirectory,
            ).to.be.a('string');

            expect(
                manager.enable(EXTENSION_IDS.configGenerator).status,
            ).to.equal('enabled');
            expect(
                manager.getHealth(EXTENSION_IDS.configGenerator).status,
            ).to.equal('healthy');
            expect(
                manager.disable(EXTENSION_IDS.configGenerator).status,
            ).to.equal('disabled');
            expect(
                manager.getAvailability(EXTENSION_IDS.configGenerator).status,
            ).to.equal('disabled');

            const uninstalled = manager.uninstall(
                EXTENSION_IDS.configGenerator,
            );
            expect(uninstalled.status).to.equal('reinstall-required');
            expect(uninstalled.record.codeStatus).to.equal('removed');

            const reinstalled = await manager.installFromSource(
                EXTENSION_IDS.configGenerator,
            );
            expect(reinstalled.status).to.equal('installed-disabled');
            expect(
                manager.enable(EXTENSION_IDS.configGenerator).status,
            ).to.equal('enabled');
            expect(
                manager.getHealth(EXTENSION_IDS.configGenerator).status,
            ).to.equal('healthy');
            manager.disable(EXTENSION_IDS.configGenerator);
            manager.uninstall(EXTENSION_IDS.configGenerator);
        } finally {
            clearExtensionRegistryForTests();
            resetExtensionManagerForTests();
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('updates an enabled signed extension, preserves data, rolls back, and restores after activation failure', async function () {
        const repository = staticConfigGeneratorRepository();
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const testKeyId = 'config-generator-update-test-key';
        const v2 = signedConfigGeneratorRelease(repository, {
            version: '1.2.0',
            keyId: testKeyId,
            privateKey,
        });
        const v3 = signedConfigGeneratorRelease(repository, {
            version: '1.3.0',
            keyId: testKeyId,
            privateKey,
            backendEntrypoint: `'use strict';
module.exports = Object.freeze({
    extensionId: '${EXTENSION_IDS.configGenerator}',
    implementationAbi: 'config-generator@1',
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
        store.write(preservedProjects, 'configGenerator');
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
                trustedKeys: {
                    [testKeyId]: publicKey.export({
                        type: 'spki',
                        format: 'pem',
                    }),
                },
                trustedOfficialKeyIds: {
                    [EXTENSION_IDS.configGenerator]: [
                        repository.packageDocument.signature.keyId,
                        testKeyId,
                    ],
                },
                adoptLegacy: false,
                restoreEnabled: false,
            });
            const manager = host.manager;
            const source = await manager.addSource({
                url: repository.sourceUrl,
            });
            await manager.installFromSource(EXTENSION_IDS.configGenerator);
            manager.enable(EXTENSION_IDS.configGenerator);

            activeCatalog = v2.catalog;
            const updated = await manager.update(EXTENSION_IDS.configGenerator);
            expect(updated.status).to.equal('updated-enabled');
            expect(updated.record).to.include({
                version: '1.2.0',
                enabled: true,
                rollbackAvailable: true,
            });
            expect(updated.record.rollbackVersions).to.deep.equal(['1.1.0']);
            expect(
                manager.getHealth(EXTENSION_IDS.configGenerator).status,
            ).to.equal('healthy');
            expect(store.read('configGenerator')).to.deep.equal(
                preservedProjects,
            );
            expect(
                manager
                    .getCatalog()
                    .entries.find(
                        (entry) => entry.id === EXTENSION_IDS.configGenerator,
                    ),
            ).to.include({
                installedVersion: '1.2.0',
                availableVersion: '1.2.0',
                updateAvailable: false,
                rollbackAvailable: true,
            });

            manager.removeSource(source.id);
            const rolledBack = manager.rollback(EXTENSION_IDS.configGenerator);
            expect(rolledBack.status).to.equal('rolled-back-enabled');
            expect(rolledBack.record).to.include({
                version: '1.1.0',
                enabled: true,
                rollbackAvailable: false,
            });
            expect(
                manager.getHealth(EXTENSION_IDS.configGenerator).status,
            ).to.equal('healthy');
            expect(store.read('configGenerator')).to.deep.equal(
                preservedProjects,
            );
            await manager.addSource({ url: repository.sourceUrl });
            expect(
                manager
                    .getCatalog()
                    .entries.find(
                        (entry) => entry.id === EXTENSION_IDS.configGenerator,
                    ),
            ).to.include({
                installedVersion: '1.1.0',
                availableVersion: '1.2.0',
                updateAvailable: true,
            });

            activeCatalog = v3.catalog;
            let activationError;
            try {
                await manager.update(EXTENSION_IDS.configGenerator);
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
            expect(manager.getRecord(EXTENSION_IDS.configGenerator)).to.include(
                { version: '1.1.0', enabled: true },
            );
            expect(
                manager.getHealth(EXTENSION_IDS.configGenerator).status,
            ).to.equal('healthy');
            expect(store.read('configGenerator')).to.deep.equal(
                preservedProjects,
            );
        } finally {
            clearExtensionRegistryForTests();
            resetExtensionManagerForTests();
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('keeps only three verified rollback packages and removes the pruned version from disk', async function () {
        const repository = staticConfigGeneratorRepository();
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const testKeyId = 'config-generator-history-test-key';
        const releases = ['1.2.0', '1.3.0', '1.4.0', '1.5.0'].map((version) =>
            signedConfigGeneratorRelease(repository, {
                version,
                keyId: testKeyId,
                privateKey,
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
                trustedKeys: {
                    [testKeyId]: publicKey.export({
                        type: 'spki',
                        format: 'pem',
                    }),
                },
                trustedOfficialKeyIds: {
                    [EXTENSION_IDS.configGenerator]: [
                        repository.packageDocument.signature.keyId,
                        testKeyId,
                    ],
                },
            });
            await manager.addSource({ url: repository.sourceUrl });
            await manager.installFromSource(EXTENSION_IDS.configGenerator);
            const packageDirectories = new Map([
                [
                    '1.1.0',
                    manager.getRecord(EXTENSION_IDS.configGenerator)
                        .packageDirectory,
                ],
            ]);

            for (const release of releases) {
                activeCatalog = release.catalog;
                const updated = await manager.update(
                    EXTENSION_IDS.configGenerator,
                );
                expect(updated.status).to.equal('updated-disabled');
                expect(updated).not.to.have.property('cleanupWarning');
                const record = manager.getRecord(EXTENSION_IDS.configGenerator);
                packageDirectories.set(record.version, record.packageDirectory);
            }

            const current = manager.getRecord(EXTENSION_IDS.configGenerator);
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

    it('rejects unauthorized or tampered executable source mirrors', async function () {
        const repository = staticConfigGeneratorRepository();
        const rogueKeys = crypto.generateKeyPairSync('ed25519');
        const rogueKeyId = 'globally-trusted-but-wrong-extension-key';
        const rogueRelease = signedConfigGeneratorRelease(repository, {
            version: '1.2.0',
            keyId: rogueKeyId,
            privateKey: rogueKeys.privateKey,
        });
        const wrongKeyManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            trustedKeys: {
                [rogueKeyId]: rogueKeys.publicKey.export({
                    type: 'spki',
                    format: 'pem',
                }),
            },
            sourceFetcher: async (url) =>
                response(
                    url === repository.sourceUrl
                        ? rogueRelease.catalog
                        : rogueRelease.packageDocument,
                ),
        });
        await wrongKeyManager.addSource({ url: repository.sourceUrl });
        let wrongKeyError;
        try {
            await wrongKeyManager.installFromSource(
                EXTENSION_IDS.configGenerator,
            );
        } catch (error) {
            wrongKeyError = error;
        }
        expect(wrongKeyError).to.have.property(
            'code',
            'EXTENSION_SIGNING_KEY_NOT_ALLOWED',
        );

        const arbitraryExecutableCatalog = clone(repository.catalog);
        arbitraryExecutableCatalog.entries[0].id =
            'com.example.executable-extension';
        arbitraryExecutableCatalog.entries[0].manifest.id =
            'com.example.executable-extension';
        const arbitraryManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(arbitraryExecutableCatalog),
        });
        let arbitraryError;
        try {
            await arbitraryManager.addSource({ url: repository.sourceUrl });
        } catch (error) {
            arbitraryError = error;
        }
        expect(arbitraryError).to.have.property(
            'code',
            'EXTENSION_SOURCE_MANIFEST_INVALID',
        );

        const changedManifestCatalog = clone(repository.catalog);
        changedManifestCatalog.entries[0].manifest.description =
            'Untrusted replacement';
        const manifestManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(changedManifestCatalog),
        });
        let manifestError;
        try {
            await manifestManager.addSource({ url: repository.sourceUrl });
        } catch (error) {
            manifestError = error;
        }
        expect(manifestError).to.have.property(
            'code',
            'EXTENSION_SOURCE_OFFICIAL_MIRROR_UNAUTHORIZED',
        );

        const changedDigestCatalog = clone(repository.catalog);
        changedDigestCatalog.entries[0].packageDigest = '0'.repeat(64);
        changedDigestCatalog.entries[0].packageDigests.node = '0'.repeat(64);
        const digestManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            packageStore: null,
            sourceFetcher: async () => response(changedDigestCatalog),
        });
        let digestError;
        try {
            await digestManager.addSource({ url: repository.sourceUrl });
        } catch (error) {
            digestError = error;
        }
        expect(digestError).to.have.property(
            'code',
            'EXTENSION_CATALOG_PACKAGE_MISMATCH',
        );

        const tamperedPackage = clone(repository.packageDocument);
        tamperedPackage.signature.value = `${tamperedPackage.signature.value.slice(
            0,
            -2,
        )}AA`;
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
            await packageManager.installFromSource(
                EXTENSION_IDS.configGenerator,
            );
        } catch (error) {
            packageError = error;
        }
        expect(packageError).to.have.property(
            'code',
            'EXTENSION_SIGNATURE_INVALID',
        );
        expect(
            packageManager.getRecord(EXTENSION_IDS.configGenerator),
        ).to.equal(null);
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

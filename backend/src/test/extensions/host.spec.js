import { expect } from 'chai';
import { describe, it } from 'mocha';
import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { ARTIFACTS_KEY } from '@/constants';
import {
    EXTENSION_IDS,
    canonicalJson,
    extensionAvailability,
    normalizeExtensionManifest,
    routeExecutionLane,
} from '@/extensions/contracts';
import {
    createLocalOfficialPackage,
    embeddedExtensionImplementations,
    officialExtensionTrustedKeys,
    signedExtensionCatalog,
} from '@/extensions/catalog.generated';
import {
    ExtensionManager,
    resetExtensionManagerForTests,
} from '@/extensions/manager';
import { createNodeExtensionPackageStore } from '@/extensions/package-store';
import { sha256Hex, verifySignedEnvelope } from '@/extensions/signature';
import { initializeExtensionHost } from '@/extensions/host';
import { registerExtensionControlRoutes } from '@/restful/extensions';
import configHostingManifest from '@/extensions/config-hosting/manifest.json';
import {
    createConfigHostingAdapter,
    createConfigHostingRouteApps,
} from '@/extensions/config-hosting';
import {
    clearExtensionRegistryForTests,
    registerExtension,
    resolveExtensionRouteLane,
} from '@/extensions/registry';

const EXTERNAL_CONFIG_GENERATOR_ID = 'org.substore.config-generator';
const GENERIC_REMOTE_EXTENSION_ID = 'org.example.remote-extension';

function createStore(initial) {
    return createKeyStore(
        initial === undefined
            ? {}
            : {
                  '#sub-store-extensions':
                      typeof initial === 'string'
                          ? initial
                          : JSON.stringify(initial),
              },
    );
}

function createKeyStore(initial = {}) {
    const values = { ...initial };
    let writes = 0;
    let writtenKeys = [];
    return {
        read(key) {
            return Object.prototype.hasOwnProperty.call(values, key)
                ? values[key]
                : undefined;
        },
        write(value, key) {
            values[key] = value;
            writes += 1;
            writtenKeys.push(key);
        },
        delete(key) {
            delete values[key];
            writes += 1;
            writtenKeys.push(key);
        },
        writes() {
            return writes;
        },
        writtenKeys() {
            return [...writtenKeys];
        },
        resetWrittenKeys() {
            writtenKeys = [];
        },
    };
}

function createRouteApp() {
    const handlers = new Map();
    const app = {};
    for (const method of ['get', 'post', 'delete']) {
        app[method] = (path, handler) => {
            handlers.set(`${method.toUpperCase()} ${path}`, handler);
            return app;
        };
    }
    return { app, handlers };
}

function createExpressLikeRouteApp() {
    const handlers = new Map();
    const app = {};
    const register = (method, routePath, routeHandlers) => {
        handlers.set(
            `${method.toUpperCase()} ${routePath}`,
            routeHandlers[routeHandlers.length - 1],
        );
        return app;
    };
    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
        app[method] = (routePath, ...routeHandlers) =>
            register(method, routePath, routeHandlers);
    }
    app.route = (routePath) => {
        const chain = {};
        for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
            chain[method] = (...routeHandlers) => {
                register(method, routePath, routeHandlers);
                return chain;
            };
        }
        return chain;
    };
    return { app, handlers };
}

function createResponse() {
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

describe('Extension Host foundation', function () {
    it('keeps the Host generic and lets config-generator packages self-register', function () {
        const hostSource = fs.readFileSync(
            path.resolve(process.cwd(), 'src/extensions/host.js'),
            'utf8',
        );
        expect(hostSource).to.not.include('configGeneratorAdapter');
        expect(hostSource).to.not.match(
            /config-generator\/(?:index|adapter|embedded)/,
        );
    });

    it('validates namespaced manifests and exposes product lane metadata', function () {
        const manifest = normalizeExtensionManifest(configHostingManifest);
        expect(manifest.id).to.equal(EXTENSION_IDS.configHosting);
        expect(routeExecutionLane(manifest, 'runtime/sync')).to.equal('parser');
        expect(routeExecutionLane(manifest, 'runtime/artifacts')).to.equal(
            'simple',
        );
        expect(routeExecutionLane(manifest, 'missing')).to.equal(null);
        const externalManifest = normalizeExtensionManifest({
            schemaVersion: 1,
            id: GENERIC_REMOTE_EXTENSION_ID,
            kind: 'executable',
            name: 'Generic remote extension',
            version: '1.0.0',
            publisher: { id: 'org.substore', name: 'Sub-Store' },
            host: { apiVersion: '1.0.0', runtimes: ['node'] },
            variants: {
                node: {
                    implementationId: `${GENERIC_REMOTE_EXTENSION_ID}@1/node`,
                    implementationAbi: 'remote-extension@1',
                    entrypoint: 'backend/index.cjs',
                    containsExecutableCode: true,
                },
            },
            scriptExecutionLanes: {
                simple: {
                    product: 'sub-store-0',
                    routes: ['projects'],
                },
                parser: {
                    product: 'sub-store-1',
                    routes: ['preview/:target', 'download/config-project/**'],
                },
            },
        });
        registerExtension({
            extensionId: GENERIC_REMOTE_EXTENSION_ID,
            manifest: externalManifest,
        });
        try {
            expect(
                resolveExtensionRouteLane(
                    GENERIC_REMOTE_EXTENSION_ID,
                    '/api/extensions/remote-extension/preview/qx',
                ),
            ).to.equal('parser');
            expect(
                resolveExtensionRouteLane(
                    GENERIC_REMOTE_EXTENSION_ID,
                    '/api/extensions/remote-extension/projects',
                ),
            ).to.equal('simple');
            expect(
                resolveExtensionRouteLane(
                    GENERIC_REMOTE_EXTENSION_ID,
                    '/download/config-project/demo/QX',
                ),
            ).to.equal('parser');
        } finally {
            clearExtensionRegistryForTests();
        }
    });

    it('verifies the generated catalog and local packages with the built-in release root', function () {
        const result = verifySignedEnvelope(signedExtensionCatalog, {
            trustedKeys: officialExtensionTrustedKeys,
        });
        expect(result.valid).to.equal(true);
        expect(result.trust).to.equal('trusted');
        expect(canonicalJson(signedExtensionCatalog.payload)).to.be.a('string');
        for (const runtime of ['node', 'qx', 'loon', 'surge', 'stash']) {
            const packageInput = createLocalOfficialPackage(
                EXTENSION_IDS.configHosting,
                runtime,
            );
            const packageResult = verifySignedEnvelope(
                {
                    payload: packageInput.payload,
                    signature: packageInput.signature,
                },
                { trustedKeys: officialExtensionTrustedKeys },
            );
            expect(packageResult).to.include({
                valid: true,
                trust: 'trusted',
            });
            const signedEntry = signedExtensionCatalog.payload.entries.find(
                (entry) => entry.id === EXTENSION_IDS.configHosting,
            );
            expect(
                signedEntry.packageDigests[packageInput.selectedVariant],
            ).to.equal(packageInput.packageDigest);
        }
        expect(
            createLocalOfficialPackage(EXTERNAL_CONFIG_GENERATOR_ID, 'node'),
        ).to.equal(null);
    });

    it('does not seed the third-party config-generator without an installed source', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
        });
        expect(manager.findEntry(EXTERNAL_CONFIG_GENERATOR_ID)).to.equal(null);
        expect(
            manager.getCatalog().entries.map((entry) => entry.id),
        ).to.not.include(EXTERNAL_CONFIG_GENERATOR_ID);
        expect(
            manager.getRuntimeManifest().extensions.map((entry) => entry.id),
        ).to.not.include(EXTERNAL_CONFIG_GENERATOR_ID);
        expect(
            manager.getAvailability(EXTERNAL_CONFIG_GENERATOR_ID).status,
        ).to.equal('missing');
        expect(
            createLocalOfficialPackage(EXTERNAL_CONFIG_GENERATOR_ID, 'node'),
        ).to.equal(null);
        expect(embeddedExtensionImplementations).to.not.have.property(
            EXTERNAL_CONFIG_GENERATOR_ID,
        );
        expect(() => manager.install(EXTERNAL_CONFIG_GENERATOR_ID))
            .to.throw()
            .with.property('code', 'EXTENSION_SOURCE_NOT_FOUND');
    });

    it('keeps digest-only verification disabled by default and reports its trust mode accurately', function () {
        const previous = process.env.SUB_STORE_EXTENSION_ALLOW_DIGEST_ONLY;
        delete process.env.SUB_STORE_EXTENSION_ALLOW_DIGEST_ONLY;
        try {
            const payload = signedExtensionCatalog.payload;
            const digest = sha256Hex(canonicalJson(payload));
            const digestOnlyEnvelope = {
                payload,
                expiresAt: signedExtensionCatalog.expiresAt,
                signature: {
                    algorithm: 'sha256-digest',
                    keyId: 'development-only',
                    digest,
                    value: digest,
                },
            };
            const productionManager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                catalogEnvelope: digestOnlyEnvelope,
            });
            expect(productionManager.getCatalog()).to.include({
                verified: false,
                verificationMode: 'unverified',
            });
            expect(
                productionManager.getRuntimeManifest().capabilities,
            ).to.include({
                supportsSignedCatalog: false,
                supportsIntegrityVerifiedCatalog: false,
            });
            expect(() =>
                productionManager.install(EXTENSION_IDS.configHosting),
            ).to.throw('catalog is not verified');

            const developmentManager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                allowDigestOnly: true,
                catalogEnvelope: digestOnlyEnvelope,
            });
            expect(developmentManager.getCatalog()).to.include({
                verified: true,
                verificationMode: 'digest-only-development',
            });
            expect(developmentManager.getRuntimeManifest()).to.include({
                verificationMode: 'digest-only-development',
            });

            const releaseManager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
            });
            expect(releaseManager.getCatalog()).to.include({
                verified: true,
                verificationMode: 'trusted-signature',
            });
        } finally {
            if (previous === undefined) {
                delete process.env.SUB_STORE_EXTENSION_ALLOW_DIGEST_ONLY;
            } else {
                process.env.SUB_STORE_EXTENSION_ALLOW_DIGEST_ONLY = previous;
            }
        }
    });

    it('passes trusted and revoked key policy to catalog and package verification', function () {
        let packageVerificationOptions;
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
        const keyId = 'test-official-root';
        const catalogEnvelope = {
            payload: signedExtensionCatalog.payload,
            signature: {
                algorithm: 'ed25519',
                keyId,
                value: crypto
                    .sign(
                        null,
                        Buffer.from(
                            canonicalJson(signedExtensionCatalog.payload),
                        ),
                        privateKey,
                    )
                    .toString('base64'),
            },
        };
        const packageStore = {
            setVerificationOptions(options) {
                packageVerificationOptions = options;
            },
        };
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            catalogEnvelope,
            allowDigestOnly: false,
            trustedKeys: { [keyId]: publicKey },
            packageStore,
        });
        expect(manager.getCatalog().verification).to.include({
            valid: true,
            trust: 'trusted',
        });
        expect(manager.getCatalog().verificationMode).to.equal(
            'trusted-signature',
        );
        expect(packageVerificationOptions).to.include({
            allowDigestOnly: false,
        });
        expect(packageVerificationOptions.trustedKeys[keyId]).to.equal(
            publicKey,
        );

        const revokedManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            catalogEnvelope,
            allowDigestOnly: false,
            trustedKeys: { [keyId]: publicKey },
            revokedKeyIds: [keyId],
            packageStore: null,
        });
        expect(revokedManager.getCatalog().verification).to.include({
            valid: false,
            reasonCode: 'EXTENSION_SIGNING_KEY_REVOKED',
        });
    });

    it('binds runtime manifests and installable package digests to the signed catalog', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
        });
        expect(manager.getCatalog()).to.include({
            verified: true,
            verificationMode: 'trusted-signature',
        });
        const unsignedId = 'org.example.unsigned-hosting';
        const unsignedManifest = JSON.parse(
            JSON.stringify(configHostingManifest)
                .split(EXTENSION_IDS.configHosting)
                .join(unsignedId),
        );
        expect(() =>
            manager.registerManifest(unsignedManifest, null, {
                kind: 'official',
            }),
        ).to.throw('not authorized by the signed catalog');

        const modifiedManifest = {
            ...configHostingManifest,
            description: `${configHostingManifest.description} modified`,
        };
        const modifiedManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            officialCatalog: [
                {
                    id: modifiedManifest.id,
                    manifest: modifiedManifest,
                    distribution: 'trusted-official-package',
                    source: 'test-modified-catalog',
                },
            ],
        });
        expect(modifiedManager.getCatalog().verified).to.equal(false);
        let error;
        try {
            modifiedManager.install(EXTENSION_IDS.configHosting);
        } catch (caught) {
            error = caught;
        }
        expect(error).to.include({
            code: 'EXTENSION_CATALOG_MANIFEST_MISMATCH',
        });
    });

    it('installs the local official config-hosting receipt and keeps it disabled until explicit enable', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
        });
        manager.registerAdapter(
            EXTENSION_IDS.configHosting,
            createConfigHostingAdapter(),
        );
        const result = manager.install(EXTENSION_IDS.configHosting);
        expect(result.status).to.equal('installed-disabled');
        expect(
            manager.getAvailability(EXTENSION_IDS.configHosting).status,
        ).to.equal('disabled');
        expect(
            manager.getRecord(EXTENSION_IDS.configHosting).packageDigest,
        ).to.match(/^([a-f0-9]{64})$/);
        expect(
            manager.getRecord(EXTENSION_IDS.configHosting).verificationMode,
        ).to.equal('trusted-signature');
        expect(manager.enable(EXTENSION_IDS.configHosting).status).to.equal(
            'enabled',
        );
        expect(manager.disable(EXTENSION_IDS.configHosting).status).to.equal(
            'disabled',
        );
    });

    it('rejects a tampered official receipt before writing lifecycle state', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            allowDigestOnly: true,
        });
        const packageInput = createLocalOfficialPackage(
            EXTENSION_IDS.configHosting,
            'node',
        );
        packageInput.signature.value = 'tampered';
        expect(() =>
            manager.install(EXTENSION_IDS.configHosting, {
                package: packageInput,
            }),
        ).to.throw('signature/digest');
        expect(
            manager.getAvailability(EXTENSION_IDS.configHosting).status,
        ).to.equal('missing');
    });

    it('uses expected revision fencing and preserves retained data on uninstall', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            allowDigestOnly: true,
        });
        manager.registerAdapter(
            EXTENSION_IDS.configHosting,
            createConfigHostingAdapter(),
        );
        manager.install(EXTENSION_IDS.configHosting);
        const revision = manager.getRuntimeManifest().revision;
        expect(() =>
            manager.enable(EXTENSION_IDS.configHosting, {
                expectedRevision: revision - 1,
            }),
        ).to.throw('state changed');
        manager.enable(EXTENSION_IDS.configHosting, {
            expectedRevision: revision,
        });
        const removed = manager.uninstall(EXTENSION_IDS.configHosting);
        expect(removed.status).to.equal('reinstall-required');
        expect(manager.getAvailability(EXTENSION_IDS.configHosting)).to.include(
            {
                status: 'reinstall-required',
                retainedReason: 'user-uninstalled',
            },
        );
    });

    it('migrates aggregate lifecycle records into one root key per extension', function () {
        const remoteExtensionRecord = {
            extensionId: GENERIC_REMOTE_EXTENSION_ID,
            version: '1.1.0',
            installationStatus: 'installed',
            dataStatus: 'active',
            enabled: false,
        };
        const configHostingRecord = {
            extensionId: EXTENSION_IDS.configHosting,
            version: '1.0.0',
            installationStatus: 'installed',
            dataStatus: 'active',
            enabled: true,
        };
        const store = createKeyStore({
            '#sub-store-extensions': JSON.stringify({
                schemaVersion: 1,
                revision: 7,
                storeRevision: 7,
                dataGeneration: 3,
                installed: {
                    [GENERIC_REMOTE_EXTENSION_ID]: remoteExtensionRecord,
                    [EXTENSION_IDS.configHosting]: configHostingRecord,
                },
                sources: {},
                migrations: {},
                tasks: [],
                audit: [],
            }),
        });
        const manager = new ExtensionManager({
            store,
            env: { isNode: true },
        });

        expect(manager.getRuntimeManifest()).to.include({
            revision: 7,
            dataGeneration: 3,
        });
        expect(store.read('#sub-store-extensions')).to.equal(undefined);

        const index = JSON.parse(store.read('#sub-store-extension-index'));
        expect(index).to.not.have.property('installed');
        expect(index.extensionIds).to.have.members([
            GENERIC_REMOTE_EXTENSION_ID,
            EXTENSION_IDS.configHosting,
        ]);
        expect(
            JSON.parse(
                store.read(
                    `#sub-store-extension:${GENERIC_REMOTE_EXTENSION_ID}`,
                ),
            ),
        ).to.deep.equal(remoteExtensionRecord);
        expect(
            JSON.parse(
                store.read(
                    `#sub-store-extension:${EXTENSION_IDS.configHosting}`,
                ),
            ),
        ).to.deep.equal(configHostingRecord);
    });

    it('writes only the changed extension record plus the shared index', function () {
        const store = createKeyStore({
            '#sub-store-extensions': JSON.stringify({
                schemaVersion: 1,
                revision: 2,
                storeRevision: 2,
                dataGeneration: 1,
                installed: {
                    [GENERIC_REMOTE_EXTENSION_ID]: {
                        extensionId: GENERIC_REMOTE_EXTENSION_ID,
                        version: '1.1.0',
                        enabled: false,
                    },
                    [EXTENSION_IDS.configHosting]: {
                        extensionId: EXTENSION_IDS.configHosting,
                        version: '1.0.0',
                        enabled: true,
                    },
                },
                sources: {},
                migrations: {},
                tasks: [],
                audit: [],
            }),
        });
        const manager = new ExtensionManager({
            store,
            env: { isNode: true },
        });

        manager.readState();
        store.resetWrittenKeys();
        manager._commit((state) => {
            state.installed[GENERIC_REMOTE_EXTENSION_ID].enabled = true;
            return state;
        });

        expect(store.writtenKeys()).to.deep.equal([
            `#sub-store-extension:${GENERIC_REMOTE_EXTENSION_ID}`,
            '#sub-store-extension-index',
        ]);
    });

    it('restores extension records when the shared index write fails', function () {
        const recordKey = `#sub-store-extension:${GENERIC_REMOTE_EXTENSION_ID}`;
        const initialRecord = {
            extensionId: GENERIC_REMOTE_EXTENSION_ID,
            version: '1.1.0',
            enabled: false,
        };
        const baseStore = createKeyStore({
            [recordKey]: JSON.stringify(initialRecord),
            '#sub-store-extension-index': JSON.stringify({
                schemaVersion: 1,
                revision: 2,
                storeRevision: 2,
                dataGeneration: 1,
                extensionIds: [GENERIC_REMOTE_EXTENSION_ID],
                sources: {},
                migrations: {},
                tasks: [],
                audit: [],
            }),
        });
        let failIndexWrite = true;
        const store = {
            ...baseStore,
            write(value, key) {
                if (key === '#sub-store-extension-index' && failIndexWrite) {
                    failIndexWrite = false;
                    throw new Error('simulated index write failure');
                }
                return baseStore.write(value, key);
            },
        };
        const manager = new ExtensionManager({
            store,
            env: { isNode: true },
        });

        expect(() =>
            manager._commit((state) => {
                state.installed[GENERIC_REMOTE_EXTENSION_ID].enabled = true;
                return state;
            }),
        ).to.throw('simulated index write failure');

        expect(JSON.parse(store.read(recordKey))).to.deep.equal(initialRecord);
        expect(manager.getRuntimeManifest().revision).to.equal(2);
        expect(manager.getRecord(GENERIC_REMOTE_EXTENSION_ID).enabled).to.equal(
            false,
        );
    });

    it('allows extension management by default when no admin token is configured', async function () {
        const previousToken = process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN;
        const previousHash = process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;
        delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN;
        delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;

        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                allowDigestOnly: true,
            });
            const { app, handlers } = createRouteApp();
            registerExtensionControlRoutes(app, manager);

            const runtimeResponse = createResponse();
            handlers.get('GET /api/extensions/runtime')(
                { headers: {} },
                runtimeResponse,
            );
            expect(runtimeResponse.body.data.extensions).to.have.length(1);
            expect(runtimeResponse.body.data.managementMode).to.equal('open');
            expect(runtimeResponse.headers.ETag).to.equal(
                `W/"extensions-${runtimeResponse.body.data.storageIdentity}-${runtimeResponse.body.data.revision}"`,
            );

            const catalogResponse = createResponse();
            await handlers.get('GET /api/extensions/catalog')(
                { headers: {} },
                catalogResponse,
            );
            expect(
                catalogResponse.body.data.entries.map((item) => item.id),
            ).to.include(EXTENSION_IDS.configHosting);
            expect(
                catalogResponse.body.data.entries.map((item) => item.id),
            ).to.not.include(GENERIC_REMOTE_EXTENSION_ID);
            const initialCatalogEtag = catalogResponse.headers.ETag;
            expect(initialCatalogEtag).to.equal(
                `W/"extensions-${catalogResponse.body.data.storageIdentity}-${catalogResponse.body.data.revision}-catalog-${catalogResponse.body.data.sequence}"`,
            );
            expect(catalogResponse.headers['Cache-Control']).to.equal(
                'no-cache',
            );

            const unchangedCatalogResponse = createResponse();
            await handlers.get('GET /api/extensions/catalog')(
                { headers: { 'if-none-match': initialCatalogEtag } },
                unchangedCatalogResponse,
            );
            expect(unchangedCatalogResponse.statusCode).to.equal(304);

            const sourcesResponse = createResponse();
            await handlers.get('GET /api/extensions/sources')(
                { headers: {} },
                sourcesResponse,
            );
            expect(sourcesResponse.statusCode).to.equal(200);
            expect(sourcesResponse.body.data.items).to.deep.equal([]);
            expect(sourcesResponse.headers.ETag).to.equal(
                `W/"extensions-${sourcesResponse.body.data.storageIdentity}-${sourcesResponse.body.data.revision}-sources"`,
            );

            const unchangedSourcesResponse = createResponse();
            await handlers.get('GET /api/extensions/sources')(
                {
                    headers: {
                        'if-none-match': sourcesResponse.headers.ETag,
                    },
                },
                unchangedSourcesResponse,
            );
            expect(unchangedSourcesResponse.statusCode).to.equal(304);

            const installResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: EXTENSION_IDS.configHosting },
                    body: {},
                    headers: {},
                },
                installResponse,
            );
            expect(installResponse.statusCode).to.equal(201);
            expect(installResponse.body.data.status).to.equal(
                'installed-disabled',
            );

            const changedCatalogResponse = createResponse();
            await handlers.get('GET /api/extensions/catalog')(
                { headers: { 'if-none-match': initialCatalogEtag } },
                changedCatalogResponse,
            );
            expect(changedCatalogResponse.statusCode).to.equal(200);
            expect(changedCatalogResponse.headers.ETag).to.not.equal(
                initialCatalogEtag,
            );
            expect(changedCatalogResponse.body.data.revision).to.be.greaterThan(
                catalogResponse.body.data.revision,
            );

            const missingSourceInstallResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: GENERIC_REMOTE_EXTENSION_ID },
                    body: {},
                    headers: {},
                },
                missingSourceInstallResponse,
            );
            expect(missingSourceInstallResponse.statusCode).to.equal(404);
            expect(missingSourceInstallResponse.body.error.code).to.equal(
                'EXTENSION_SOURCE_NOT_FOUND',
            );
        } finally {
            if (previousToken === undefined)
                delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN;
            else process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN = previousToken;
            if (previousHash === undefined)
                delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;
            else
                process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH = previousHash;
        }
    });

    it('scopes source cache validators to the backend storage identity', async function () {
        const firstManager = new ExtensionManager({
            store: { ...createKeyStore(), identity: 'source-etag-store-a' },
            env: { isNode: true },
        });
        const secondManager = new ExtensionManager({
            store: { ...createKeyStore(), identity: 'source-etag-store-b' },
            env: { isNode: true },
        });
        const firstRoutes = createRouteApp();
        const secondRoutes = createRouteApp();
        registerExtensionControlRoutes(firstRoutes.app, firstManager);
        registerExtensionControlRoutes(secondRoutes.app, secondManager);

        const firstResponse = createResponse();
        await firstRoutes.handlers.get('GET /api/extensions/sources')(
            { headers: {} },
            firstResponse,
        );
        const secondResponse = createResponse();
        await secondRoutes.handlers.get('GET /api/extensions/sources')(
            { headers: { 'if-none-match': firstResponse.headers.ETag } },
            secondResponse,
        );

        expect(firstResponse.body.data.revision).to.equal(
            secondResponse.body.data.revision,
        );
        expect(firstResponse.body.data.storageIdentity).to.not.equal(
            secondResponse.body.data.storageIdentity,
        );
        expect(secondResponse.statusCode).to.equal(200);
        expect(secondResponse.headers.ETag).to.not.equal(
            firstResponse.headers.ETag,
        );
    });

    it('requires authentication only when an extension admin token is configured', async function () {
        const previousToken = process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN;
        const previousHash = process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;
        process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN = 'extension-test-token';
        delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;

        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                allowDigestOnly: true,
            });
            const { app, handlers } = createRouteApp();
            registerExtensionControlRoutes(app, manager);

            expect(manager.getRuntimeManifest().managementMode).to.equal(
                'token',
            );

            const missingResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: EXTENSION_IDS.configHosting },
                    body: {},
                    headers: {},
                },
                missingResponse,
            );
            expect(missingResponse.statusCode).to.equal(401);
            expect(missingResponse.body.error.code).to.equal(
                'EXTENSION_ADMIN_AUTH_REQUIRED',
            );

            const invalidResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: EXTENSION_IDS.configHosting },
                    body: {},
                    headers: { authorization: 'Bearer wrong-token' },
                },
                invalidResponse,
            );
            expect(invalidResponse.statusCode).to.equal(403);
            expect(invalidResponse.body.error.code).to.equal(
                'EXTENSION_ADMIN_UNAUTHORIZED',
            );

            const authorizedResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install')(
                {
                    params: { id: EXTENSION_IDS.configHosting },
                    body: {},
                    headers: {
                        authorization: 'Bearer extension-test-token',
                    },
                },
                authorizedResponse,
            );
            expect(authorizedResponse.statusCode).to.equal(201);
            expect(authorizedResponse.body.data.status).to.equal(
                'installed-disabled',
            );
        } finally {
            if (previousToken === undefined)
                delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN;
            else process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN = previousToken;
            if (previousHash === undefined)
                delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;
            else
                process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH = previousHash;
        }
    });

    it('maps retained and disabled records to distinct availability states', function () {
        expect(
            extensionAvailability(
                {
                    extensionId: 'org.example.test',
                    installationStatus: 'removed',
                    dataStatus: 'retained',
                    retainedReason: 'backup-restored',
                },
                'org.example.test',
            ),
        ).to.include({
            status: 'reinstall-required',
            retainedReason: 'backup-restored',
        });
        expect(
            extensionAvailability(
                {
                    extensionId: 'org.example.test',
                    installationStatus: 'installed',
                    dataStatus: 'active',
                    enabled: false,
                },
                'org.example.test',
            ),
        ).to.include({ status: 'disabled', reasonCode: 'EXTENSION_DISABLED' });
    });

    it('publishes honest Node consistency and rejects unsupported manifest contracts before install', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            allowDigestOnly: true,
        });
        expect(manager.getRuntimeManifest().consistency).to.include({
            mode: 'single-process-verified-write',
            crossRequestLock: false,
            atomicPointerCommit: false,
        });
        const manifest = manager.getManifest(EXTENSION_IDS.configHosting);
        let error;
        try {
            manager._preflightManifest(
                {
                    ...manifest,
                    host: { ...manifest.host, apiVersion: '9.0.0' },
                },
                'node',
            );
        } catch (caught) {
            error = caught;
        }
        expect(error).to.have.property(
            'code',
            'EXTENSION_HOST_API_INCOMPATIBLE',
        );
        error = null;
        try {
            manager._preflightManifest(
                {
                    ...manifest,
                    permissions: [
                        ...manifest.permissions,
                        'unknown.permission',
                    ],
                },
                'node',
            );
        } catch (caught) {
            error = caught;
        }
        expect(error).to.have.property('code', 'EXTENSION_PERMISSION_UNKNOWN');

        const missingCapabilityManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            allowDigestOnly: true,
            hostCapabilities: {},
        });
        error = null;
        try {
            missingCapabilityManager._preflightManifest(manifest, 'node');
        } catch (caught) {
            error = caught;
        }
        expect(error).to.have.property(
            'code',
            'EXTENSION_HARD_CAPABILITY_MISSING',
        );
    });

    it('returns a structured unsupported data purge operation', function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
            allowDigestOnly: true,
        });
        let error;
        try {
            manager.purgeData(EXTENSION_IDS.configHosting);
        } catch (caught) {
            error = caught;
        }
        expect(error).to.include({
            code: 'EXTENSION_DATA_PURGE_UNSUPPORTED',
            statusCode: 501,
        });
    });

    it('adopts legacy artifacts once through the real Node package installer while leaving fresh stores untouched', function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-extension-adoption-'),
        );
        try {
            const legacyStore = createKeyStore({ [ARTIFACTS_KEY]: [] });
            const packageStore = createNodeExtensionPackageStore({ basePath });
            const host = initializeExtensionHost({
                reset: true,
                store: legacyStore,
                env: { isNode: true },
                packageStore,
                restoreEnabled: false,
            });
            const adopted = host.manager.getRecord(EXTENSION_IDS.configHosting);
            expect(adopted).to.include({
                installationStatus: 'installed',
                enabled: true,
                source: 'legacy-adoption',
                adoptionStatus: 'completed',
            });
            expect(adopted.packageDigest).to.match(/^[a-f0-9]{64}$/);
            expect(fs.existsSync(adopted.packageDirectory)).to.equal(true);
            expect(
                fs.existsSync(
                    path.join(
                        packageStore.extensionRoot(EXTENSION_IDS.configHosting),
                        'active.json',
                    ),
                ),
            ).to.equal(true);
            const revision = host.manager.getRuntimeManifest().revision;
            host.manager.adoptLegacyConfigHostingIfNeeded();
            expect(host.manager.getRuntimeManifest().revision).to.equal(
                revision,
            );

            resetExtensionManagerForTests();
            const freshStore = createKeyStore();
            const freshHost = initializeExtensionHost({
                reset: true,
                store: freshStore,
                env: { isNode: true },
                allowDigestOnly: true,
                packageStore: createNodeExtensionPackageStore({
                    basePath: `${basePath}-fresh`,
                }),
                restoreEnabled: false,
            });
            expect(
                freshHost.manager.getAvailability(EXTENSION_IDS.configHosting)
                    .status,
            ).to.equal('missing');
            expect(freshStore.writes()).to.equal(0);

            resetExtensionManagerForTests();
            const failedStore = createKeyStore({ [ARTIFACTS_KEY]: [] });
            const digest = sha256Hex(
                canonicalJson(signedExtensionCatalog.payload),
            );
            const untrustedCatalog = {
                payload: signedExtensionCatalog.payload,
                expiresAt: signedExtensionCatalog.expiresAt,
                signature: {
                    algorithm: 'sha256-digest',
                    keyId: 'development-only',
                    digest,
                    value: digest,
                },
            };
            const failedPackageStore = createNodeExtensionPackageStore({
                basePath: `${basePath}-failed`,
            });
            const failedHost = initializeExtensionHost({
                reset: true,
                store: failedStore,
                env: { isNode: true },
                allowDigestOnly: false,
                catalogEnvelope: untrustedCatalog,
                packageStore: failedPackageStore,
                restoreEnabled: false,
            });
            expect(
                failedHost.manager.getAvailability(EXTENSION_IDS.configHosting)
                    .status,
            ).to.equal('missing');
            const failedRevision =
                failedHost.manager.getRuntimeManifest().revision;
            expect(
                failedHost.manager.adoptLegacyConfigHostingIfNeeded(),
            ).to.include({
                status: 'deferred',
                retryable: true,
            });
            expect(failedHost.manager.getRuntimeManifest().revision).to.equal(
                failedRevision,
            );

            resetExtensionManagerForTests();
            const recoveredHost = initializeExtensionHost({
                reset: true,
                store: failedStore,
                env: { isNode: true },
                packageStore: failedPackageStore,
                restoreEnabled: false,
            });
            expect(
                recoveredHost.manager.getRecord(EXTENSION_IDS.configHosting),
            ).to.include({
                installationStatus: 'installed',
                enabled: true,
                adoptionStatus: 'completed',
                verificationMode: 'trusted-signature',
            });
        } finally {
            resetExtensionManagerForTests();
            fs.rmSync(basePath, { recursive: true, force: true });
            fs.rmSync(`${basePath}-fresh`, { recursive: true, force: true });
            fs.rmSync(`${basePath}-failed`, { recursive: true, force: true });
        }
    });

    it('installs and activates the Node package from a verified version directory', function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-extension-test-'),
        );
        try {
            const store = createStore(undefined);
            const packageStore = createNodeExtensionPackageStore({ basePath });
            let starts = 0;
            let stops = 0;
            const manager = new ExtensionManager({
                store,
                env: { isNode: true },
                packageStore,
            });
            manager.registerAdapter(
                EXTENSION_IDS.configHosting,
                createConfigHostingAdapter({
                    startScheduledJobs: () => {
                        starts += 1;
                    },
                    stopScheduledJobs: () => {
                        stops += 1;
                    },
                }),
            );

            const installed = manager.install(EXTENSION_IDS.configHosting, {
                idempotencyKey: 'install-node-package',
            });
            const record = manager.getRecord(EXTENSION_IDS.configHosting);
            expect(installed.task.status).to.equal('succeeded');
            expect(record.selectedVariant).to.equal('node');
            expect(record.manifestDigest).to.match(/^[a-f0-9]{64}$/);
            expect(record.packageDigest).to.match(/^[a-f0-9]{64}$/);
            expect(record.receiptDigest).to.match(/^[a-f0-9]{64}$/);
            expect(record.verificationMode).to.equal('trusted-signature');
            expect(fs.existsSync(record.packageDirectory)).to.equal(true);
            expect(fs.existsSync(record.entrypoint)).to.equal(true);

            const revisionAfterInstall = manager.getRuntimeManifest().revision;
            const repeated = manager.install(EXTENSION_IDS.configHosting, {
                idempotencyKey: 'install-node-package',
            });
            expect(repeated.taskId).to.equal(installed.taskId);
            expect(manager.getRuntimeManifest().revision).to.equal(
                revisionAfterInstall,
            );

            const enabled = manager.enable(EXTENSION_IDS.configHosting, {
                idempotencyKey: 'enable-node-package',
            });
            expect(enabled.task.status).to.equal('succeeded');
            expect(
                manager.getHealth(EXTENSION_IDS.configHosting).status,
            ).to.equal('healthy');
            expect(starts).to.equal(1);
            expect(
                fs.existsSync(
                    path.join(
                        packageStore.extensionRoot(EXTENSION_IDS.configHosting),
                        'active.json',
                    ),
                ),
            ).to.equal(true);

            manager.disable(EXTENSION_IDS.configHosting, {
                idempotencyKey: 'disable-node-package',
            });
            expect(stops).to.equal(1);

            const removed = manager.uninstall(EXTENSION_IDS.configHosting, {
                idempotencyKey: 'uninstall-node-package',
            });
            expect(removed.task.status).to.equal('succeeded');
            expect(removed.record.dataStatus).to.equal('retained');
            expect(fs.existsSync(record.packageDirectory)).to.equal(false);
            expect(
                manager.getAvailability(EXTENSION_IDS.configHosting).status,
            ).to.equal('reinstall-required');
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('fails closed when an installed Node entrypoint is modified', function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-extension-tamper-'),
        );
        try {
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                allowDigestOnly: true,
                packageStore: createNodeExtensionPackageStore({ basePath }),
            });
            manager.registerAdapter(
                EXTENSION_IDS.configHosting,
                createConfigHostingAdapter(),
            );
            manager.install(EXTENSION_IDS.configHosting);
            const record = manager.getRecord(EXTENSION_IDS.configHosting);
            fs.appendFileSync(record.entrypoint, '\n// modified\n', 'utf8');

            expect(() => manager.enable(EXTENSION_IDS.configHosting)).to.throw(
                'failed verification',
            );
            expect(
                manager.getAvailability(EXTENSION_IDS.configHosting).status,
            ).to.equal('disabled');
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('disables and uninstalls an active Node package without reloading tampered bytes', function () {
        const exercise = (action) => {
            const basePath = fs.mkdtempSync(
                path.join(os.tmpdir(), `sub-store-extension-${action}-tamper-`),
            );
            try {
                let stops = 0;
                const manager = new ExtensionManager({
                    store: createStore(undefined),
                    env: { isNode: true },
                    packageStore: createNodeExtensionPackageStore({ basePath }),
                });
                manager.registerAdapter(
                    EXTENSION_IDS.configHosting,
                    createConfigHostingAdapter({
                        stopScheduledJobs: () => {
                            stops += 1;
                        },
                    }),
                );
                manager.install(EXTENSION_IDS.configHosting);
                manager.enable(EXTENSION_IDS.configHosting);
                const record = manager.getRecord(EXTENSION_IDS.configHosting);
                fs.appendFileSync(record.entrypoint, '\n// modified\n', 'utf8');

                const tamperedHealth = manager.getHealth(
                    EXTENSION_IDS.configHosting,
                );
                expect(tamperedHealth.status).to.equal('unhealthy');
                expect(tamperedHealth.packageIntegrity).to.include({
                    status: 'failed',
                    code: 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH',
                });

                const result = manager[action](EXTENSION_IDS.configHosting);
                expect(stops).to.equal(1);
                expect(
                    manager.getHealth(EXTENSION_IDS.configHosting).status,
                ).to.not.equal('healthy');
                if (action === 'disable') {
                    expect(result.status).to.equal('disabled');
                    expect(
                        manager.getAvailability(EXTENSION_IDS.configHosting)
                            .status,
                    ).to.equal('disabled');
                } else {
                    expect(result.status).to.equal('reinstall-required');
                    expect(
                        manager.getAvailability(EXTENSION_IDS.configHosting)
                            .status,
                    ).to.equal('reinstall-required');
                    expect(fs.existsSync(record.packageDirectory)).to.equal(
                        false,
                    );
                }
            } finally {
                fs.rmSync(basePath, { recursive: true, force: true });
            }
        };

        exercise('disable');
        exercise('uninstall');
    });

    it('keeps the scheduler gate closed when deactivation cleanup throws', function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-extension-stop-failure-'),
        );
        try {
            let schedulerGate;
            let jobRunning = false;
            const adapter = createConfigHostingAdapter({
                startScheduledJobs: ({ isActive }) => {
                    schedulerGate = isActive;
                    jobRunning = true;
                },
                stopScheduledJobs: () => {
                    throw new Error('simulated scheduler stop failure');
                },
            });
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
            });
            manager.registerAdapter(EXTENSION_IDS.configHosting, adapter);
            manager.install(EXTENSION_IDS.configHosting);
            manager.enable(EXTENSION_IDS.configHosting);

            expect(jobRunning).to.equal(true);
            expect(schedulerGate()).to.equal(true);
            expect(
                manager.disable(EXTENSION_IDS.configHosting).status,
            ).to.equal('disabled');
            expect(adapter.health().active).to.equal(false);
            expect(schedulerGate()).to.equal(false);
            expect(
                manager.getAvailability(EXTENSION_IDS.configHosting).status,
            ).to.equal('disabled');
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('uninstalls a disabled Node package without loading code and records cleanup failures', function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-extension-cleanup-'),
        );
        try {
            const packageStore = createNodeExtensionPackageStore({ basePath });
            const manager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                allowDigestOnly: true,
                packageStore,
            });
            manager.install(EXTENSION_IDS.configHosting);
            const originalLoad = packageStore.load;
            packageStore.load = () => {
                throw new Error('disabled uninstall must not load code');
            };
            const removed = manager.uninstall(EXTENSION_IDS.configHosting, {
                idempotencyKey: 'disabled-uninstall',
            });
            expect(removed.task.status).to.equal('succeeded');
            expect(removed.record.codeStatus).to.equal('removed');
            packageStore.load = originalLoad;

            const failureStore = createNodeExtensionPackageStore({
                basePath: `${basePath}-failure`,
            });
            const failureManager = new ExtensionManager({
                store: createStore(undefined),
                env: { isNode: true },
                allowDigestOnly: true,
                packageStore: failureStore,
            });
            failureManager.install(EXTENSION_IDS.configHosting);
            const originalRemove = failureStore.remove.bind(failureStore);
            failureStore.remove = () => {
                const failure = new Error('simulated cleanup failure');
                failure.code = 'EXTENSION_PACKAGE_REMOVE_FAILED';
                throw failure;
            };
            let cleanupError;
            try {
                failureManager.uninstall(EXTENSION_IDS.configHosting, {
                    idempotencyKey: 'failed-uninstall',
                });
            } catch (caught) {
                cleanupError = caught;
            }
            expect(cleanupError).to.include({
                code: 'EXTENSION_PACKAGE_CLEANUP_FAILED',
                statusCode: 500,
            });
            const pending = failureManager.getRecord(
                EXTENSION_IDS.configHosting,
            );
            expect(pending).to.include({
                installationStatus: 'removed',
                dataStatus: 'retained',
                codeStatus: 'cleanup-pending',
            });
            expect(
                failureManager.getTask(cleanupError.details.taskId),
            ).to.include({ status: 'failed' });
            failureStore.remove = originalRemove;
            const retried = failureManager.uninstall(
                EXTENSION_IDS.configHosting,
                { idempotencyKey: 'retry-uninstall' },
            );
            expect(retried.task.status).to.equal('succeeded');
            expect(retried.record.codeStatus).to.equal('removed');
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
            fs.rmSync(`${basePath}-failure`, { recursive: true, force: true });
        }
    });

    it('gates both legacy and canonical config-hosting routes', async function () {
        const manager = new ExtensionManager({
            store: createStore(undefined),
            env: { isQX: true },
        });
        manager.registerAdapter(
            EXTENSION_IDS.configHosting,
            createConfigHostingAdapter(),
        );
        const { app, handlers } = createExpressLikeRouteApp();
        const routeApps = createConfigHostingRouteApps(app, manager, 'parser');
        const handler = (req, res) => res.json({ ok: true });
        routeApps.legacy.get('/api/sync/artifacts', handler);
        routeApps.canonical.get('/api/sync/artifacts', handler);

        expect(handlers.has('GET /api/sync/artifacts')).to.equal(true);
        expect(
            handlers.has(
                `GET /api/extensions/${EXTENSION_IDS.configHosting}/runtime/sync`,
            ),
        ).to.equal(true);

        const enabledResponse = createResponse();
        await handlers.get('GET /api/sync/artifacts')({}, enabledResponse);
        expect(enabledResponse.body).to.deep.equal({ ok: true });

        manager.disable(EXTENSION_IDS.configHosting);
        const disabledResponse = createResponse();
        await handlers.get('GET /api/sync/artifacts')({}, disabledResponse);
        expect(disabledResponse.statusCode).to.equal(409);
        expect(disabledResponse.body.error.code).to.equal('EXTENSION_DISABLED');
    });
});

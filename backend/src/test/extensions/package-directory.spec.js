import { expect } from 'chai';
import { describe, it } from 'mocha';
import { CONFIG_GENERATOR_KEY } from '@/constants';
import { createLocalOfficialPackage } from '@/extensions/catalog.generated';
import { EXTENSION_IDS } from '@/extensions/contracts';
import { initializeExtensionHost } from '@/extensions/host';
import {
    ExtensionManager,
    resetExtensionManagerForTests,
} from '@/extensions/manager';
import {
    EXTENSION_DIRECTORY_FORMAT,
    EXTENSION_DIRECTORY_MIME,
    normalizeExtensionPackageDirectory,
} from '@/extensions/package-directory';
import { createNodeExtensionPackageStore } from '@/extensions/package-store';
import {
    clearExtensionRegistryForTests,
    getArtifactSourceAdapter,
    registerExtensionRoutes,
} from '@/extensions/registry';
import { registerExtensionControlRoutes } from '@/restful/extensions';
import express from '@/vendor/express';
import fs from 'fs';
import os from 'os';
import path from 'path';

const TEST_HOST = '127.0.0.1';

function directoryProjection(packageInput) {
    const { payload } = packageInput;
    return {
        schemaVersion: 1,
        format: EXTENSION_DIRECTORY_FORMAT,
        files: {
            'manifest.json': JSON.stringify(packageInput.manifest, null, 2),
            'receipt.json': JSON.stringify(packageInput.receipt, null, 2),
            'package.json': JSON.stringify(
                {
                    schemaVersion: packageInput.schemaVersion,
                    source: packageInput.source,
                    packageDigest: packageInput.packageDigest,
                    payloadDigest: packageInput.signature.digest,
                    selectedVariant: packageInput.selectedVariant,
                    variant: payload.variant,
                    containsExecutableCode:
                        payload.containsExecutableCode === true,
                    containsInstallHook: payload.containsInstallHook === true,
                    fileDigests: payload.fileDigests,
                    signature: packageInput.signature,
                },
                null,
                2,
            ),
            ...payload.files,
        },
    };
}

function nullRecord(entries) {
    const record = Object.create(null);
    for (const [key, value] of entries) record[key] = value;
    return record;
}

function createStore(initial) {
    return createKeyStore(
        initial === undefined
            ? {}
            : { '#sub-store-extensions': JSON.stringify(initial) },
    );
}

function createKeyStore(initial = {}) {
    const values = { ...initial };
    let writes = 0;
    return {
        read(key) {
            return Object.prototype.hasOwnProperty.call(values, key)
                ? values[key]
                : undefined;
        },
        write(value, key) {
            values[key] = value;
            writes += 1;
        },
        delete(key) {
            delete values[key];
            writes += 1;
        },
        writes() {
            return writes;
        },
    };
}

function createRouteApp() {
    const handlers = new Map();
    const app = {};
    const methods = ['get', 'post', 'put', 'patch', 'delete'];
    for (const method of methods) {
        app[method] = (route, ...routeHandlers) => {
            handlers.set(
                `${method.toUpperCase()} ${route}`,
                routeHandlers[routeHandlers.length - 1],
            );
            return app;
        };
    }
    app.route = (route) => {
        const chain = {};
        for (const method of methods) {
            chain[method] = (...routeHandlers) => {
                handlers.set(
                    `${method.toUpperCase()} ${route}`,
                    routeHandlers[routeHandlers.length - 1],
                );
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
        send(body) {
            this.body = body;
            return this;
        },
        end() {
            this.ended = true;
        },
    };
}

function waitForListening(server) {
    if (server?.listening) return Promise.resolve();
    return new Promise((resolve, reject) => {
        server.once('listening', resolve);
        server.once('error', reject);
    });
}

function closeServer(server) {
    return new Promise((resolve, reject) => {
        server.close((error) => {
            if (error) reject(error);
            else resolve();
        });
        // Node's fetch implementation keeps pooled HTTP connections alive.
        // Close them explicitly so the lifecycle test cannot hang after all
        // assertions have completed.
        server.closeAllConnections?.();
    });
}

describe('Extension package directory', function () {
    it('reconstructs the exact signed package while overriding transport metadata', function () {
        const officialPackage = createLocalOfficialPackage(
            EXTENSION_IDS.configHosting,
            'node',
        );
        const projection = directoryProjection(officialPackage);
        const packageMetadata = JSON.parse(projection.files['package.json']);
        packageMetadata.source = 'attacker-controlled';
        packageMetadata.payloadDigest = '0'.repeat(64);
        projection.files['package.json'] = JSON.stringify(packageMetadata);

        const normalized = normalizeExtensionPackageDirectory(projection, {
            expectedExtensionId: EXTENSION_IDS.configHosting,
        });

        expect(normalized.packageInput.source).to.equal('local-upload');
        expect(normalized.packageInput.payload).to.deep.equal(
            officialPackage.payload,
        );
        expect(normalized.packageInput.signature).to.deep.equal(
            officialPackage.signature,
        );
        expect(normalized.summary).to.include({
            extensionId: EXTENSION_IDS.configHosting,
            selectedVariant: 'node',
            fileCount: 1,
        });
        expect(normalized.summary.totalBytes).to.be.greaterThan(0);
    });

    it('rejects incompatible envelopes and missing metadata', function () {
        const projection = directoryProjection(
            createLocalOfficialPackage(EXTENSION_IDS.configHosting, 'node'),
        );
        expect(() =>
            normalizeExtensionPackageDirectory({
                ...projection,
                schemaVersion: 2,
            }),
        )
            .to.throw()
            .with.property('code', 'EXTENSION_DIRECTORY_SCHEMA_INVALID');
        expect(() =>
            normalizeExtensionPackageDirectory({
                ...projection,
                format: 'zip',
            }),
        )
            .to.throw()
            .with.property('code', 'EXTENSION_DIRECTORY_FORMAT_INVALID');

        delete projection.files['receipt.json'];
        expect(() => normalizeExtensionPackageDirectory(projection))
            .to.throw()
            .with.property('code', 'EXTENSION_DIRECTORY_METADATA_MISSING');
    });

    it('rejects route, manifest and receipt identity mismatches', function () {
        const projection = directoryProjection(
            createLocalOfficialPackage(EXTENSION_IDS.configHosting, 'node'),
        );
        expect(() =>
            normalizeExtensionPackageDirectory(projection, {
                expectedExtensionId: 'org.example.other',
            }),
        )
            .to.throw()
            .with.property('code', 'EXTENSION_PACKAGE_ID_MISMATCH');

        const receipt = JSON.parse(projection.files['receipt.json']);
        receipt.extensionId = 'org.example.other';
        projection.files['receipt.json'] = JSON.stringify(receipt);
        expect(() => normalizeExtensionPackageDirectory(projection))
            .to.throw()
            .with.property('code', 'EXTENSION_PACKAGE_ID_MISMATCH');
    });

    it('rejects traversal, absolute, backslash, control and dangerous paths', function () {
        const officialPackage = createLocalOfficialPackage(
            EXTENSION_IDS.configHosting,
            'node',
        );
        const invalidPaths = [
            '../backend/index.cjs',
            '/backend/index.cjs',
            'C:/backend/index.cjs',
            'backend\\index.cjs',
            'backend//index.cjs',
            'backend/./index.cjs',
            'backend/../index.cjs',
            'backend/\u0000index.cjs',
            '__proto__/index.cjs',
            'backend/constructor/index.cjs',
            'backend/prototype/index.cjs',
        ];

        for (const invalidPath of invalidPaths) {
            const projection = directoryProjection(officialPackage);
            projection.files = nullRecord([
                ...Object.entries(projection.files),
                [invalidPath, 'unsafe'],
            ]);
            expect(() => normalizeExtensionPackageDirectory(projection))
                .to.throw()
                .with.property('code', 'EXTENSION_DIRECTORY_PATH_INVALID');
        }
    });

    it('rejects case-folded and Unicode-normalized path collisions', function () {
        const officialPackage = createLocalOfficialPackage(
            EXTENSION_IDS.configHosting,
            'node',
        );
        for (const collision of [
            ['backend/EXTRA.cjs', 'backend/extra.cjs'],
            ['backend/e\u0301.cjs', 'backend/\u00e9.cjs'],
        ]) {
            const projection = directoryProjection(officialPackage);
            projection.files = nullRecord([
                ...Object.entries(projection.files),
                [collision[0], 'one'],
                [collision[1], 'two'],
            ]);
            expect(() => normalizeExtensionPackageDirectory(projection))
                .to.throw()
                .with.property('code', 'EXTENSION_DIRECTORY_PATH_COLLISION');
        }
    });

    it('rejects binary projections, digest-map drift and package size limits', function () {
        const officialPackage = createLocalOfficialPackage(
            EXTENSION_IDS.configHosting,
            'node',
        );
        const binaryProjection = directoryProjection(officialPackage);
        binaryProjection.files['backend/index.cjs'] = {
            encoding: 'base64',
            content: 'AA==',
        };
        expect(() => normalizeExtensionPackageDirectory(binaryProjection))
            .to.throw()
            .with.property('code', 'EXTENSION_DIRECTORY_TEXT_REQUIRED');

        const digestDrift = directoryProjection(officialPackage);
        const packageMetadata = JSON.parse(digestDrift.files['package.json']);
        packageMetadata.fileDigests = {};
        digestDrift.files['package.json'] = JSON.stringify(packageMetadata);
        expect(() => normalizeExtensionPackageDirectory(digestDrift))
            .to.throw()
            .with.property('code', 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH');

        const oversized = directoryProjection(officialPackage);
        oversized.files['backend/index.cjs'] = 'x'.repeat(2 * 1024 * 1024 + 1);
        expect(() => normalizeExtensionPackageDirectory(oversized))
            .to.throw()
            .with.property('code', 'EXTENSION_PACKAGE_FILE_LIMIT_EXCEEDED');
    });

    it('inspects without persistence and installs through the dedicated admin routes', async function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-directory-route-'),
        );
        try {
            const store = createStore(undefined);
            const manager = new ExtensionManager({
                store,
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
            });
            const { app, handlers } = createRouteApp();
            registerExtensionControlRoutes(app, manager);
            const projection = directoryProjection(
                createLocalOfficialPackage(EXTENSION_IDS.configHosting, 'node'),
            );

            const inspectResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/packages/inspect')(
                {
                    body: projection,
                    headers: { 'content-type': EXTENSION_DIRECTORY_MIME },
                    extensionAdmin: true,
                },
                inspectResponse,
            );
            expect(inspectResponse.statusCode).to.equal(200);
            expect(inspectResponse.body.data).to.include({
                extensionId: EXTENSION_IDS.configHosting,
                selectedVariant: 'node',
                verificationMode: 'trusted-signature',
            });
            expect(store.writes()).to.equal(0);

            const installResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install-local')(
                {
                    params: { id: EXTENSION_IDS.configHosting },
                    body: projection,
                    headers: {
                        'content-type': `${EXTENSION_DIRECTORY_MIME}; charset=utf-8`,
                        'x-idempotency-key': 'install-local-package',
                    },
                    extensionAdmin: true,
                },
                installResponse,
            );
            expect(installResponse.statusCode).to.equal(201);
            expect(installResponse.body.data.status).to.equal(
                'installed-disabled',
            );
            expect(manager.getRecord(EXTENSION_IDS.configHosting)).to.include({
                enabled: false,
                source: 'local-upload',
            });
            expect(
                fs.existsSync(
                    manager.getRecord(EXTENSION_IDS.configHosting)
                        .packageDirectory,
                ),
            ).to.equal(true);

            const revision = manager.getRuntimeManifest().revision;
            const repeatedResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install-local')(
                {
                    params: { id: EXTENSION_IDS.configHosting },
                    body: projection,
                    headers: {
                        'content-type': EXTENSION_DIRECTORY_MIME,
                        'x-idempotency-key': 'install-local-package',
                    },
                    extensionAdmin: true,
                },
                repeatedResponse,
            );
            expect(repeatedResponse.statusCode).to.equal(201);
            expect(manager.getRuntimeManifest().revision).to.equal(revision);
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });

    it('protects local package routes by admin, MIME, runtime and route identity', async function () {
        const nodeManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isNode: true },
        });
        const { app, handlers } = createRouteApp();
        registerExtensionControlRoutes(app, nodeManager);
        const projection = directoryProjection(
            createLocalOfficialPackage(EXTENSION_IDS.configHosting, 'node'),
        );
        const inspect = handlers.get(
            'POST /api/admin/extensions/packages/inspect',
        );
        const install = handlers.get(
            'POST /api/admin/extensions/:id/install-local',
        );
        const catalogInstall = handlers.get(
            'POST /api/admin/extensions/:id/install',
        );

        const previousToken = process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN;
        const previousHash = process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;
        process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN = 'extension-test-token';
        delete process.env.SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH;
        try {
            const unauthorized = createResponse();
            await inspect(
                {
                    body: projection,
                    headers: { 'content-type': EXTENSION_DIRECTORY_MIME },
                },
                unauthorized,
            );
            expect(unauthorized.statusCode).to.equal(401);
            expect(unauthorized.body.error.code).to.equal(
                'EXTENSION_ADMIN_AUTH_REQUIRED',
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

        const wrongMime = createResponse();
        await inspect(
            {
                body: projection,
                headers: { 'content-type': 'application/json' },
                extensionAdmin: true,
            },
            wrongMime,
        );
        expect(wrongMime.statusCode).to.equal(415);
        expect(wrongMime.body.error.code).to.equal(
            'EXTENSION_DIRECTORY_MEDIA_TYPE_REQUIRED',
        );

        const wrongRoute = createResponse();
        await catalogInstall(
            {
                params: { id: EXTENSION_IDS.configHosting },
                body: { package: projection },
                headers: {},
                extensionAdmin: true,
            },
            wrongRoute,
        );
        expect(wrongRoute.statusCode).to.equal(400);
        expect(wrongRoute.body.error.code).to.equal(
            'EXTENSION_PACKAGE_UPLOAD_ROUTE_REQUIRED',
        );

        const mismatchedId = createResponse();
        await install(
            {
                params: { id: 'org.example.other' },
                body: projection,
                headers: { 'content-type': EXTENSION_DIRECTORY_MIME },
                extensionAdmin: true,
            },
            mismatchedId,
        );
        expect(mismatchedId.statusCode).to.equal(409);
        expect(mismatchedId.body.error.code).to.equal(
            'EXTENSION_PACKAGE_ID_MISMATCH',
        );

        const scriptManager = new ExtensionManager({
            store: createStore(undefined),
            env: { isQX: true },
        });
        const scriptRoutes = createRouteApp();
        registerExtensionControlRoutes(scriptRoutes.app, scriptManager);
        const unsupported = createResponse();
        await scriptRoutes.handlers.get(
            'POST /api/admin/extensions/packages/inspect',
        )(
            {
                body: projection,
                headers: { 'content-type': EXTENSION_DIRECTORY_MIME },
                extensionAdmin: true,
            },
            unsupported,
        );
        expect(unsupported.statusCode).to.equal(501);
        expect(unsupported.body.error.code).to.equal(
            'EXTENSION_LOCAL_PACKAGE_UNSUPPORTED',
        );
    });

    it('ships a browser-selectable config-generator directory that verifies exactly', async function () {
        const root = path.resolve(
            process.cwd(),
            'src/test/fixtures/extensions/packages/org.substore.config-generator',
        );
        const packageMetadataText = fs.readFileSync(
            path.join(root, 'package.json'),
            'utf8',
        );
        const packageMetadata = JSON.parse(packageMetadataText);
        const projection = {
            schemaVersion: 1,
            format: EXTENSION_DIRECTORY_FORMAT,
            files: {
                'manifest.json': fs.readFileSync(
                    path.join(root, 'manifest.json'),
                    'utf8',
                ),
                'receipt.json': fs.readFileSync(
                    path.join(root, 'receipt.json'),
                    'utf8',
                ),
                'package.json': packageMetadataText,
                ...Object.fromEntries(
                    Object.keys(packageMetadata.fileDigests).map((name) => [
                        name,
                        fs.readFileSync(path.join(root, name), 'utf8'),
                    ]),
                ),
            },
        };
        const normalized = normalizeExtensionPackageDirectory(projection, {
            expectedExtensionId: EXTENSION_IDS.configGenerator,
        });
        expect(normalized.packageInput.packageDigest).to.equal(
            packageMetadata.packageDigest,
        );
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-config-generator-directory-'),
        );
        const retainedData = {
            version: 1,
            projects: [{ name: 'folder-project', rules: [] }],
            ruleSets: [{ name: 'folder-rules', rules: [] }],
        };
        let server;
        try {
            resetExtensionManagerForTests();
            clearExtensionRegistryForTests();
            const store = createKeyStore({
                [CONFIG_GENERATOR_KEY]: retainedData,
            });
            const packageStore = createNodeExtensionPackageStore({ basePath });
            const host = initializeExtensionHost({
                reset: true,
                store,
                env: { isNode: true },
                packageStore,
                adoptLegacy: false,
                restoreEnabled: false,
            });
            expect(
                host.manager.inspectLocalPackage(normalized.packageInput),
            ).to.include({
                extensionId: EXTENSION_IDS.configGenerator,
                selectedVariant: 'node',
                verificationMode: 'trusted-signature',
            });

            // Match the real Node startup order: mount the extension surface,
            // then broader download and terminal GET routes, and only then
            // install the package while the listener is already running.
            const app = express({
                substore: { info() {} },
                port: 0,
                host: TEST_HOST,
            });
            registerExtensionRoutes(app, {
                extensionManager: host.manager,
                produceBuiltinArtifact: async () => '',
            });
            app.get('/download/:name/:target', (req, res) =>
                res.status(418).json({ source: 'generic-download' }),
            );
            server = app.start();
            await waitForListening(server);
            const baseUrl = `http://${TEST_HOST}:${server.address().port}`;

            const beforeInstall = await fetch(
                `${baseUrl}/api/extensions/config-generator/projects`,
            );
            expect(beforeInstall.status).to.equal(404);

            const controlRoutes = createRouteApp();
            registerExtensionControlRoutes(controlRoutes.app, host.manager);
            const installLocal = controlRoutes.handlers.get(
                'POST /api/admin/extensions/:id/install-local',
            );
            const installResponse = createResponse();
            await installLocal(
                {
                    params: { id: EXTENSION_IDS.configGenerator },
                    body: projection,
                    headers: {
                        'content-type': EXTENSION_DIRECTORY_MIME,
                        'x-idempotency-key': 'folder-install',
                    },
                    extensionAdmin: true,
                },
                installResponse,
            );
            expect(installResponse.statusCode).to.equal(201);
            expect(installResponse.body.data.status).to.equal(
                'installed-disabled',
            );

            host.manager.enable(EXTENSION_IDS.configGenerator, {
                idempotencyKey: 'folder-enable',
            });
            expect(
                host.manager.getHealth(EXTENSION_IDS.configGenerator).status,
            ).to.equal('healthy');

            const projectsResponse = await fetch(
                `${baseUrl}/api/extensions/config-generator/projects`,
            );
            expect(projectsResponse.status).to.equal(200);
            expect((await projectsResponse.json()).data).to.deep.equal(
                retainedData.projects,
            );
            for (const downloadPath of [
                '/download/config-project/missing-project',
                '/download/config-project/missing-project/QX',
                '/download/config-project/missing-project/proxy-source/nodes/QX',
            ]) {
                const response = await fetch(`${baseUrl}${downloadPath}`);
                expect(response.status).to.equal(404);
                expect((await response.json()).error.code).to.equal(
                    'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                );
            }
            expect(
                getArtifactSourceAdapter('config-project').list(),
            ).to.deep.equal([
                { name: 'folder-project', displayName: 'folder-project' },
            ]);

            const assetRoute = controlRoutes.handlers.get(
                'GET /api/extensions/:id/assets/*',
            );
            const assetResponse = createResponse();
            await assetRoute(
                {
                    params: {
                        id: EXTENSION_IDS.configGenerator,
                        0: 'frontend/index.js',
                    },
                    headers: {},
                },
                assetResponse,
            );
            expect(assetResponse.statusCode).to.equal(200);
            expect(assetResponse.body).to.equal(
                projection.files['frontend/index.js'],
            );
            expect(assetResponse.headers).to.include({
                'X-Sub-Store-Asset-Digest':
                    packageMetadata.fileDigests['frontend/index.js'],
                'X-Content-Type-Options': 'nosniff',
            });

            const installedDirectory = host.manager.getRecord(
                EXTENSION_IDS.configGenerator,
            ).packageDirectory;
            host.manager.disable(EXTENSION_IDS.configGenerator, {
                idempotencyKey: 'folder-disable',
            });
            const disabledProjects = await fetch(
                `${baseUrl}/api/extensions/config-generator/projects`,
            );
            expect(disabledProjects.status).to.equal(409);
            expect((await disabledProjects.json()).error.code).to.equal(
                'EXTENSION_DISABLED',
            );
            const disabledAssetResponse = createResponse();
            await assetRoute(
                {
                    params: {
                        id: EXTENSION_IDS.configGenerator,
                        0: 'frontend/index.js',
                    },
                    headers: {},
                },
                disabledAssetResponse,
            );
            expect(disabledAssetResponse.statusCode).to.equal(409);
            expect(disabledAssetResponse.body.error.code).to.equal(
                'EXTENSION_DISABLED',
            );

            host.manager.enable(EXTENSION_IDS.configGenerator, {
                idempotencyKey: 'folder-runtime-reenable',
            });
            const reenabledProjects = await fetch(
                `${baseUrl}/api/extensions/config-generator/projects`,
            );
            expect(reenabledProjects.status).to.equal(200);
            expect((await reenabledProjects.json()).data).to.deep.equal(
                retainedData.projects,
            );

            host.manager.uninstall(EXTENSION_IDS.configGenerator, {
                idempotencyKey: 'folder-uninstall',
            });
            expect(fs.existsSync(installedDirectory)).to.equal(false);
            expect(store.read(CONFIG_GENERATOR_KEY)).to.deep.equal(
                retainedData,
            );
            const uninstalledProjects = await fetch(
                `${baseUrl}/api/extensions/config-generator/projects`,
            );
            expect(uninstalledProjects.status).to.equal(409);
            expect((await uninstalledProjects.json()).error.code).to.equal(
                'EXTENSION_REINSTALL_REQUIRED',
            );

            const reinstallResponse = createResponse();
            await installLocal(
                {
                    params: { id: EXTENSION_IDS.configGenerator },
                    body: projection,
                    headers: {
                        'content-type': EXTENSION_DIRECTORY_MIME,
                        'x-idempotency-key': 'folder-reinstall',
                    },
                    extensionAdmin: true,
                },
                reinstallResponse,
            );
            expect(reinstallResponse.statusCode).to.equal(201);
            host.manager.enable(EXTENSION_IDS.configGenerator, {
                idempotencyKey: 'folder-reenable',
            });

            const reloadedProjectsResponse = await fetch(
                `${baseUrl}/api/extensions/config-generator/projects`,
            );
            expect(reloadedProjectsResponse.status).to.equal(200);
            expect((await reloadedProjectsResponse.json()).data).to.deep.equal(
                retainedData.projects,
            );
            const reloadedAssetResponse = createResponse();
            await assetRoute(
                {
                    params: {
                        id: EXTENSION_IDS.configGenerator,
                        0: 'frontend/index.js',
                    },
                    headers: {},
                },
                reloadedAssetResponse,
            );
            expect(reloadedAssetResponse.statusCode).to.equal(200);
            expect(store.read(CONFIG_GENERATOR_KEY)).to.deep.equal(
                retainedData,
            );

            host.manager.disable(EXTENSION_IDS.configGenerator);
            host.manager.uninstall(EXTENSION_IDS.configGenerator);
        } finally {
            if (server?.listening) await closeServer(server);
            clearExtensionRegistryForTests();
            resetExtensionManagerForTests();
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });
});

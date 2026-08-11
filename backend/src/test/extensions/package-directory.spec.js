import { expect } from 'chai';
import { describe, it } from 'mocha';
import { createLocalOfficialPackage } from '@/extensions/catalog.generated';
import {
    EXTENSION_IDS,
    canonicalJson,
    normalizeExtensionManifest,
} from '@/extensions/contracts';
import { ExtensionManager } from '@/extensions/manager';
import {
    EXTENSION_DIRECTORY_FORMAT,
    EXTENSION_DIRECTORY_MIME,
    normalizeExtensionPackageDirectory,
} from '@/extensions/package-directory';
import { createNodeExtensionPackageStore } from '@/extensions/package-store';
import { registerExtensionControlRoutes } from '@/restful/extensions';
import {
    createDigestReceipt,
    extensionPackageDigest,
    sha256Hex,
} from '@/extensions/signature';
import fs from 'fs';
import os from 'os';
import path from 'path';

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

function localExecutablePackage() {
    const extensionId = 'org.example.local-executable';
    const implementationAbi = 'local-executable@1';
    const manifest = normalizeExtensionManifest({
        schemaVersion: 1,
        id: extensionId,
        kind: 'executable',
        distribution: 'store',
        name: 'Local executable',
        version: '1.0.0',
        publisher: { id: 'org.example', name: 'Example publisher' },
        host: { apiVersion: '1.0.0', runtimes: ['node'] },
        variants: {
            node: {
                implementationId: `${extensionId}@1/node`,
                implementationAbi,
                entrypoint: 'backend/index.cjs',
                containsExecutableCode: true,
            },
        },
    });
    const files = {
        'backend/index.cjs': `'use strict';
module.exports = Object.freeze({
    extensionId: '${extensionId}',
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
            lanes: {},
            containsExecutableCode: true,
        },
    });
    const payload = { ...projection, packageDigest, receipt };
    const payloadDigest = sha256Hex(canonicalJson(payload));
    return {
        schemaVersion: 1,
        source: 'local-upload',
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

    it('treats an explicitly uploaded executable directory as integrity-trusted across restart', async function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-local-executable-'),
        );
        try {
            const store = createStore(undefined);
            const packageStore = createNodeExtensionPackageStore({ basePath });
            const manager = new ExtensionManager({
                store,
                env: { isNode: true },
                packageStore,
            });
            const { app, handlers } = createRouteApp();
            registerExtensionControlRoutes(app, manager);
            const packageInput = localExecutablePackage();
            const projection = directoryProjection(packageInput);

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
                extensionId: packageInput.manifest.id,
                verificationMode: 'local-integrity',
            });

            const installResponse = createResponse();
            await handlers.get('POST /api/admin/extensions/:id/install-local')(
                {
                    params: { id: packageInput.manifest.id },
                    body: projection,
                    headers: { 'content-type': EXTENSION_DIRECTORY_MIME },
                    extensionAdmin: true,
                },
                installResponse,
            );
            expect(installResponse.statusCode).to.equal(201);
            expect(installResponse.body.data.record).to.include({
                distribution: 'local-executable',
                verificationMode: 'local-integrity',
            });
            manager.enable(packageInput.manifest.id);
            expect(manager.getHealth(packageInput.manifest.id).status).to.equal(
                'healthy',
            );

            const restarted = new ExtensionManager({
                store,
                env: { isNode: true },
                packageStore,
            });
            const restored = restarted.restoreEnabledExtensions();
            expect(restored).to.have.length(1);
            expect(restored[0]).to.include({
                extensionId: packageInput.manifest.id,
                status: 'enabled',
            });
            expect(
                restarted.getHealth(packageInput.manifest.id).status,
            ).to.equal('healthy');
            restarted.disable(packageInput.manifest.id);
            restarted.uninstall(packageInput.manifest.id);
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
});

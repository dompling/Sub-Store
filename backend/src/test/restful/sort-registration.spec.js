import { expect } from 'chai';
import { readFileSync } from 'fs';
import { describe, it } from 'mocha';
import path from 'path';

import {
    CONFIG_HOSTING_EXTENSION_ID,
    createConfigHostingRouteApps,
} from '@/extensions/config-hosting';
import registerSortingRoutes, {
    registerArtifactSortRoute,
    registerCoreSortRoutes,
} from '@/restful/sort';

const CORE_SORT_PATHS = [
    '/api/sort/subs',
    '/api/sort/collections',
    '/api/sort/files',
    '/api/sort/tokens',
    '/api/sort/archives',
];

function createRecordingApp() {
    const registrations = [];

    return {
        registrations,
        post(routePath, ...handlers) {
            registrations.push({ method: 'post', path: routePath, handlers });
            return this;
        },
    };
}

function createResponse() {
    return {
        body: null,
        statusCode: 200,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(body) {
            this.body = body;
            return this;
        },
    };
}

function readEntry(relativePath) {
    return readFileSync(path.resolve(__dirname, relativePath), 'utf8');
}

function expectSplitComposition(source, gatewayVariable) {
    expect(source).to.include('registerCoreSortRoutes($app);');
    expect(source).to.include(
        `registerArtifactSortRoute(${gatewayVariable}.legacy);`,
    );
    expect(source).to.include(
        `registerArtifactSortRoute(${gatewayVariable}.canonical);`,
    );
    expect(source).to.not.include('registerArtifactSortRoute($app);');
}

describe('sorting route registration', function () {
    it('splits core routes from the config-hosting artifact route', function () {
        const coreApp = createRecordingApp();
        registerCoreSortRoutes(coreApp);
        expect(
            coreApp.registrations.map(({ path: routePath }) => routePath),
        ).to.deep.equal(CORE_SORT_PATHS);

        const artifactApp = createRecordingApp();
        registerArtifactSortRoute(artifactApp);
        expect(
            artifactApp.registrations.map(({ path: routePath }) => routePath),
        ).to.deep.equal(['/api/sort/artifacts']);

        const compatibilityApp = createRecordingApp();
        registerSortingRoutes(compatibilityApp);
        expect(
            compatibilityApp.registrations.map(
                ({ path: routePath }) => routePath,
            ),
        ).to.have.members([...CORE_SORT_PATHS, '/api/sort/artifacts']);
        expect(compatibilityApp.registrations).to.have.length(6);
    });

    it('registers core routes directly and keeps both artifact aliases gated', async function () {
        const app = createRecordingApp();
        const guardCalls = [];
        const manager = {
            guard(extensionId) {
                guardCalls.push(extensionId);
                const error = new Error('extension disabled');
                error.code = 'EXTENSION_DISABLED';
                error.statusCode = 409;
                throw error;
            },
        };
        const configHostingApps = createConfigHostingRouteApps(
            app,
            manager,
            'simple',
        );

        registerCoreSortRoutes(app);
        registerArtifactSortRoute(configHostingApps.legacy);
        registerArtifactSortRoute(configHostingApps.canonical);

        const paths = app.registrations.map(({ path: routePath }) => routePath);
        expect(paths).to.deep.equal([
            ...CORE_SORT_PATHS,
            '/api/sort/artifacts',
            `/api/extensions/${CONFIG_HOSTING_EXTENSION_ID}/runtime/sort`,
        ]);
        expect(
            paths.filter((routePath) => routePath.endsWith('/sort/subs')),
        ).to.deep.equal(['/api/sort/subs']);

        const artifactRegistrations = app.registrations.filter(
            ({ path: routePath }) =>
                routePath.endsWith('/sort/artifacts') ||
                routePath.endsWith('/runtime/sort'),
        );
        for (const { handlers } of artifactRegistrations) {
            const response = createResponse();
            await handlers[0]({}, response);
            expect(response.statusCode).to.equal(409);
            expect(response.body.status).to.equal('failed');
            expect(response.body.error.code).to.equal('EXTENSION_DISABLED');
        }
        expect(guardCalls).to.deep.equal([
            CONFIG_HOSTING_EXTENSION_ID,
            CONFIG_HOSTING_EXTENSION_ID,
        ]);
    });

    it('uses the split registration in both backend entry points', function () {
        expectSplitComposition(
            readEntry('../../restful/index.js'),
            'configHostingSimpleApps',
        );
        expectSplitComposition(
            readEntry('../../products/sub-store-0.js'),
            'configHostingApps',
        );
    });
});

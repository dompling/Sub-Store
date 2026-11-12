import { expect } from 'chai';
import { after, before, beforeEach, describe, it } from 'mocha';

import {
    ARTIFACTS_KEY,
    COLLECTIONS_KEY,
    FILES_KEY,
    SETTINGS_KEY,
    SUBS_KEY,
} from '@/constants';

const VLESS_WS =
    'vless://11111111-1111-4111-8111-111111111111@1.1.1.1:443?security=tls&type=ws&host=cdn.example.com&path=%2Fws&sni=sni.example.com#VLESS%20WS';

let $;
let registerArtifactRoutes;
let registerSyncRoutes;
let produceArtifact;
let produceSyncArtifactOutput;
let resolveArtifactSourcePlatform;
let originalError;
let originalInfo;
let originalRead;
let originalWrite;
let extensionRegistry;
let originalGetArtifactSourceAdapter;
let resourceBrokerModule;
let originalGetDefaultResourceBroker;
let state;
let ageUtils;

function createRouteApp() {
    const handlers = new Map();
    const methods = ['get', 'post', 'put', 'patch', 'delete'];
    const app = {
        handlers,
        route(pattern) {
            const chain = {};
            methods.forEach((method) => {
                chain[method] = (handler) => {
                    handlers.set(`${method.toUpperCase()} ${pattern}`, handler);
                    return chain;
                };
            });
            return chain;
        },
    };

    methods.forEach((method) => {
        app[method] = (pattern, handler) => {
            handlers.set(`${method.toUpperCase()} ${pattern}`, handler);
            return app;
        };
    });

    return app;
}

function getHandler(pattern) {
    const app = createRouteApp();
    registerSyncRoutes(app);
    return app.handlers.get(`GET ${pattern}`);
}

function createResponse(routePath) {
    return {
        req: {
            route: {
                path: routePath,
            },
        },
        body: null,
        statusCode: 200,
        json(payload) {
            this.body = payload;
            return this;
        },
        status(code) {
            this.statusCode = code;
            return this;
        },
    };
}

async function requestSyncArtifact(name) {
    const handler = getHandler('/api/sync/artifact/:name');
    const res = createResponse('/api/sync/artifact/:name');

    await handler(
        {
            body: {},
            params: { name },
            query: {},
        },
        res,
    );

    return res;
}

async function requestDeleteArtifact(name) {
    const app = createRouteApp();
    registerArtifactRoutes(app);
    const handler = app.handlers.get('DELETE /api/artifact/:name');
    const res = createResponse('/api/artifact/:name');

    await handler(
        {
            params: { name },
            query: {},
        },
        res,
    );

    return res;
}

describe('sync routes', function () {
    before(async function () {
        ({ default: $ } = require('@/core/app'));
        ({ default: registerArtifactRoutes } = require('@/restful/artifacts'));
        ({
            default: registerSyncRoutes,
            produceArtifact,
            produceSyncArtifactOutput,
            resolveArtifactSourcePlatform,
        } = require('@/restful/sync'));
        extensionRegistry = require('@/extensions/registry');
        originalGetArtifactSourceAdapter =
            extensionRegistry.getArtifactSourceAdapter;
        resourceBrokerModule = require('@/extensions/resource-broker');
        originalGetDefaultResourceBroker =
            resourceBrokerModule.getDefaultResourceBroker;
        ageUtils = require('@/utils/age');

        originalRead = $.read.bind($);
        originalWrite = $.write.bind($);
        originalInfo = $.info.bind($);
        originalError = $.error.bind($);
    });

    after(function () {
        if ($) {
            $.read = originalRead;
            $.write = originalWrite;
            $.info = originalInfo;
            $.error = originalError;
        }
        if (extensionRegistry) {
            extensionRegistry.getArtifactSourceAdapter =
                originalGetArtifactSourceAdapter;
        }
        if (resourceBrokerModule) {
            resourceBrokerModule.getDefaultResourceBroker =
                originalGetDefaultResourceBroker;
        }
    });

    it('uses sourceRef and representation without consulting the legacy type adapter', async function () {
        const sourceRef = {
            schema: 'substore.resource-ref@1',
            providerId: 'org.example.rules',
            providerContributionId: 'org.example.rules.rule-sets',
            type: 'rule-set',
            id: 'advertising',
            contract: 'substore.rule-set@1',
        };
        let brokerInput;
        let legacyLookupCount = 0;
        extensionRegistry.getArtifactSourceAdapter = () => {
            legacyLookupCount += 1;
            return null;
        };
        resourceBrokerModule.getDefaultResourceBroker = () => ({
            produce(ref, options) {
                brokerInput = { ref, options };
                return {
                    body: 'DOMAIN,example.com',
                    diagnostics: [],
                    freshness: { state: 'fresh' },
                };
            },
        });

        try {
            const output = await produceSyncArtifactOutput({
                name: 'resource-artifact',
                type: 'rule-set',
                source: 'display-only',
                sourceRef,
                representation: 'surge-rule-set',
                platform: 'Surge',
                upload: false,
            });

            expect(output).to.equal('DOMAIN,example.com');
            expect(legacyLookupCount).to.equal(0);
            expect(brokerInput).to.deep.equal({
                ref: sourceRef,
                options: {
                    representation: 'surge-rule-set',
                    target: 'Surge',
                    freshnessPolicy: undefined,
                },
            });
        } finally {
            extensionRegistry.getArtifactSourceAdapter =
                originalGetArtifactSourceAdapter;
            resourceBrokerModule.getDefaultResourceBroker =
                originalGetDefaultResourceBroker;
        }
    });

    it('fails closed when sourceRef is present but the Broker is unavailable', async function () {
        let legacyLookupCount = 0;
        extensionRegistry.getArtifactSourceAdapter = () => {
            legacyLookupCount += 1;
            return {
                produce: () => 'legacy-fallback-must-not-run',
            };
        };
        resourceBrokerModule.getDefaultResourceBroker = () => null;

        let error;
        try {
            await produceSyncArtifactOutput({
                name: 'resource-artifact',
                type: 'rule-set',
                source: 'display-only',
                sourceRef: {
                    schema: 'substore.resource-ref@1',
                    providerId: 'org.example.rules',
                    providerContributionId: 'org.example.rules.rule-sets',
                    type: 'rule-set',
                    id: 'advertising',
                    contract: 'substore.rule-set@1',
                },
                representation: 'surge-rule-set',
                platform: 'Surge',
            });
        } catch (cause) {
            error = cause;
        } finally {
            extensionRegistry.getArtifactSourceAdapter =
                originalGetArtifactSourceAdapter;
            resourceBrokerModule.getDefaultResourceBroker =
                originalGetDefaultResourceBroker;
        }

        expect(error.code).to.equal('RESOURCE_BROKER_UNAVAILABLE');
        expect(legacyLookupCount).to.equal(0);
    });

    it('unwraps a ResourceOutput envelope on the legacy artifact path', async function () {
        const adapter = {
            type: 'config-project',
            platforms: ['Surge'],
            produce: () => ({
                representation: 'surge-config',
                body: '[General]\nloglevel = notify',
                freshness: { state: 'fresh' },
                diagnostics: [],
            }),
        };
        extensionRegistry.getArtifactSourceAdapter = (type) =>
            type === adapter.type
                ? adapter
                : originalGetArtifactSourceAdapter(type);

        try {
            const output = await produceSyncArtifactOutput({
                name: 'config-project-artifact',
                type: 'config-project',
                source: 'demo-project',
                platform: 'Surge',
                upload: false,
            });

            expect(output).to.equal('[General]\nloglevel = notify');
        } finally {
            extensionRegistry.getArtifactSourceAdapter =
                originalGetArtifactSourceAdapter;
        }
    });

    beforeEach(function () {
        state = {
            [SETTINGS_KEY]: {},
            [SUBS_KEY]: [
                { name: 'raw-sub', source: 'local', content: VLESS_WS },
            ],
            [COLLECTIONS_KEY]: [
                { name: 'raw-col', subscriptions: ['raw-sub'] },
            ],
            [ARTIFACTS_KEY]: [
                {
                    name: 'local-artifact',
                    type: 'file',
                    source: 'local-file',
                    sync: true,
                    upload: false,
                    updated: 1711111111111,
                    url: 'https://gist.example.com/old',
                },
            ],
            [FILES_KEY]: [
                {
                    name: 'local-file',
                    source: 'local',
                    content: 'local content',
                },
            ],
        };

        $.read = (key) => state[key] || [];
        $.write = (data, key) => {
            state[key] = data;
            return true;
        };
        $.info = () => {};
        $.error = () => {};
    });

    it('returns subscription output and raw only when requested', async function () {
        state[SUBS_KEY][0].process = [
            {
                type: 'Script Operator',
                args: {
                    mode: 'script',
                    content: `function operator(proxies, targetPlatform, context) {
                        return proxies.map(proxy => ({ ...proxy, name: context.raw[0] }));
                    }`,
                },
            },
        ];

        for (const type of ['subscription', 'sub']) {
            for (const produceType of [undefined, 'internal', 'raw']) {
                const options = { type, name: 'raw-sub', produceType };
                const original = await produceArtifact(options);
                const output = await produceArtifact({
                    ...options,
                    includeRaw: true,
                });

                expect(output).to.deep.equal({
                    result: original,
                    raw: [VLESS_WS],
                });
                expect(
                    await produceArtifact({ ...options, includeRaw: false }),
                ).to.deep.equal(original);
                if (produceType !== 'raw') {
                    const proxies = Array.isArray(output.result)
                        ? output.result
                        : JSON.parse(output.result);
                    expect(proxies[0].name).to.equal(output.raw[0]);
                }
            }
        }
    });

    it('keeps processor raw arguments unchanged regardless of includeRaw', async function () {
        const { ProxyUtils } = require('@/core/proxy-utils');
        const originalProcess = ProxyUtils.process;
        let passedRaw;
        ProxyUtils.process = (...args) => {
            passedRaw = args[5];
            return originalProcess(...args);
        };

        try {
            for (const content of [VLESS_WS, [VLESS_WS]]) {
                state[SUBS_KEY][0].content = content;
                for (const options of [
                    {},
                    { includeRaw: false },
                    { includeRaw: true },
                ]) {
                    const output = await produceArtifact({
                        type: 'subscription',
                        name: 'raw-sub',
                        ...options,
                    });

                    expect(passedRaw).to.equal(content);
                    const result = options.includeRaw ? output.result : output;
                    expect(JSON.parse(result)).to.have.length(1);
                }
            }
        } finally {
            ProxyUtils.process = originalProcess;
        }
    });

    it('returns collection raw keyed by subscription name including tag matches', async function () {
        const taggedContent = VLESS_WS.replace('#VLESS%20WS', '#Tagged');
        state[SUBS_KEY].push({
            name: 'tagged-sub',
            source: 'local',
            content: taggedContent,
            tag: ['raw-tag'],
        });
        state[COLLECTIONS_KEY][0].subscriptionTags = ['raw-tag'];

        for (const type of ['collection', 'col']) {
            const options = { type, name: 'raw-col', produceType: 'internal' };
            const output = await produceArtifact({
                ...options,
                includeRaw: true,
            });

            expect(output.result).to.deep.equal(await produceArtifact(options));
            expect(output.result.map((proxy) => proxy.name)).to.deep.equal([
                'VLESS WS',
                'Tagged',
            ]);
            expect(output.raw).to.deep.equal({
                'raw-sub': [VLESS_WS],
                'tagged-sub': [taggedContent],
            });
        }
    });

    it('preserves unpreprocessed remote raw and merged source order', async function () {
        const openApi = require('@/vendor/open-api');
        const originalHTTP = openApi.HTTP;
        const remoteContent = [
            'proxies:',
            '  - name: Remote',
            '    type: ss',
            '    server: example.com',
            '    port: 443',
            '    cipher: aes-128-gcm',
            '    password: pass',
            '',
        ].join('\n');
        const secondContent = VLESS_WS.replace('#VLESS%20WS', '#Second');
        const url =
            'https://example.com/raw-first\nhttps://example.com/raw-second';
        openApi.HTTP = () => ({
            get: async ({ url }) => ({
                body: url.endsWith('raw-first') ? remoteContent : secondContent,
                headers: {},
                statusCode: 200,
            }),
        });

        try {
            for (const mergeSources of ['localFirst', 'remoteFirst']) {
                Object.assign(state[SUBS_KEY][0], {
                    source: 'remote',
                    url,
                    mergeSources,
                });
                const expectedRaw = [remoteContent, secondContent];
                if (mergeSources === 'localFirst')
                    expectedRaw.unshift(VLESS_WS);
                else expectedRaw.push(VLESS_WS);

                for (const [type, override] of [
                    ['subscription', false],
                    ['subscription', true],
                    ['collection', false],
                ]) {
                    const output = await produceArtifact({
                        type,
                        name: type === 'collection' ? 'raw-col' : 'raw-sub',
                        produceType: type === 'collection' ? 'internal' : 'raw',
                        ...(override
                            ? { url, content: VLESS_WS, mergeSources }
                            : {}),
                        noCache: true,
                        noFlow: true,
                        includeRaw: true,
                    });

                    expect(output.raw).to.deep.equal(
                        type === 'collection'
                            ? { 'raw-sub': expectedRaw }
                            : expectedRaw,
                    );
                    if (type === 'subscription') {
                        const remoteIndex =
                            mergeSources === 'localFirst' ? 1 : 0;
                        expect(
                            JSON.parse(output.result)[remoteIndex],
                        ).to.not.equal(remoteContent);
                    } else {
                        expect(output.result).to.have.length(3);
                    }
                }
            }
        } finally {
            openApi.HTTP = originalHTTP;
        }
    });

    it('returns available raw alongside subscription and collection fallback output', async function () {
        const failingProcess = [
            {
                type: 'Script Operator',
                args: { mode: 'script', content: "throw new Error('boom')" },
            },
        ];

        for (const type of ['subscription', 'collection']) {
            state[SUBS_KEY][0].process =
                type === 'subscription' ? failingProcess : [];
            state[COLLECTIONS_KEY][0].process =
                type === 'collection' ? failingProcess : [];
            const output = await produceArtifact({
                type,
                name: type === 'subscription' ? 'raw-sub' : 'raw-col',
                produceType: 'internal',
                ignoreFailedRemoteSub: 'fallbackQuiet',
                includeRaw: true,
            });

            expect(output).to.deep.equal({
                result: [],
                raw:
                    type === 'subscription'
                        ? [VLESS_WS]
                        : { 'raw-sub': [VLESS_WS] },
            });
        }
    });

    it('preserves ignored and fallback child failures in returned collection raw', async function () {
        state[SUBS_KEY].push({
            name: 'broken-sub',
            source: 'local',
            content: VLESS_WS,
            process: [
                {
                    type: 'Script Operator',
                    args: {
                        mode: 'script',
                        content: "throw new Error('boom')",
                    },
                },
            ],
        });
        state[COLLECTIONS_KEY][0].subscriptions.push('broken-sub');

        for (const mode of ['quiet', 'fallbackQuiet']) {
            const output = await produceArtifact({
                type: 'collection',
                name: 'raw-col',
                ignoreFailedRemoteSub: mode,
                includeRaw: true,
            });

            expect(JSON.parse(output.result)).to.have.length(1);
            expect(output.raw).to.deep.equal({
                'raw-sub': [VLESS_WS],
                'broken-sub': mode === 'quiet' ? undefined : [],
            });
        }
    });

    it('updates run time without requiring a Gist URL when upload is disabled', async function () {
        const startedAt = new Date().getTime();

        const res = await requestSyncArtifact('local-artifact');

        expect(res.statusCode).to.equal(200);
        expect(res.body.status).to.equal('success');
        expect(res.body.data.updated).to.be.at.least(startedAt);
        expect(res.body.data).to.not.have.property('url');
        expect(state[ARTIFACTS_KEY][0].updated).to.be.at.least(startedAt);
        expect(state[ARTIFACTS_KEY][0]).to.not.have.property('url');
    });

    it('preserves artifact edits made while a single artifact sync is running', async function () {
        const startedAt = new Date().getTime();
        let artifactReads = 0;
        $.read = (key) => {
            if (key === ARTIFACTS_KEY) {
                artifactReads++;
                if (artifactReads === 2) {
                    state[ARTIFACTS_KEY] = [
                        {
                            ...state[ARTIFACTS_KEY][0],
                            remark: 'edited while syncing',
                            cron: '55 23 * * *',
                        },
                    ];
                }
            }
            return state[key] || [];
        };

        const res = await requestSyncArtifact('local-artifact');

        expect(res.statusCode).to.equal(200);
        expect(res.body.status).to.equal('success');
        expect(res.body.data.remark).to.equal('edited while syncing');
        expect(res.body.data.cron).to.equal('55 23 * * *');
        expect(res.body.data.updated).to.be.at.least(startedAt);
        expect(res.body.data).to.not.have.property('url');
        expect(state[ARTIFACTS_KEY][0].remark).to.equal('edited while syncing');
        expect(state[ARTIFACTS_KEY][0].cron).to.equal('55 23 * * *');
        expect(state[ARTIFACTS_KEY][0].updated).to.be.at.least(startedAt);
        expect(state[ARTIFACTS_KEY][0]).to.not.have.property('url');
    });

    it('does not try to delete a remote file when only run time exists', async function () {
        delete state[ARTIFACTS_KEY][0].url;

        const res = await requestDeleteArtifact('local-artifact');

        expect(res.statusCode).to.equal(200);
        expect(res.body.status).to.equal('success');
        expect(res.body.data.remote).to.deep.equal({
            attempted: false,
            status: 'not_attempted',
        });
        expect(state[ARTIFACTS_KEY]).to.deep.equal([]);
    });

    it('encrypts sync artifact output with artifact age-public-key', async function () {
        const pair = await ageUtils.generateKeyPair();
        state[ARTIFACTS_KEY][0]['age-public-key'] = pair['age-public-key'];

        const output = await produceSyncArtifactOutput(state[ARTIFACTS_KEY][0]);
        const decrypted = await ageUtils.decryptArmorIfPresent(
            output,
            pair['age-secret-key'],
        );

        expect(output).to.contain(ageUtils.AGE_ARMOR_HEADER);
        expect(decrypted).to.equal('local content');
    });

    it('uses source age-public-key when artifact has no key', async function () {
        const pair = await ageUtils.generateKeyPair();
        state[FILES_KEY][0]['age-public-key'] = pair['age-public-key'];

        const output = await produceSyncArtifactOutput(state[ARTIFACTS_KEY][0]);
        const decrypted = await ageUtils.decryptArmorIfPresent(
            output,
            pair['age-secret-key'],
        );

        expect(output).to.contain(ageUtils.AGE_ARMOR_HEADER);
        expect(decrypted).to.equal('local content');
    });

    it('uses artifact age-public-key before source key', async function () {
        const sourcePair = await ageUtils.generateKeyPair();
        const artifactPair = await ageUtils.generateKeyPair();
        state[FILES_KEY][0]['age-public-key'] = sourcePair['age-public-key'];
        state[ARTIFACTS_KEY][0]['age-public-key'] =
            artifactPair['age-public-key'];

        const output = await produceSyncArtifactOutput(state[ARTIFACTS_KEY][0]);
        const decrypted = await ageUtils.decryptArmorIfPresent(
            output,
            artifactPair['age-secret-key'],
        );

        expect(output).to.contain(ageUtils.AGE_ARMOR_HEADER);
        expect(decrypted).to.equal('local content');
        try {
            await ageUtils.decryptArmorIfPresent(
                output,
                sourcePair['age-secret-key'],
            );
            throw new Error('Expected source key decrypt to fail');
        } catch (e) {
            expect(e.message).to.contain('age 解密失败');
        }
    });

    it('uses the first declared extension platform for the legacy hidden Stash default', async function () {
        let producerInput;
        const adapter = {
            type: 'config-project',
            platforms: ['Surge', 'QX', 'Clash', 'Loon'],
            findSourceConfig: () => null,
            produce: async (input) => {
                producerInput = input;
                return '[General]\nloglevel = notify';
            },
        };
        extensionRegistry.getArtifactSourceAdapter = (type) =>
            type === adapter.type
                ? adapter
                : originalGetArtifactSourceAdapter(type);

        try {
            const artifact = {
                name: 'config-project-artifact',
                type: 'config-project',
                source: 'demo-project',
                platform: 'Stash',
                upload: false,
            };

            const output = await produceSyncArtifactOutput(artifact);

            expect(output).to.equal('[General]\nloglevel = notify');
            expect(producerInput.platform).to.equal('Surge');
        } finally {
            extensionRegistry.getArtifactSourceAdapter =
                originalGetArtifactSourceAdapter;
        }
    });

    it('rejects explicit unsupported extension platforms instead of silently changing them', function () {
        let error;
        try {
            resolveArtifactSourcePlatform(
                {
                    type: 'config-project',
                    platforms: ['Surge', 'QX', 'Clash', 'Loon'],
                },
                'ShadowRocket',
            );
        } catch (cause) {
            error = cause;
        }

        expect(error).to.include({
            code: 'UNSUPPORTED_ARTIFACT_PLATFORM',
        });
        expect(error.message).to.contain('config-project');
        expect(error.message).to.contain('ShadowRocket');
        expect(error.details.supportedPlatforms).to.deep.equal([
            'Surge',
            'QX',
            'Clash',
            'Loon',
        ]);
    });

    it('returns readable structured error details instead of object coercion', async function () {
        state[ARTIFACTS_KEY][0]['age-public-key'] = 'invalid-age-key';

        const res = await requestSyncArtifact('local-artifact');

        expect(res.statusCode).to.equal(500);
        expect(res.body.error.code).to.equal('FAILED_TO_SYNC_ARTIFACT');
        expect(res.body.error.details).to.contain('INVALID_AGE_PUBLIC_KEY');
        expect(res.body.error.details).to.contain(
            'age-public-key 仅支持 X25519',
        );
        expect(res.body.error.details).to.not.contain('[object Object]');
    });

    it('redacts sensitive structured error details', async function () {
        const adapter = {
            type: 'config-project',
            platforms: ['Surge'],
            findSourceConfig: () => null,
            produce: async () => {
                throw {
                    code: 'CONFIG_GENERATOR_REMOTE_FAILURE',
                    message: 'Remote generation failed',
                    details: {
                        token: 'super-secret-token',
                        publicKey: 'age1sensitive',
                        endpoint: 'https://example.com/config',
                    },
                };
            },
        };
        extensionRegistry.getArtifactSourceAdapter = (type) =>
            type === adapter.type
                ? adapter
                : originalGetArtifactSourceAdapter(type);
        state[ARTIFACTS_KEY][0] = {
            name: 'config-project-artifact',
            type: 'config-project',
            source: 'demo-project',
            platform: 'Surge',
            upload: false,
        };

        try {
            const res = await requestSyncArtifact('config-project-artifact');

            expect(res.statusCode).to.equal(500);
            expect(res.body.error.details).to.contain(
                'CONFIG_GENERATOR_REMOTE_FAILURE',
            );
            expect(res.body.error.details).to.contain(
                'Remote generation failed',
            );
            expect(res.body.error.details).to.contain(
                'https://example.com/config',
            );
            expect(res.body.error.details).to.contain('[REDACTED]');
            expect(res.body.error.details).to.not.contain('super-secret-token');
            expect(res.body.error.details).to.not.contain('age1sensitive');
        } finally {
            extensionRegistry.getArtifactSourceAdapter =
                originalGetArtifactSourceAdapter;
        }
    });
});

import { expect } from 'chai';
import { after, before, beforeEach, describe, it } from 'mocha';

import { ARTIFACTS_KEY, FILES_KEY, SETTINGS_KEY } from '@/constants';

let $;
let registerArtifactRoutes;
let registerSyncRoutes;
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

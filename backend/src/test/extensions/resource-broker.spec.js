import { expect } from 'chai';
import { describe, it } from 'mocha';
import { createBackendExtensionSdkV1 } from '@/extensions/backend-sdk-v1';
import {
    createResourceBroker,
    CORE_RESOURCE_REPRESENTATION,
} from '@/extensions/resource-broker';
import { createExtensionReferenceIndex } from '@/extensions/reference-index';
import { RESOURCE_REF_SCHEMA } from '@/extensions/resource-contracts';
import {
    ExtensionManager,
    extensionHostCapabilities,
    resetExtensionManagerForTests,
} from '@/extensions/manager';
import { initializeExtensionHost } from '@/extensions/host';
import configHostingManifest from '@/extensions/config-hosting/manifest.json';

function createStore(initial = {}) {
    const values = { ...initial };
    return {
        read(key) {
            return values[key];
        },
        write(value, key) {
            values[key] = value;
        },
    };
}

function resourceRef(overrides = {}) {
    return {
        schema: RESOURCE_REF_SCHEMA,
        providerId: 'org.example.rules',
        providerContributionId: 'org.example.rules.rule-sets',
        type: 'rule-set',
        id: 'advertising',
        contract: 'substore.rule-set@1',
        ...overrides,
    };
}

function resourceProvider(overrides = {}) {
    return {
        providerId: 'org.example.rules',
        providerContributionId: 'org.example.rules.rule-sets',
        source: {
            id: 'org.example.rules.rule-sets',
            type: 'rule-set',
            contract: 'substore.rule-set@1',
            representations: ['surge-rule-set'],
            list: () => [
                {
                    id: 'advertising',
                    name: 'Advertising',
                    secretBody: 'must-not-leak',
                    lifecycle: { state: 'active' },
                },
            ],
            get: () => ({
                id: 'advertising',
                name: 'Advertising',
                secretBody: 'must-not-leak',
                lifecycle: { state: 'active' },
            }),
            produce: () => 'DOMAIN,example.com',
        },
        ...overrides,
    };
}

function manager(status = 'enabled') {
    return {
        getAvailability(providerId) {
            return { status, extensionId: providerId };
        },
    };
}

function brokerWith(provider, options = {}) {
    const providers = provider ? [provider] : [];
    return createResourceBroker({
        manager: options.manager || manager(),
        store: options.store || createStore(),
        produceBuiltinArtifact:
            options.produceBuiltinArtifact || (async () => []),
        listProviders: () => providers,
        resolveProvider: (ref) =>
            providers.find(
                (candidate) =>
                    candidate.providerId === ref.providerId &&
                    candidate.providerContributionId ===
                        ref.providerContributionId &&
                    candidate.source.type === ref.type,
            ) || null,
    });
}

describe('Host Resource Broker', function () {
    it('lists sanitized descriptors from strict providers', async function () {
        const descriptors = await brokerWith(resourceProvider()).list({
            types: ['rule-set'],
        });

        expect(descriptors).to.have.length(1);
        expect(descriptors[0].ref).to.deep.equal(resourceRef());
        expect(descriptors[0]).to.not.have.property('secretBody');
    });

    it('preserves a provider descriptor stable ref id instead of its display name', async function () {
        const provider = resourceProvider();
        const descriptor = {
            schema: 'substore.resource-descriptor@1',
            ref: resourceRef({ id: 'rs_7bce398f' }),
            name: 'Advertising renamed',
            contracts: ['substore.rule-set@1'],
            representations: ['surge-rule-set'],
            lifecycle: { state: 'active' },
            availability: { status: 'available' },
        };
        provider.source.list = () => [descriptor];
        provider.source.get = () => descriptor;

        const listed = await brokerWith(provider).list();
        const fetched = await brokerWith(provider).get(descriptor.ref);

        expect(listed[0].ref.id).to.equal('rs_7bce398f');
        expect(listed[0].name).to.equal('Advertising renamed');
        expect(fetched.ref.id).to.equal('rs_7bce398f');
    });

    it('rejects a provider descriptor whose ref does not match the requested id', async function () {
        const provider = resourceProvider();
        provider.source.get = () => ({
            ref: resourceRef({ id: 'another-resource' }),
            name: 'Another resource',
            contracts: ['substore.rule-set@1'],
            representations: ['surge-rule-set'],
        });

        let error;
        try {
            await brokerWith(provider).get(resourceRef());
        } catch (cause) {
            error = cause;
        }

        expect(error.code).to.equal('RESOURCE_DESCRIPTOR_INVALID');
    });

    it('preserves provider diagnostics and freshness envelopes', async function () {
        const provider = resourceProvider();
        provider.source.produce = () => ({
            representation: 'surge-rule-set',
            body: 'DOMAIN,example.com',
            freshness: { state: 'stale', fetchedAt: 100 },
            diagnostics: [
                {
                    severity: 'warning',
                    code: 'STALE_CACHE',
                    message: 'Using cached rules',
                },
            ],
        });

        const output = await brokerWith(provider).produce(resourceRef(), {
            representation: 'surge-rule-set',
        });

        expect(output.freshness).to.deep.equal({
            state: 'stale',
            fetchedAt: 100,
        });
        expect(output.diagnostics[0]).to.include({
            code: 'STALE_CACHE',
        });
    });

    it('rejects an unsupported representation before invoking the provider', async function () {
        let produced = false;
        const provider = resourceProvider();
        provider.source.produce = () => {
            produced = true;
            return '';
        };

        let error;
        try {
            await brokerWith(provider).produce(resourceRef(), {
                representation: 'qx-rule-set',
            });
        } catch (cause) {
            error = cause;
        }

        expect(error.code).to.equal('RESOURCE_REPRESENTATION_UNSUPPORTED');
        expect(produced).to.equal(false);
    });

    it('rejects incompatible contracts', async function () {
        let error;
        try {
            await brokerWith(resourceProvider()).get(
                resourceRef({ contract: 'substore.rule-set@2' }),
            );
        } catch (cause) {
            error = cause;
        }

        expect(error.code).to.equal('RESOURCE_CONTRACT_INCOMPATIBLE');
    });

    for (const [status, code] of [
        ['disabled', 'RESOURCE_PROVIDER_DISABLED'],
        ['updating', 'RESOURCE_PROVIDER_UPDATING'],
        ['missing', 'RESOURCE_PROVIDER_NOT_INSTALLED'],
    ]) {
        it(`maps ${status} provider lifecycle to ${code}`, async function () {
            let error;
            try {
                await brokerWith(resourceProvider(), {
                    manager: manager(status),
                }).get(resourceRef());
            } catch (cause) {
                error = cause;
            }
            expect(error.code).to.equal(code);
        });
    }

    it('exposes subscriptions and collections as core node resources', async function () {
        const store = createStore({
            subs: [{ name: 'Y2' }],
            collections: [{ name: 'All' }],
        });
        const inputs = [];
        const broker = brokerWith(null, {
            store,
            produceBuiltinArtifact(input) {
                inputs.push(input);
                return [{ name: 'Tokyo', type: 'vmess' }];
            },
        });

        const descriptors = await broker.list({
            types: ['subscription', 'collection'],
        });
        const output = await broker.produce(
            descriptors.find((item) => item.ref.type === 'subscription').ref,
            { representation: CORE_RESOURCE_REPRESENTATION },
        );

        expect(descriptors.map((item) => item.ref.type)).to.have.members([
            'subscription',
            'collection',
        ]);
        expect(JSON.parse(output.body)).to.deep.equal([
            { name: 'Tokyo', type: 'vmess' },
        ]);
        expect(inputs[0]).to.include({
            type: 'subscription',
            name: 'Y2',
            platform: 'JSON',
            produceType: 'internal',
            noFlow: true,
        });
    });
});

describe('Resource Broker SDK scopes', function () {
    function manifest(permissions) {
        return { permissions };
    }

    it('filters an unqualified list to the declared type scope', async function () {
        let options;
        const sdk = createBackendExtensionSdkV1({
            extensionId: 'org.example.consumer',
            manifest: manifest([
                { name: 'resources.list', scope: ['rule-set'] },
            ]),
            store: createStore(),
            resourceBroker: {
                list(input) {
                    options = input;
                    return [];
                },
            },
            referenceIndex: createExtensionReferenceIndex({
                store: createStore(),
            }),
        });

        await sdk.resources.list();

        expect(options.types).to.deep.equal(['rule-set']);
    });

    it('rejects explicit list types outside the declared scope', async function () {
        const sdk = createBackendExtensionSdkV1({
            extensionId: 'org.example.consumer',
            manifest: manifest([
                { name: 'resources.list', scope: ['rule-set'] },
            ]),
            store: createStore(),
            resourceBroker: { list: () => [] },
            referenceIndex: createExtensionReferenceIndex({
                store: createStore(),
            }),
        });

        let error;
        try {
            await sdk.resources.list({ types: ['subscription'] });
        } catch (cause) {
            error = cause;
        }

        expect(error.code).to.equal('EXTENSION_PERMISSION_SCOPE_DENIED');
    });

    it('restricts reference writes and reads to the current provider', function () {
        const referenceIndex = createExtensionReferenceIndex({
            store: createStore(),
        });
        const sdk = createBackendExtensionSdkV1({
            extensionId: 'org.example.consumer',
            manifest: manifest([
                {
                    name: 'references.manage-own',
                    scope: ['config-project'],
                },
                { name: 'references.read-own', scope: ['rule-set'] },
            ]),
            store: createStore(),
            resourceBroker: {},
            referenceIndex,
        });

        const foreignOwner = resourceRef({
            providerId: 'org.example.other',
            providerContributionId: 'org.example.other.projects',
            type: 'config-project',
            contract: 'substore.config-project@1',
        });
        expect(() =>
            sdk.references.replaceOwn({
                owner: foreignOwner,
                targets: [resourceRef()],
            }),
        )
            .to.throw()
            .with.property('code', 'EXTENSION_PERMISSION_SCOPE_DENIED');
        expect(() => sdk.references.listIncoming(resourceRef()))
            .to.throw()
            .with.property('code', 'EXTENSION_PERMISSION_SCOPE_DENIED');
    });

    it('degrades a corrupt incoming reference index without blocking the provider', function () {
        const sdk = createBackendExtensionSdkV1({
            extensionId: 'org.example.rules',
            manifest: manifest([
                { name: 'references.read-own', scope: ['rule-set'] },
            ]),
            store: createStore(),
            resourceBroker: {},
            referenceIndex: {
                listIncoming() {
                    const error = new Error('corrupt index');
                    error.code = 'REFERENCE_INDEX_CORRUPT';
                    throw error;
                },
            },
        });

        expect(sdk.references.listIncoming(resourceRef())).to.deep.equal({
            available: false,
            items: [],
            reasonCode: 'REFERENCE_INDEX_CORRUPT',
        });
    });
});

describe('Resource Broker Host capability', function () {
    function brokerManifest() {
        return {
            schemaVersion: 1,
            id: 'org.example.broker-consumer',
            kind: 'executable',
            name: 'Broker consumer',
            version: '1.0.0',
            publisher: { id: 'org.example', name: 'Example' },
            host: { apiVersion: '1.0.0', runtimes: ['node'] },
            requires: { hard: ['resource-broker@1'] },
        };
    }

    it('does not advertise the Broker in lightweight Host capabilities', function () {
        const manager = new ExtensionManager({
            store: createStore(),
            env: { isNode: true },
            bundledCatalog: [],
            officialCatalog: [],
            catalogEnvelope: null,
            hostCapabilities: extensionHostCapabilities(),
            packageStore: null,
        });

        expect(() => manager._preflightManifest(brokerManifest()))
            .to.throw()
            .with.property('code', 'EXTENSION_HARD_CAPABILITY_MISSING');
    });

    it('advertises the Broker only when the complete Node Host enables it', function () {
        const manager = new ExtensionManager({
            store: createStore(),
            env: { isNode: true },
            bundledCatalog: [],
            officialCatalog: [],
            catalogEnvelope: null,
            hostCapabilities: extensionHostCapabilities({
                resourceBroker: true,
            }),
            packageStore: null,
        });

        expect(manager._preflightManifest(brokerManifest())).to.include({
            status: 'compatible',
        });
    });

    it('binds the complete Broker SDK before restoring executable plugins', function () {
        const extensionId = 'org.example.activation-check';
        const activationManifest = {
            schemaVersion: 1,
            id: extensionId,
            kind: 'executable',
            name: 'Activation check',
            version: '1.0.0',
            publisher: { id: 'org.example', name: 'Example' },
            host: { apiVersion: '1.0.0', runtimes: ['node'] },
            requires: { hard: ['resource-broker@1'] },
            permissions: [{ name: 'resources.list', scope: ['subscription'] }],
        };
        const store = createStore({
            '#sub-store-extension-index': JSON.stringify({
                schemaVersion: 1,
                revision: 1,
                storeRevision: 1,
                dataGeneration: 1,
                extensionIds: [extensionId],
                sources: {},
                migrations: {},
                tasks: [],
                audit: [],
            }),
            [`#sub-store-extension:${extensionId}`]: JSON.stringify({
                extensionId,
                version: '1.0.0',
                source: 'official-local',
                installationStatus: 'installed',
                dataStatus: 'active',
                enabled: true,
                compatibilityStatus: 'compatible',
            }),
        });
        let activatedServices;
        resetExtensionManagerForTests();
        try {
            const host = initializeExtensionHost({
                reset: true,
                store,
                env: { isNode: true },
                bundledCatalog: [
                    { id: extensionId, manifest: activationManifest },
                ],
                officialCatalog: [
                    {
                        id: configHostingManifest.id,
                        manifest: configHostingManifest,
                    },
                ],
                catalogEnvelope: null,
                packageStore: null,
                adoptLegacy: false,
                produceBuiltinArtifact: async () => [],
                registerEmbeddedExtensions(manager) {
                    manager.registerAdapter(extensionId, {
                        activate() {
                            activatedServices =
                                manager.hostBindings.createServices({
                                    extensionId,
                                    manifest: activationManifest,
                                    store,
                                });
                            return { active: true };
                        },
                        deactivate() {
                            return { active: false };
                        },
                    });
                },
            });
            const record = host.manager.getRecord(extensionId);
            host.manager._activateRecord(record);

            expect(host.resourceBroker).to.be.an('object');
            expect(activatedServices.resources.list).to.be.a('function');
            expect(activatedServices.resources.get).to.be.a('function');
            expect(activatedServices.resources.produce).to.be.a('function');
        } finally {
            resetExtensionManagerForTests();
        }
    });
});

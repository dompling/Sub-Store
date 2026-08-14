import { expect } from 'chai';
import { afterEach, describe, it } from 'mocha';
import { normalizeExtensionManifest } from '@/extensions/contracts';
import {
    clearExtensionRegistryForTests,
    getArtifactSourceAdapter,
    listArtifactSources,
    listResourceProviders,
    registerExtension,
} from '@/extensions/registry';
import {
    getExtensionManager,
    resetExtensionManagerForTests,
} from '@/extensions/manager';

function createStore(initial = {}) {
    const values = { ...initial };
    return {
        read(key) {
            return values[key];
        },
        write(value, key) {
            values[key] = value;
        },
        delete(key) {
            delete values[key];
        },
    };
}

function manifest(overrides = {}) {
    const base = {
        schemaVersion: 1,
        id: 'org.example.rules',
        kind: 'executable',
        name: 'Rules',
        version: '1.0.0',
        publisher: { id: 'org.example', name: 'Example' },
        host: { apiVersion: '1.0.0', runtimes: ['node'] },
        requires: { hard: ['resource-broker@1'] },
        permissions: [
            { name: 'artifact-source.register', scope: ['rule-set'] },
        ],
        contributes: {
            artifactSources: [
                {
                    id: 'org.example.rules.rule-sets',
                    type: 'rule-set',
                    contract: 'substore.rule-set@1',
                    representations: ['surge-rule-set'],
                },
            ],
        },
    };
    const merged = {
        ...base,
        ...overrides,
        host: { ...base.host, ...(overrides.host || {}) },
        requires: { ...base.requires, ...(overrides.requires || {}) },
        contributes: {
            ...base.contributes,
            ...(overrides.contributes || {}),
        },
    };
    return normalizeExtensionManifest(merged);
}

function source(overrides = {}) {
    return {
        id: 'org.example.rules.rule-sets',
        type: 'rule-set',
        contract: 'substore.rule-set@1',
        representations: ['surge-rule-set'],
        list: () => [],
        get: () => null,
        produce: () => '',
        ...overrides,
    };
}

function enableManifests(...manifests) {
    resetExtensionManagerForTests();
    getExtensionManager({
        store: createStore(),
        env: { isNode: true },
        packageStore: null,
        bundledCatalog: manifests.map((candidate) => ({
            manifest: candidate,
            distribution: 'bundled',
            defaultEnabled: true,
        })),
        officialCatalog: [],
    });
}

describe('Resource provider registry validation', function () {
    afterEach(function () {
        clearExtensionRegistryForTests();
        resetExtensionManagerForTests();
    });

    it('registers a strict provider whose runtime source matches its manifest', function () {
        registerExtension({
            extensionId: 'org.example.rules',
            manifest: manifest(),
            artifactSources: [source()],
        });

        expect(listResourceProviders()).to.have.length(1);
        expect(listResourceProviders()[0]).to.include({
            providerId: 'org.example.rules',
            providerContributionId: 'org.example.rules.rule-sets',
        });
    });

    for (const [name, runtimeSource, code] of [
        [
            'undeclared contribution ids',
            source({ id: 'org.example.rules.other' }),
            'EXTENSION_ARTIFACT_SOURCE_UNDECLARED',
        ],
        [
            'type mismatches',
            source({ type: 'subscription' }),
            'EXTENSION_ARTIFACT_SOURCE_MISMATCH',
        ],
        [
            'contract mismatches',
            source({ contract: 'substore.rule-set@2' }),
            'EXTENSION_ARTIFACT_SOURCE_MISMATCH',
        ],
        [
            'undeclared representations',
            source({ representations: ['qx-rule-set'] }),
            'EXTENSION_ARTIFACT_SOURCE_REPRESENTATION_DENIED',
        ],
    ]) {
        it(`rejects ${name} without leaving a partial registration`, function () {
            expect(() =>
                registerExtension({
                    extensionId: 'org.example.rules',
                    manifest: manifest(),
                    artifactSources: [runtimeSource],
                }),
            )
                .to.throw()
                .with.property('code', code);
            expect(listResourceProviders()).to.deep.equal([]);
        });
    }

    it('rejects providers outside artifact-source.register scope', function () {
        const scopedManifest = manifest({
            permissions: [
                {
                    name: 'artifact-source.register',
                    scope: ['subscription'],
                },
            ],
        });

        expect(() =>
            registerExtension({
                extensionId: 'org.example.rules',
                manifest: scopedManifest,
                artifactSources: [source()],
            }),
        )
            .to.throw()
            .with.property('code', 'EXTENSION_PERMISSION_SCOPE_DENIED');
        expect(listResourceProviders()).to.deep.equal([]);
    });

    it('keeps legacy artifact sources out of the Resource Broker registry', function () {
        const legacyManifest = manifest({ requires: { hard: [] } });
        registerExtension({
            extensionId: 'org.example.rules',
            manifest: legacyManifest,
            artifactSources: [source()],
        });

        expect(listResourceProviders()).to.deep.equal([]);
    });

    it('rejects an ambiguous legacy type-only lookup instead of choosing registration order', function () {
        const firstManifest = manifest({ requires: { hard: [] } });
        const secondManifest = manifest({
            id: 'org.example.rules.alternate',
            requires: { hard: [] },
            contributes: {
                artifactSources: [
                    {
                        id: 'org.example.rules.alternate.rule-sets',
                        type: 'rule-set',
                        contract: 'substore.rule-set@1',
                        representations: ['surge-rule-set'],
                    },
                ],
            },
        });
        enableManifests(firstManifest, secondManifest);
        registerExtension({
            extensionId: firstManifest.id,
            manifest: firstManifest,
            artifactSources: [source()],
        });
        registerExtension({
            extensionId: secondManifest.id,
            manifest: secondManifest,
            artifactSources: [
                source({ id: 'org.example.rules.alternate.rule-sets' }),
            ],
        });

        expect(() => getArtifactSourceAdapter('rule-set'))
            .to.throw()
            .with.property('code', 'RESOURCE_PROVIDER_AMBIGUOUS');
    });

    it('lists strict descriptors with stable refs without exposing provider-only fields', async function () {
        const strictManifest = manifest();
        const stableRef = {
            schema: 'substore.resource-ref@1',
            providerId: strictManifest.id,
            providerContributionId: 'org.example.rules.rule-sets',
            type: 'rule-set',
            id: 'rs_7bce398f',
            contract: 'substore.rule-set@1',
        };
        enableManifests(strictManifest);
        registerExtension({
            extensionId: strictManifest.id,
            manifest: strictManifest,
            artifactSources: [
                source({
                    list: () => [
                        {
                            schema: 'substore.resource-descriptor@1',
                            ref: stableRef,
                            name: 'Advertising renamed',
                            contracts: ['substore.rule-set@1'],
                            representations: ['surge-rule-set'],
                            lifecycle: { state: 'active' },
                            availability: { status: 'available' },
                            secretBody: 'DOMAIN,secret.example',
                            token: 'must-not-leak',
                            url: 'https://example.com/private?token=secret',
                        },
                    ],
                }),
            ],
        });

        const groups = await listArtifactSources();

        expect(groups).to.have.length(1);
        expect(groups[0]).to.include({
            id: 'org.example.rules.rule-sets',
            sourceId: 'org.example.rules.rule-sets',
            type: 'rule-set',
            contract: 'substore.rule-set@1',
            ownerExtensionId: strictManifest.id,
            status: 'enabled',
        });
        expect(groups[0].items).to.have.length(1);
        expect(groups[0].items[0].ref).to.deep.equal(stableRef);
        expect(groups[0].items[0].name).to.equal('Advertising renamed');
        expect(groups[0].items[0]).to.not.have.any.keys(
            'secretBody',
            'token',
            'url',
        );
    });
});

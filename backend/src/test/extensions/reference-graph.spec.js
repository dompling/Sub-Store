import { expect } from 'chai';
import { describe, it } from 'mocha';
import { EXTENSION_REFERENCE_INDEX_KEY } from '@/constants';
import { createExtensionReferenceIndex } from '@/extensions/reference-index';
import { RESOURCE_REF_SCHEMA } from '@/extensions/resource-contracts';

function resourceRef(overrides = {}) {
    return {
        schema: RESOURCE_REF_SCHEMA,
        providerId: 'org.example.rule-studio',
        providerContributionId: 'org.example.rule-studio.rule-sets',
        type: 'rule-set',
        id: 'advertising',
        contract: 'substore.rule-set@1',
        ...overrides,
    };
}

function ownerRef(overrides = {}) {
    return resourceRef({
        providerId: 'org.example.config-generator',
        providerContributionId: 'org.example.config-generator.config-projects',
        type: 'config-project',
        id: 'daily-config',
        contract: 'substore.config-project@1',
        ...overrides,
    });
}

function createStore(initial = {}) {
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
        writes() {
            return writes;
        },
    };
}

function persistedIndex(store) {
    return JSON.parse(store.read(EXTENSION_REFERENCE_INDEX_KEY));
}

function expectDiagnosticFailure(operation) {
    expect(operation)
        .to.throw()
        .that.satisfies(
            (error) => typeof error.code === 'string' && error.code.length > 0,
        );
}

describe('Extension resource reference index', function () {
    it('persists normalized owner-to-target edges using schema version 1', function () {
        const store = createStore();
        const index = createExtensionReferenceIndex({ store });
        const owner = ownerRef({ ignored: 'not part of ResourceRefV1' });
        const target = resourceRef({ ignored: 'not part of ResourceRefV1' });

        index.replaceOwn({ owner, targets: [target] });

        expect(persistedIndex(store)).to.deep.equal({
            schemaVersion: 1,
            edges: [
                {
                    owner: ownerRef(),
                    target: resourceRef(),
                },
            ],
        });
        expect(store.writes()).to.equal(1);
    });

    it('replaces all prior targets owned by the same resource', function () {
        const store = createStore();
        const index = createExtensionReferenceIndex({ store });
        const owner = ownerRef();
        const removedTarget = resourceRef({ id: 'advertising' });
        const retainedTarget = resourceRef({ id: 'privacy' });

        index.replaceOwn({ owner, targets: [removedTarget] });
        index.replaceOwn({ owner, targets: [retainedTarget] });

        expect(index.listIncoming(removedTarget)).to.deep.equal({
            available: true,
            items: [],
        });
        expect(index.listIncoming(retainedTarget)).to.deep.equal({
            available: true,
            items: [{ owner, target: retainedTarget }],
        });
    });

    it('preserves edges owned by other resources during replacement', function () {
        const store = createStore();
        const index = createExtensionReferenceIndex({ store });
        const target = resourceRef();
        const firstOwner = ownerRef({ id: 'first-config' });
        const secondOwner = ownerRef({ id: 'second-config' });

        index.replaceOwn({ owner: firstOwner, targets: [target] });
        index.replaceOwn({ owner: secondOwner, targets: [target] });
        index.replaceOwn({ owner: firstOwner, targets: [] });

        expect(index.listIncoming(target)).to.deep.equal({
            available: true,
            items: [{ owner: secondOwner, target }],
        });
    });

    it('deduplicates repeated targets for one owner', function () {
        const store = createStore();
        const index = createExtensionReferenceIndex({ store });
        const owner = ownerRef();
        const target = resourceRef();

        index.replaceOwn({ owner, targets: [target, { ...target }, target] });

        expect(index.listIncoming(target)).to.deep.equal({
            available: true,
            items: [{ owner, target }],
        });
        expect(persistedIndex(store).edges).to.have.length(1);
    });

    it('matches incoming references by every ResourceRefV1 identity field', function () {
        const store = createStore();
        const index = createExtensionReferenceIndex({ store });
        const owner = ownerRef();
        const target = resourceRef();

        index.replaceOwn({ owner, targets: [target] });

        expect(index.listIncoming(target)).to.deep.equal({
            available: true,
            items: [{ owner, target }],
        });
        for (const [field, value] of [
            ['providerId', 'org.example.other-provider'],
            ['providerContributionId', 'org.example.rule-studio.other-source'],
            ['type', 'subscription'],
            ['id', 'privacy'],
            ['contract', 'substore.rule-set@2'],
        ]) {
            expect(
                index.listIncoming({ ...target, [field]: value }),
                field,
            ).to.deep.equal({ available: true, items: [] });
        }
    });

    it('fails closed on corrupt persisted JSON without overwriting it', function () {
        const original = '{invalid json';
        const store = createStore({
            [EXTENSION_REFERENCE_INDEX_KEY]: original,
        });

        expectDiagnosticFailure(() => {
            const index = createExtensionReferenceIndex({ store });
            index.replaceOwn({ owner: ownerRef(), targets: [resourceRef()] });
        });

        expect(store.read(EXTENSION_REFERENCE_INDEX_KEY)).to.equal(original);
        expect(store.writes()).to.equal(0);
    });

    it('does not treat corrupt persisted JSON as an empty incoming index', function () {
        const store = createStore({
            [EXTENSION_REFERENCE_INDEX_KEY]: '{invalid json',
        });

        expectDiagnosticFailure(() => {
            const index = createExtensionReferenceIndex({ store });
            index.listIncoming(resourceRef());
        });
    });

    it('fails closed on a future schema without overwriting it', function () {
        const original = JSON.stringify({ schemaVersion: 2, edges: [] });
        const store = createStore({
            [EXTENSION_REFERENCE_INDEX_KEY]: original,
        });

        expectDiagnosticFailure(() => {
            const index = createExtensionReferenceIndex({ store });
            index.replaceOwn({ owner: ownerRef(), targets: [resourceRef()] });
        });

        expect(store.read(EXTENSION_REFERENCE_INDEX_KEY)).to.equal(original);
        expect(store.writes()).to.equal(0);
    });

    it('does not read a future schema as an empty incoming index', function () {
        const store = createStore({
            [EXTENSION_REFERENCE_INDEX_KEY]: JSON.stringify({
                schemaVersion: 2,
                edges: [],
            }),
        });

        expectDiagnosticFailure(() => {
            const index = createExtensionReferenceIndex({ store });
            index.listIncoming(resourceRef());
        });
    });
});

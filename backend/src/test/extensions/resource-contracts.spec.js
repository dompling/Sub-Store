import { expect } from 'chai';
import { describe, it } from 'mocha';
import {
    RESOURCE_DESCRIPTOR_SCHEMA,
    RESOURCE_OUTPUT_SCHEMA,
    RESOURCE_REF_SCHEMA,
    normalizeResourceDescriptor,
    normalizeResourceOutput,
    normalizeResourceRef,
    resourceRefKey,
} from '@/extensions/resource-contracts';

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

describe('Resource contracts', function () {
    it('normalizes a complete versioned resource reference', function () {
        const input = resourceRef();

        const normalized = normalizeResourceRef(input);

        expect(normalized).to.deep.equal(input);
        expect(Object.isFrozen(normalized)).to.equal(true);
    });

    it('rejects a resource reference without a contract', function () {
        const input = resourceRef();
        delete input.contract;

        expect(() => normalizeResourceRef(input))
            .to.throw()
            .that.satisfies(
                (error) =>
                    error.code === 'RESOURCE_REF_INVALID' &&
                    error.details?.field === 'contract',
            );
    });

    it('rejects a resource reference with an unsupported schema', function () {
        expect(() =>
            normalizeResourceRef(resourceRef({ schema: 'resource-ref@2' })),
        )
            .to.throw()
            .that.satisfies(
                (error) =>
                    error.code === 'RESOURCE_REF_INVALID' &&
                    error.details?.field === 'schema',
            );
    });

    it('rejects malformed versioned contracts', function () {
        for (const contract of [
            'substore.rule-set',
            'substore.rule-set@0',
            'substore.rule-set@1.1',
            '@1',
        ]) {
            expect(
                () => normalizeResourceRef(resourceRef({ contract })),
                contract,
            )
                .to.throw()
                .that.satisfies(
                    (error) =>
                        error.code === 'RESOURCE_REF_INVALID' &&
                        error.details?.field === 'contract',
                );
        }
    });

    it('uses every identity field when constructing a resource key', function () {
        const base = resourceRef();
        const baseKey = resourceRefKey(base);

        for (const [field, value] of [
            ['providerId', 'org.example.other'],
            ['providerContributionId', 'org.example.rules.other'],
            ['type', 'subscription'],
            ['id', 'privacy'],
            ['contract', 'substore.rule-set@2'],
        ]) {
            expect(
                resourceRefKey({ ...base, [field]: value }),
                field,
            ).to.not.equal(baseKey);
        }
    });

    it('defaults descriptor lifecycle and availability to usable states', function () {
        const ref = resourceRef();

        const descriptor = normalizeResourceDescriptor({
            ref,
            representations: ['surge-rule-set'],
        });

        expect(descriptor).to.include({
            schema: RESOURCE_DESCRIPTOR_SCHEMA,
            name: ref.id,
        });
        expect(descriptor.lifecycle).to.deep.equal({ state: 'active' });
        expect(descriptor.availability).to.deep.equal({
            status: 'available',
        });
    });

    it('preserves an archived unavailable descriptor', function () {
        const descriptor = normalizeResourceDescriptor({
            ref: resourceRef(),
            name: 'Advertising rules',
            contracts: ['substore.rule-set@1'],
            representations: ['surge-rule-set'],
            lifecycle: { state: 'archived', archivedAt: 1720000000000 },
            availability: { status: 'missing', reason: 'archived' },
        });

        expect(descriptor.lifecycle).to.deep.equal({
            state: 'archived',
            archivedAt: 1720000000000,
        });
        expect(descriptor.availability).to.deep.equal({
            status: 'missing',
            reason: 'archived',
        });
    });

    it('rejects descriptor lifecycle states outside the contract', function () {
        expect(() =>
            normalizeResourceDescriptor({
                ref: resourceRef(),
                representations: ['surge-rule-set'],
                lifecycle: { state: 'deleted' },
            }),
        )
            .to.throw()
            .with.property('code', 'RESOURCE_DESCRIPTOR_INVALID');
    });

    it('rejects descriptor availability states outside the contract', function () {
        expect(() =>
            normalizeResourceDescriptor({
                ref: resourceRef(),
                representations: ['surge-rule-set'],
                availability: { status: 'unknown' },
            }),
        )
            .to.throw()
            .with.property('code', 'RESOURCE_DESCRIPTOR_INVALID');
    });

    it('wraps a legacy string as a fresh text resource output', function () {
        const ref = resourceRef();

        const output = normalizeResourceOutput('DOMAIN,example.com', {
            ref,
            representation: 'surge-rule-set',
            legacy: true,
        });

        expect(output).to.deep.equal({
            schema: RESOURCE_OUTPUT_SCHEMA,
            ref,
            representation: 'surge-rule-set',
            body: 'DOMAIN,example.com',
            mediaType: 'text/plain',
            freshness: { state: 'fresh' },
            diagnostics: [],
        });
    });

    it('wraps a node array as JSON for the node representation', function () {
        const ref = resourceRef({
            type: 'subscription',
            contract: 'substore.subscription@1',
        });
        const nodes = [{ name: 'Tokyo', type: 'vmess' }];

        const output = normalizeResourceOutput(nodes, {
            ref,
            representation: 'substore-nodes-json',
        });

        expect(output.body).to.equal(JSON.stringify(nodes));
        expect(output.mediaType).to.equal('application/json');
        expect(output.representation).to.equal('substore-nodes-json');
    });

    it('rejects an output envelope for a different representation', function () {
        const privateBody = 'PRIVATE RULE CONTENT';

        expect(() =>
            normalizeResourceOutput(
                {
                    representation: 'qx-rule-set',
                    body: privateBody,
                },
                {
                    ref: resourceRef(),
                    representation: 'surge-rule-set',
                },
            ),
        )
            .to.throw()
            .that.satisfies(
                (error) =>
                    error.code === 'RESOURCE_OUTPUT_INVALID' &&
                    error.details?.requested === 'surge-rule-set' &&
                    !JSON.stringify(error.details).includes(privateBody),
            );
    });
});

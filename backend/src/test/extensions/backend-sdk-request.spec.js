import { expect } from 'chai';
import { describe, it } from 'mocha';
import { createBackendExtensionSdkV1 } from '@/extensions/backend-sdk-v1';

function createSdk() {
    return createBackendExtensionSdkV1({
        extensionId: 'org.example.request-client',
        manifest: { permissions: [] },
        store: {},
    });
}

describe('Backend Extension SDK request service', function () {
    it('uses the same User-Agent target detection as Host downloads', function () {
        const resolve = createSdk().request.resolveClientTarget;
        const cases = [
            ['Surge iOS/5.12.0', 'Surge'],
            ['Quantumult%20X/1.4.0', 'QX'],
            ['Loon/852 CFNetwork/1498.700.2', 'Loon'],
            ['Clash-Verge/v2.4.2', 'ClashMeta'],
        ];

        for (const [userAgent, value] of cases) {
            expect(
                resolve({ headers: { 'user-agent': userAgent } }),
            ).to.deep.equal({ value, source: 'user-agent' });
        }
    });

    it('preserves platform query precedence over target and headers', function () {
        expect(
            createSdk().request.resolveClientTarget({
                query: { platform: 'JSON', target: 'Loon' },
                headers: { 'user-agent': 'Surge iOS/5.12.0' },
            }),
        ).to.deep.equal({ value: 'JSON', source: 'platform-query' });
    });

    it('uses target query when platform is absent', function () {
        expect(
            createSdk().request.resolveClientTarget({
                query: { target: 'Loon' },
                headers: { 'user-agent': 'Surge iOS/5.12.0' },
            }),
        ).to.deep.equal({ value: 'Loon', source: 'target-query' });
    });

    it('reports Accept detection and the existing V2Ray default', function () {
        const resolve = createSdk().request.resolveClientTarget;

        expect(
            resolve({ headers: { accept: 'application/json, text/plain' } }),
        ).to.deep.equal({ value: 'JSON', source: 'accept' });
        expect(resolve()).to.deep.equal({
            value: 'V2Ray',
            source: 'default',
        });
    });
});

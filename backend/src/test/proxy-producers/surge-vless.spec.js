import { expect } from 'chai';
import { describe, it } from 'mocha';

import { ProxyUtils } from '@/core/proxy-utils';
import { produceExternal, UUID } from './helpers';

const base = {
    type: 'vless',
    name: 'VLESS',
    server: 'vless.example.com',
    port: 443,
    uuid: UUID,
};

describe('Surge VLESS producer', function () {
    for (const target of ['Surge', 'SurgeMac']) {
        it(`rejects unknown security on ${target} with external fallback enabled`, function () {
            const output = produceExternal(
                target,
                [
                    { ...base, security: 'xtls' },
                    {
                        type: 'http',
                        name: 'Working',
                        server: 'http.example.com',
                        port: 80,
                    },
                ],
                { useMihomoExternal: true },
            );
            expect(output).to.equal('Working=http,http.example.com,80');
        });
    }

    it('filters VLESS policies without a user ID', function () {
        expect(
            ProxyUtils.produce(
                [{ ...base, uuid: undefined }],
                'Surge',
                'external',
            ),
        ).to.equal('');
    });

    for (const target of ['Surge', 'SurgeMac']) {
        it(`uses the working REALITY field names for ${target}`, function () {
            const output = produceExternal(target, {
                ...base,
                flow: 'xtls-rprx-vision',
                tls: true,
                sni: 'sni.example.com',
                'reality-opts': {
                    'public-key': 'public-key',
                    'short-id': 'abcd',
                },
            });
            expect(output).to.equal(
                `VLESS=vless,"vless.example.com",443,encryption="none",fingerprint="chrome",flow="xtls-rprx-vision",packet-encoding="auto",reality-public-key="public-key",reality-short-id="abcd",security="reality",transport="tcp",uuid="${UUID}",sni="sni.example.com"`,
            );
        });
    }

    it('preserves explicit fingerprint and UDP packet encoding', function () {
        const output = produceExternal('Surge', {
            ...base,
            tls: true,
            'client-fingerprint': 'firefox',
            'packet-encoding': 'xudp',
        });
        expect(output).to.include(',fingerprint="firefox"');
        expect(output).to.include(',packet-encoding="xudp"');
    });

    it('preserves explicitly disabled UDP packet encoding', function () {
        const output = produceExternal('Surge', {
            ...base,
            'packet-encoding': '',
        });
        expect(output).to.include(',packet-encoding="none"');
    });

    for (const platform of ['Surge', 'SurgeMac']) {
        it(`filters finalmask nodes on ${platform} instead of losing masking through fallback`, function () {
            const [proxy] = ProxyUtils.parse(
                `vless://${UUID}@vless.example.com:443?security=tls&fm=${encodeURIComponent(
                    JSON.stringify({
                        udp: [
                            {
                                type: 'salamander',
                                settings: { password: 'mask' },
                            },
                        ],
                    }),
                )}#Masked`,
            );
            const output = produceExternal(
                platform,
                [
                    proxy,
                    {
                        type: 'http',
                        name: 'Working',
                        server: 'http.example.com',
                        port: 80,
                    },
                ],
                { useMihomoExternal: true },
            );
            expect(output).to.equal('Working=http,http.example.com,80');
        });
    }

    for (const username of ['alice,bob', 'alice bob']) {
        it(`quotes custom VLESS usernames containing ${
            username.includes(',') ? 'commas' : 'spaces'
        }`, function () {
            const output = produceExternal('Surge', {
                ...base,
                uuid: username,
            });
            expect(output).to.include(`,uuid="${username}"`);
            expect(ProxyUtils.parse(output)[0].uuid).to.equal(username);
        });
    }

    it('accepts the RAW transport alias from VLESS share links', function () {
        const proxies = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443?type=raw&security=tls&flow=xtls-rprx-vision#Raw`,
        );
        const output = produceExternal('Surge', proxies);
        expect(output).to.include(`Raw=vless,"vless.example.com",443,`);
        expect(output).to.include(',flow="xtls-rprx-vision"');
    });

    for (const platform of ['Surge', 'SurgeMac']) {
        it(`exports native VLESS on ${platform} even when external fallback is enabled`, function () {
            const output = produceExternal(platform, base, {
                useMihomoExternal: true,
            });
            expect(output).to.equal(
                `VLESS=vless,"vless.example.com",443,encryption="none",fingerprint="chrome",packet-encoding="auto",security="none",transport="tcp",uuid="${UUID}"`,
            );
        });
    }

    it('exports TLS Vision with common policy and certificate options', function () {
        const output = produceExternal('Surge', {
            ...base,
            tls: true,
            flow: 'xtls-rprx-vision',
            sni: 'sni.example.com',
            alpn: ['h2', 'http/1.1'],
            'skip-cert-verify': false,
            'name-cert-verify': 'verify.example.com',
            tfo: true,
            'ip-version': 'ipv4',
            'test-url': 'https://test.example.com',
            'underlying-proxy': 'Relay',
        });
        for (const field of [
            'flow="xtls-rprx-vision"',
            'security="tls"',
            'sni="sni.example.com"',
            'alpn="h2,http/1.1"',
            'skip-cert-verify=false',
            'server-cert-verify-name="verify.example.com"',
            'tfo=true',
            'ip-version=v4-only',
            'test-url=https://test.example.com',
            'underlying-proxy=Relay',
        ]) {
            expect(output).to.include(`,${field}`);
        }
        expect(output).to.not.include('vmess-aead');
        expect(output).to.not.include('encrypt-method');
    });

    it('keeps REALITY keys and Vision when converting a VLESS share link', function () {
        const proxies = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443?security=reality&type=tcp&pbk=public-key&sid=0123456789abcdef&sni=www.example.com&flow=xtls-rprx-vision-udp443#Reality`,
        );
        const output = produceExternal('Surge', proxies);
        expect(output).to.include(`Reality=vless,"vless.example.com",443,`);
        expect(output).to.include(',reality-public-key="public-key"');
        expect(output).to.include(',reality-short-id="0123456789abcdef"');
        expect(output).to.include(',flow="xtls-rprx-vision-udp443"');
        expect(output).to.include(',sni="www.example.com"');
    });

    for (const tls of [false, true]) {
        it(`exports WebSocket with tls=${tls} and preserves headers`, function () {
            const output = produceExternal('Surge', {
                ...base,
                network: 'ws',
                tls,
                'ws-opts': {
                    path: '/vless',
                    headers: { Host: 'cdn.example.com' },
                },
            });
            expect(output).to.include(',transport="ws"');
            expect(output).to.include(',ws-path="/vless"');
            expect(output).to.include(',ws-headers="Host:"cdn.example.com""');
            expect(output).to.include(`,security="${tls ? 'tls' : 'none'}"`);
        });
    }

    for (const security of [
        { tls: true },
        { 'reality-opts': { 'public-key': 'public-key', 'short-id': '' } },
    ]) {
        it(`exports gRPC with ${
            security.tls ? 'TLS' : 'REALITY'
        } and URI mode/authority`, function () {
            const output = produceExternal('Surge', {
                ...base,
                ...security,
                network: 'grpc',
                'grpc-opts': {
                    'grpc-service-name': '/my/path/tun',
                    '_grpc-type': 'multi',
                    '_grpc-authority': 'grpc.example.com',
                },
            });
            expect(output).to.include(',transport="grpc"');
            expect(output).to.include(',grpc-service-name="/my/path/tun"');
            expect(output).to.include(',grpc-mode="multi"');
            expect(output).to.include(',grpc-authority="grpc.example.com"');
        });
    }

    it('omits certificate parameters for plaintext VLESS', function () {
        const output = produceExternal('Surge', {
            ...base,
            tls: false,
            sni: 'unused.example.com',
            alpn: ['h2'],
            'skip-cert-verify': true,
        });
        expect(output).to.include(',security="none"');
        expect(output).to.not.include('sni=');
        expect(output).to.not.include('alpn=');
        expect(output).to.not.include('skip-cert-verify=');
    });

    it('round-trips generated REALITY gRPC policies through native Surge parsing', function () {
        const output = produceExternal('Surge', {
            ...base,
            network: 'grpc',
            'reality-opts': { 'public-key': 'key', 'short-id': '' },
            'grpc-opts': {
                'grpc-service-name': 'service',
                '_grpc-type': 'multi',
                '_grpc-authority': 'authority.example.com',
            },
        });
        const [parsed] = ProxyUtils.parse(output);
        expect(parsed['reality-opts']).to.deep.equal({
            'public-key': 'key',
            'short-id': '',
        });
        expect(parsed['grpc-opts']).to.deep.equal({
            'grpc-service-name': 'service',
            '_grpc-type': 'multi',
            '_grpc-authority': 'authority.example.com',
        });
    });

    it('preserves gRPC authority from share links without a service name', function () {
        const proxies = ProxyUtils.parse(
            `vless://${UUID}@vless.example.com:443?type=grpc&security=tls&authority=custom.example.com#Grpc`,
        );
        const output = produceExternal('Surge', proxies);
        expect(output).to.include(',transport="grpc"');
        expect(output).to.include(',grpc-authority="custom.example.com"');
    });

    for (const [label, fields] of [
        ['unknown security', { security: 'invalid' }],
        ['XHTTP', { network: 'xhttp' }],
        ['HTTP', { network: 'http' }],
        [
            'HTTPUpgrade',
            { network: 'ws', 'ws-opts': { 'v2ray-http-upgrade': true } },
        ],
        ['mKCP', { network: 'kcp' }],
        [
            'VLESS Encryption',
            { encryption: 'mlkem768x25519plus.native.1rtt.key' },
        ],
        [
            'WebSocket REALITY',
            { network: 'ws', 'reality-opts': { 'public-key': 'key' } },
        ],
        ['WebSocket Vision', { network: 'ws', flow: 'xtls-rprx-vision' }],
        ['gRPC Vision', { network: 'grpc', flow: 'xtls-rprx-vision' }],
        ['unknown flow', { flow: 'xtls-rprx-direct' }],
        ['plaintext Vision', { tls: false, flow: 'xtls-rprx-vision' }],
        ['plaintext gRPC', { tls: false, network: 'grpc' }],
        [
            'unknown gRPC mode',
            { network: 'grpc', 'grpc-opts': { '_grpc-type': 'invalid' } },
        ],
    ]) {
        it(`filters ${label} without discarding other nodes`, function () {
            const output = produceExternal(
                'Surge',
                [
                    { ...base, tls: true, ...fields },
                    {
                        type: 'http',
                        name: 'Working',
                        server: 'http.example.com',
                        port: 80,
                    },
                ],
                { 'include-unsupported-proxy': true },
            );
            expect(output).to.equal('Working=http,http.example.com,80');
        });
    }
});

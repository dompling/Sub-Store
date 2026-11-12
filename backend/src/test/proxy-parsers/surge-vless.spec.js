import { expect } from 'chai';
import { describe, it } from 'mocha';

import { ProxyUtils } from '@/core/proxy-utils';
import { UUID, expectSubset, parseAll, parseOne } from './helpers';

describe('Surge VLESS parser', function () {
    it('parses REALITY and Vision from native Surge subscriptions', function () {
        const proxy = parseOne(
            `Proxy-REALITY = vless, 1.2.3.4, 443, username=${UUID}, flow=xtls-rprx-vision, sni=www.microsoft.com, reality-public-key=dwrjY6KiAMPxKdlF7T4AWFXXBtsxeHCXtBQYeCOdZV4, reality-short-id=0123456789abcdef`,
        );

        expectSubset(proxy, {
            name: 'Proxy-REALITY',
            type: 'vless',
            server: '1.2.3.4',
            port: 443,
            uuid: UUID,
            network: 'tcp',
            tls: true,
            flow: 'xtls-rprx-vision',
            sni: 'www.microsoft.com',
            'reality-opts': {
                'public-key': 'dwrjY6KiAMPxKdlF7T4AWFXXBtsxeHCXtBQYeCOdZV4',
                'short-id': '0123456789abcdef',
            },
        });
    });

    it('parses WebSocket TLS and common policy options', function () {
        const proxy = parseOne(
            `Proxy-WS=vless,ws.example.com,443,username="${UUID}",ws=true,ws-path=/vless,ws-headers="Host:cdn.example.com|X-Test:client",tls=true,sni=tls.example.com,alpn="http/1.1,h2",skip-cert-verify=true,tfo=true,udp-relay=true,underlying-proxy=Relay`,
        );

        expectSubset(proxy, {
            type: 'vless',
            uuid: UUID,
            network: 'ws',
            tls: true,
            sni: 'tls.example.com',
            alpn: ['http/1.1', 'h2'],
            'skip-cert-verify': true,
            tfo: true,
            udp: true,
            'underlying-proxy': 'Relay',
            'ws-opts': {
                path: '/vless',
                headers: { Host: 'cdn.example.com', 'X-Test': 'client' },
            },
        });
    });

    for (const security of ['tls=true', 'reality-public-key=public-key']) {
        it(`parses gRPC options with ${security}`, function () {
            const proxy = parseOne(
                `Proxy-gRPC=vless,grpc.example.com,443,username=${UUID},grpc=true,grpc-service-name=/my/path/tun,grpc-mode=multi,grpc-authority=authority.example.com,${security}`,
            );

            expectSubset(proxy, {
                type: 'vless',
                network: 'grpc',
                tls: true,
                'grpc-opts': {
                    'grpc-service-name': '/my/path/tun',
                    '_grpc-type': 'multi',
                    '_grpc-authority': 'authority.example.com',
                },
            });
            const uri = ProxyUtils.produce([proxy], 'URI', 'external');
            expect(uri).to.include('type=grpc');
            expect(uri).to.include('mode=multi');
            expect(uri).to.include('authority=authority.example.com');
        });
    }

    it('keeps short usernames and disabled transports on TCP', function () {
        const proxy = parseOne(
            "Plain=vless,plain.example.com,80,username='my-user',ws=false,grpc=false,encryption=none",
        );

        expectSubset(proxy, {
            type: 'vless',
            uuid: 'my-user',
            network: 'tcp',
            encryption: 'none',
        });
    });

    it('accepts an explicitly empty REALITY short ID', function () {
        const proxy = parseOne(
            `Empty SID=vless,reality.example.com,443,username=${UUID},reality-public-key=public-key,reality-short-id=,tls=false`,
        );

        expectSubset(proxy, {
            tls: true,
            'reality-opts': { 'public-key': 'public-key', 'short-id': '' },
        });
    });

    it('keeps unsupported encryption visible to downstream producers', function () {
        const proxy = parseOne(
            `Encrypted=vless,encrypted.example.com,443,username=${UUID},encryption=mlkem768x25519plus.native.600s.key`,
        );

        expect(proxy.encryption).to.equal('mlkem768x25519plus.native.600s.key');
    });

    it('parses mixed subscriptions and exports REALITY to Mihomo', function () {
        const proxies = parseAll(
            `Direct=direct\nReality=vless,vless.example.com,443,username=${UUID},reality-public-key=public-key,reality-short-id=abcd,flow=xtls-rprx-vision\nTrojan=trojan,trojan.example.com,443,password=secret`,
        );

        expect(proxies.map((proxy) => proxy.type)).to.deep.equal([
            'direct',
            'vless',
            'trojan',
        ]);
        const output = ProxyUtils.produce(proxies, 'ClashMeta', 'internal');
        expectSubset(
            output.find((proxy) => proxy.type === 'vless'),
            {
                type: 'vless',
                uuid: UUID,
                tls: true,
                flow: 'xtls-rprx-vision',
                'reality-opts': {
                    'public-key': 'public-key',
                    'short-id': 'abcd',
                },
            },
        );
    });
});

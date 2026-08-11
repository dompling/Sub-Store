import { expect } from 'chai';
import { after, afterEach, before, describe, it } from 'mocha';
import $ from '@/core/app';
import YAML from '@/utils/yaml';
import { COLLECTIONS_KEY, CONFIG_GENERATOR_KEY, SUBS_KEY } from '@/constants';
import { produceArtifact } from '@/restful/sync';

import {
    ConfigGeneratorValidationError,
    configGeneratorArtifactSource,
    createRemoteProxySourceContext,
    generateClashConfig,
    generateLoonConfig,
    generateQXConfig,
    generateSurgeConfig,
    getTargetIds,
    importClashConfig,
    importLoonConfig,
    importQXConfig,
    importSurgeConfig,
    normalizeTargetId,
    parseProfileSections,
    parseSurgeCsv,
    policyGroupCapabilityDiagnostics,
    projectGroupRemoteProxySource,
    projectIncludedPolicyGroups,
    registerConfigGeneratorRoutes,
    registerEmbeddedConfigGenerator,
    replaceManagedSections,
    resolvePolicyGroupCapability,
    resolveRuleSetUrl,
    serializeProfileSections,
    serializeSurgeCsv,
    unbindConfigGeneratorSdk,
    validateProject,
} from '@/extensions/embedded/config-generator';
import { resetExtensionManagerForTests } from '@/extensions/manager';
import { initializeExtensionHost } from '@/extensions/host';
import { clearExtensionRegistryForTests } from '@/extensions/registry';

function createRouteApp() {
    const handlers = new Map();
    const app = {};
    ['get', 'post', 'patch', 'delete'].forEach((method) => {
        app[method] = (path, handler) => {
            handlers.set(`${method.toUpperCase()} ${path}`, handler);
            return app;
        };
    });
    return { app, handlers };
}

function createResponse(path) {
    return {
        req: { route: { path } },
        statusCode: 200,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(body) {
            this.body = body;
            return this;
        },
        type() {
            return this;
        },
        send(body) {
            this.body = body;
            return this;
        },
    };
}

function createUnnamedRemoteRuleFixture() {
    const project = {
        name: 'unnamed-remote-rule',
        remoteProxySources: [],
        groups: [],
        rules: [
            {
                kind: 'remote',
                ruleSet: 'internal-rule-set-id',
                policy: 'REJECT',
            },
        ],
        outputs: { surge: {}, qx: {}, clash: {}, loon: {} },
    };
    const ruleSets = [
        {
            name: 'internal-rule-set-id',
            source: {
                kind: 'url',
                url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list',
                target: 'surge',
            },
        },
    ];
    return {
        project,
        ruleSets,
        input: {
            project,
            ruleSets,
            produceBuiltinArtifact: async () => '',
        },
    };
}

describe('config generator Surge extension', function () {
    const originalRead = $.read.bind($);
    const originalWrite = $.write.bind($);

    before(function () {
        clearExtensionRegistryForTests();
        initializeExtensionHost({
            reset: true,
            store: $,
            env: { isQX: true },
            registerEmbeddedExtensions: registerEmbeddedConfigGenerator,
            adoptLegacy: false,
            restoreEnabled: false,
        });
    });

    afterEach(function () {
        $.read = originalRead;
        $.write = originalWrite;
    });

    after(function () {
        unbindConfigGeneratorSdk();
        resetExtensionManagerForTests();
        clearExtensionRegistryForTests();
    });

    it('parses and replaces managed sections while preserving preamble and unmanaged sections', function () {
        const ast = parseProfileSections(
            '\uFEFF; preamble\r\n[General]\r\nfoo=bar\r\n[Rule]\r\nold\r\n',
        );
        const next = replaceManagedSections(ast, {
            'proxy group': ['Main = select, DIRECT'],
            rule: ['FINAL, DIRECT'],
        });
        const output = serializeProfileSections(next);
        expect(output).to.equal(
            '\uFEFF; preamble\r\n[General]\r\nfoo=bar\r\n[Proxy Group]\r\nMain = select, DIRECT\r\n[Rule]\r\nFINAL, DIRECT\r\n',
        );
    });

    it('quotes and round-trips Surge CSV values', function () {
        const line = serializeSurgeCsv([
            'PROCESS-NAME',
            'My App, (beta)',
            'Main',
        ]);
        expect(line).to.equal('PROCESS-NAME, "My App, (beta)", Main');
        expect(parseSurgeCsv(line)).to.deep.equal([
            'PROCESS-NAME',
            'My App, (beta)',
            'Main',
        ]);
    });

    it('generates a standalone Surge profile through the injected builtin producer', async function () {
        const project = {
            name: 'main',
            revision: 3,
            embeddedSource: { type: 'subscription', name: 'nodes' },
            remoteProxySources: [],
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
            ],
            rules: [
                { kind: 'comment', text: 'routing' },
                {
                    kind: 'inline',
                    type: 'DOMAIN-SUFFIX',
                    value: 'example.com',
                    policy: 'Main',
                },
                { kind: 'final', policy: 'DIRECT' },
            ],
            outputs: { surge: {} },
        };
        const result = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async ({ type }) => {
                if (type === 'file')
                    throw new Error('A base file must not be requested');
                return 'Proxy A = direct, a.example.com, 1\n';
            },
        });
        expect(result.sourceRevision).to.equal(3);
        expect(result.body).to.contain(
            '[Proxy]\nProxy A = direct, a.example.com, 1',
        );
        expect(result.body).to.contain('[Proxy Group]\nMain = select, DIRECT');
        expect(result.body).to.contain('[Rule]\n# routing\nDOMAIN-SUFFIX');
        expect(result.body).to.contain('DOMAIN-SUFFIX, example.com, Main');
        expect(result.body).to.contain('[General]');
        expect(result.body).to.contain('[Host]');
        expect(result.body).to.contain('[MITM]');
    });

    it('keeps Surge-only PROCESS-NAME rules in independent config without annotating inline rules', async function () {
        const result = await generateSurgeConfig({
            project: {
                name: 'grouped-rules',
                remoteProxySources: [],
                groups: [{ name: 'YouTube', type: 'select', members: [] }],
                rules: [
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'youtube.com',
                        policy: 'YouTube',
                    },
                    {
                        kind: 'inline',
                        type: 'PROCESS-NAME',
                        value: 'YouTube',
                        policy: 'YouTube',
                    },
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'ads.example.com',
                        policy: 'REJECT',
                    },
                ],
                outputs: {
                    surge: {
                        independentConfig:
                            '[General]\n\n[Rule]\nPROCESS-NAME, Legacy, YouTube\n\n[MITM]\n',
                    },
                },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(result.body).to.contain('PROCESS-NAME, Legacy, YouTube');
        expect(result.body).to.contain('DOMAIN, youtube.com, YouTube');
        expect(result.body).to.contain('DOMAIN, ads.example.com, REJECT');
        expect(result.body).to.not.contain(
            '# ==================== YouTube ====================',
        );
        expect(result.body).to.not.contain(
            '# ==================== REJECT ====================',
        );
        expect(
            result.body.indexOf('PROCESS-NAME, YouTube, YouTube'),
        ).to.be.lessThan(result.body.indexOf('DOMAIN, youtube.com, YouTube'));
        expect(result.body).to.contain(
            'DOMAIN, youtube.com, YouTube\nDOMAIN, ads.example.com, REJECT',
        );
    });

    it('preserves Surge rule order while annotating only RULE-SET blocks', async function () {
        const result = await generateSurgeConfig({
            project: {
                name: 'ordered-rules',
                remoteProxySources: [],
                groups: [
                    { name: 'A', type: 'select', members: [] },
                    { name: 'B', type: 'select', members: [] },
                ],
                rules: [
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'first.example',
                        policy: 'B',
                    },
                    { kind: 'remote', ruleSet: 'ads', policy: 'A' },
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'second.example',
                        policy: 'B',
                    },
                    { kind: 'final', policy: 'B' },
                ],
                outputs: { surge: {} },
            },
            ruleSets: [
                {
                    name: 'ads',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/ads.list',
                        target: 'surge',
                    },
                },
            ],
            produceBuiltinArtifact: async () => '',
        });

        const ruleSection = result.body.slice(result.body.indexOf('[Rule]'));
        expect(ruleSection).to.contain(
            'DOMAIN, first.example, B\n\n' +
                '# ==================== A ====================\n' +
                'RULE-SET, https://example.com/ads.list, A\n\n' +
                'DOMAIN, second.example, B\n' +
                'FINAL, B',
        );
        expect(ruleSection.indexOf('first.example')).to.be.lessThan(
            ruleSection.indexOf('ads.list'),
        );
        expect(ruleSection.indexOf('ads.list')).to.be.lessThan(
            ruleSection.indexOf('second.example'),
        );
    });

    it('reopens repeated RULE-SET policy blocks without reordering rules', async function () {
        const result = await generateSurgeConfig({
            project: {
                name: 'repeated-rule-set-policy',
                remoteProxySources: [],
                groups: [{ name: 'Proxy', type: 'select', members: [] }],
                rules: [
                    { kind: 'remote', ruleSet: 'first', policy: 'Proxy' },
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'separator.example',
                        policy: 'DIRECT',
                    },
                    { kind: 'remote', ruleSet: 'second', policy: 'Proxy' },
                ],
                outputs: { surge: {} },
            },
            ruleSets: [
                {
                    name: 'first',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/first.list',
                        target: 'surge',
                    },
                },
                {
                    name: 'second',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/second.list',
                        target: 'surge',
                    },
                },
            ],
            produceBuiltinArtifact: async () => '',
        });

        const ruleSection = result.body.slice(result.body.indexOf('[Rule]'));
        const heading = '# ==================== Proxy ====================';
        expect(ruleSection.split(heading)).to.have.length(3);
        expect(ruleSection).to.contain(
            `${heading}\n` +
                'RULE-SET, https://example.com/first.list, Proxy\n\n' +
                'DOMAIN, separator.example, DIRECT\n\n' +
                `${heading}\n` +
                'RULE-SET, https://example.com/second.list, Proxy',
        );
        expect(ruleSection.indexOf('first.list')).to.be.lessThan(
            ruleSection.indexOf('separator.example'),
        );
        expect(ruleSection.indexOf('separator.example')).to.be.lessThan(
            ruleSection.indexOf('second.list'),
        );
    });

    it('preserves Surge comment and blank rules while ending RULE-SET blocks', async function () {
        const result = await generateSurgeConfig({
            project: {
                name: 'rule-comments',
                remoteProxySources: [],
                groups: [{ name: 'Proxy', type: 'select', members: [] }],
                rules: [
                    { kind: 'remote', ruleSet: 'first', policy: 'Proxy' },
                    { kind: 'comment', text: 'manual divider' },
                    { kind: 'remote', ruleSet: 'second', policy: 'Proxy' },
                    { kind: 'blank' },
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'after.example',
                        policy: 'DIRECT',
                    },
                    { kind: 'blank' },
                    { kind: 'final', policy: 'Proxy' },
                ],
                outputs: { surge: {} },
            },
            ruleSets: [
                {
                    name: 'first',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/first.list',
                        target: 'surge',
                    },
                },
                {
                    name: 'second',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/second.list',
                        target: 'surge',
                    },
                },
            ],
            produceBuiltinArtifact: async () => '',
        });

        const ruleSection = result.body.slice(result.body.indexOf('[Rule]'));
        const heading = '# ==================== Proxy ====================';
        expect(ruleSection).to.contain(
            `${heading}\n` +
                'RULE-SET, https://example.com/first.list, Proxy\n\n' +
                '# manual divider\n' +
                `${heading}\n` +
                'RULE-SET, https://example.com/second.list, Proxy\n\n' +
                'DOMAIN, after.example, DIRECT\n\n' +
                'FINAL, Proxy',
        );
        expect(ruleSection.split(heading)).to.have.length(3);
    });

    it('rejects dangling policies and missing Surge output', function () {
        expect(() =>
            validateProject({ name: 'bad', groups: [], rules: [] }, []),
        ).to.throw(ConfigGeneratorValidationError);
    });

    it('requires a selected remote source for policy-path groups', function () {
        const project = {
            name: 'remote-group',
            remoteProxySources: [
                {
                    name: 'nodes',
                    source: { kind: 'url', url: 'https://example.com/proxies' },
                },
            ],
            groups: [
                {
                    name: 'Remote',
                    type: 'select',
                    members: [],
                    targetOptions: { surge: { remoteProxySource: '' } },
                },
            ],
            rules: [{ kind: 'final', policy: 'Remote' }],
            outputs: { surge: {} },
        };

        expect(() => validateProject(project, [])).to.throw(
            ConfigGeneratorValidationError,
        );
        project.groups[0].targetOptions.surge.remoteProxySource = 'nodes';
        expect(validateProject(project, [])).to.equal(project);
    });

    it('preserves combined policy sources and Surge-specific policy group options', async function () {
        const project = {
            name: 'combined-groups',
            remoteProxySources: [
                {
                    name: 'remote-nodes',
                    source: { kind: 'url', url: 'https://example.com/proxies' },
                },
            ],
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'proxy', value: 'Static Node' }],
                },
                {
                    name: 'Mixed',
                    type: 'url-test',
                    members: [
                        { kind: 'builtin', value: 'DIRECT' },
                        { kind: 'proxy', value: 'Manual Node' },
                    ],
                    includeAllProxies: true,
                    includeOtherGroups: ['Main'],
                    testUrl: 'https://www.gstatic.com/generate_204',
                    interval: 600,
                    tolerance: 100,
                    timeout: 5,
                    policyUpdateInterval: 43200,
                    targetOptions: {
                        surge: {
                            remoteProxySource: 'remote-nodes',
                            evaluateBeforeUse: true,
                            hidden: true,
                            noAlert: true,
                            iconUrl: 'https://example.com/mixed.png',
                        },
                    },
                },
                {
                    name: 'Balance',
                    type: 'load-balance',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: { surge: { persistent: true } },
                },
                {
                    name: 'Network',
                    type: 'subnet',
                    members: [],
                    targetOptions: {
                        surge: {
                            subnetDefault: 'Main',
                            subnetRules: [
                                { expression: 'TYPE:WIFI', policy: 'Mixed' },
                            ],
                        },
                    },
                },
            ],
            rules: [{ kind: 'final', policy: 'DIRECT' }],
            outputs: { surge: {} },
        };

        expect(validateProject(project, [])).to.equal(project);
        const generated = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(generated.body).to.contain(
            'Mixed = url-test, DIRECT, Manual Node, include-all-proxies=1, include-other-group=Main',
        );
        expect(generated.body).to.contain(
            'policy-path=https://example.com/proxies',
        );
        expect(generated.body).to.contain(
            'url=https://www.gstatic.com/generate_204, interval=600, tolerance=100, timeout=5',
        );
        expect(generated.body).to.contain(
            'update-interval=43200, hidden=1, no-alert=1, evaluate-before-use=1, icon-url=https://example.com/mixed.png',
        );
        expect(generated.body).to.contain(
            'Balance = load-balance, DIRECT, persistent=1',
        );
        expect(generated.body).to.contain(
            'Network = subnet, default=Main, TYPE:WIFI = Mixed',
        );

        const imported = importSurgeConfig(
            `[Proxy Group]\nMain = select, Static Node\nMixed = url-test, DIRECT, Manual Node, include-all-proxies=1, include-other-group=Main, policy-path=https://example.com/proxies, interval=600, tolerance=100, timeout=5, update-interval=43200, evaluate-before-use=1, icon-url=https://example.com/mixed.png\nBalance = load-balance, DIRECT, persistent=1\nNetwork = subnet, default=Main, TYPE:WIFI = Mixed, cellular=DIRECT\n[Rule]\nFINAL, DIRECT\n`,
        );
        expect(imported.project.groups[0].members).to.deep.equal([
            { kind: 'proxy', value: 'Static Node' },
        ]);
        expect(imported.project.groups[1].members).to.deep.include({
            kind: 'proxy',
            value: 'Manual Node',
        });
        expect(imported.project.groups[1].remoteProxySource).to.equal(
            'remote-1',
        );
        expect(imported.project.groups[1].policyUpdateInterval).to.equal(43200);
        expect(imported.project.groups[1].iconUrl).to.equal(
            'https://example.com/mixed.png',
        );
        expect(
            imported.project.groups[2].targetOptions.surge.persistent,
        ).to.equal(true);
        expect(imported.project.groups[3].targetOptions.surge).to.deep.include({
            subnetDefault: 'Main',
            subnetRules: [
                { expression: 'TYPE:WIFI', policy: 'Mixed' },
                { expression: 'TYPE:CELLULAR', policy: 'DIRECT' },
            ],
        });
    });

    it('merges Surge policy groups by name while retaining independent entries and comments', async function () {
        const result = await generateSurgeConfig({
            project: {
                name: 'surge-independent-groups',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Main',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                    },
                    {
                        name: 'Generated',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'REJECT' }],
                    },
                ],
                rules: [],
                outputs: {
                    surge: {
                        independentConfig:
                            '[General]\n\n[Proxy Group]\n# legacy group\nLegacy = select, DIRECT\n\n# keep this comment\nMain = url-test, OLD\n\nTail = select, REJECT\n\n[Rule]\n\n[MITM]\n',
                    },
                },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const groups = parseProfileSections(result.body).sections.find(
            (section) => section.name === 'proxy group',
        ).body;
        expect(groups).to.include('# legacy group');
        expect(groups).to.include('# keep this comment');
        expect(groups).to.include('Legacy = select, DIRECT');
        expect(groups).to.include('Tail = select, REJECT');
        expect(groups).to.include('Main = select, DIRECT');
        expect(groups).to.include('Generated = select, REJECT');
        expect(groups.filter((line) => /^Main\s*=/.test(line))).to.have.length(
            1,
        );
        expect(groups).to.not.include('Main = url-test, OLD');
        expect(groups.indexOf('Legacy = select, DIRECT')).to.be.lessThan(
            groups.indexOf('Main = select, DIRECT'),
        );
        expect(groups.indexOf('Main = select, DIRECT')).to.be.lessThan(
            groups.indexOf('Tail = select, REJECT'),
        );
        expect(groups.indexOf('Tail = select, REJECT')).to.be.lessThan(
            groups.indexOf('Generated = select, REJECT'),
        );
    });

    it('integrates config-project with produceArtifact and the builtin processing chain', async function () {
        const state = {
            [SUBS_KEY]: [
                {
                    name: 'nodes',
                    source: 'local',
                    content: 'http://user:pass@proxy.example.com:8080#Node',
                    process: [],
                },
            ],
            [COLLECTIONS_KEY]: [],
            [CONFIG_GENERATOR_KEY]: {
                version: 1,
                ruleSets: [],
                projects: [
                    {
                        name: 'main',
                        revision: 1,
                        embeddedSource: {
                            type: 'subscription',
                            name: 'nodes',
                        },
                        remoteProxySources: [],
                        groups: [
                            {
                                name: 'Main',
                                type: 'select',
                                members: [{ kind: 'builtin', value: 'DIRECT' }],
                            },
                        ],
                        rules: [{ kind: 'final', policy: 'Main' }],
                        outputs: {
                            surge: {},
                        },
                    },
                ],
            },
        };
        $.read = (key) => state[key] || [];

        const output = await produceArtifact({
            type: 'config-project',
            name: 'main',
            platform: 'Surge',
        });

        expect(output).to.contain('[General]');
        expect(output).to.match(/\[Proxy\]\nNode\s*=.*proxy\.example\.com/);
        expect(output).to.contain('[Rule]\nFINAL, Main');
    });

    it('imports policy paths, rule sets, comments, and inline rules into an editable project', function () {
        const draft = importSurgeConfig(
            `[General]\nloglevel = notify\n[Proxy Group]\n# primary\nMain = select, DIRECT\nRemote = smart, policy-path=https://example.com/proxies, include-other-group=Main\n[Rule]\n# routing\nRULE-SET, https://example.com/rules.list, Main, update-interval=86400, no-resolve\nDOMAIN-SUFFIX, example.com, Main\nFINAL, DIRECT, dns-failed\n[Host]\nexample.com = 1.1.1.1\n`,
        );

        expect(draft.detected).to.deep.include({
            groupCount: 2,
            ruleCount: 3,
            remoteProxySources: 1,
        });
        expect(draft.project.groups[1].remoteProxySource).to.equal('remote-1');
        expect(draft.ruleSets[0].updateInterval).to.equal(86400);
        expect(draft.project.rules[0]).to.deep.include({
            kind: 'remote',
            policy: 'Main',
            noResolve: true,
        });
        expect(
            draft.project.rules.some((rule) =>
                ['comment', 'blank'].includes(rule.kind),
            ),
        ).to.equal(false);
        expect(draft.project.outputs.surge.independentConfig).to.contain(
            '[General]\nloglevel = notify',
        );
        expect(draft.project.outputs.surge.independentConfig).to.contain(
            '[Host]\nexample.com = 1.1.1.1',
        );
        expect(draft).to.not.have.property('baseFileContent');
    });

    it('imports the policy groups and routing rules used by a Surge profile', function () {
        const draft = importSurgeConfig(
            `[Proxy Group]\nSpeedtest = select, policy-path=https://example.com/proxies, update-interval=43200\nSingapore = fallback, include-other-group=Speedtest, policy-regex-filter=狮|新|SG\nProxy = select, Singapore, Speedtest\nDisney+ = select, Singapore, Proxy\n[Rule]\nDOMAIN, sub.akax.eu.org, Proxy\nRULE-SET, https://example.com/Bing.list, Proxy\nFINAL, Proxy\n`,
        );

        expect(draft.project.groups.map((group) => group.name)).to.deep.equal([
            'Speedtest',
            'Singapore',
            'Proxy',
            'Disney+',
        ]);
        expect(draft.project.groups[2].members).to.deep.equal([
            { kind: 'group', value: 'Singapore' },
            { kind: 'group', value: 'Speedtest' },
        ]);
        expect(draft.project.rules).to.deep.include({
            kind: 'inline',
            type: 'DOMAIN',
            value: 'sub.akax.eu.org',
            policy: 'Proxy',
            noResolve: false,
        });
        expect(draft.ruleSets[0]).to.deep.include({
            source: {
                kind: 'url',
                url: 'https://example.com/Bing.list',
                target: 'surge',
            },
        });
        expect(draft.project.outputs.surge.independentConfig).to.match(/^\s*$/);
    });

    it('generates Quantumult X profiles from the shared project model', async function () {
        const project = {
            name: 'qx-main',
            revision: 2,
            embeddedSource: { type: 'collection', name: 'all' },
            remoteProxySources: [
                {
                    name: 'remote-nodes',
                    source: {
                        kind: 'sub-store',
                        type: 'collection',
                        name: 'all',
                        publicBaseUrl: 'https://sub.example.com',
                    },
                    targetOptions: {
                        qx: {
                            tag: 'Main',
                            updateInterval: 43200,
                            optParser: true,
                        },
                    },
                },
            ],
            groups: [
                {
                    name: 'Proxy',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        qx: { remoteProxySource: 'remote-nodes' },
                    },
                },
            ],
            rules: [
                {
                    kind: 'inline',
                    type: 'DOMAIN-SUFFIX',
                    value: 'example.com',
                    policy: 'Proxy',
                },
                {
                    kind: 'inline',
                    type: 'PROCESS-NAME',
                    value: 'Example',
                    policy: 'Proxy',
                },
                { kind: 'remote', ruleSet: 'ads', policy: 'REJECT' },
                { kind: 'final', policy: 'DIRECT' },
            ],
            outputs: { qx: {} },
        };
        const result = await generateQXConfig({
            project,
            ruleSets: [
                {
                    name: 'ads',
                    source: {
                        kind: 'url',
                        url: 'https://rules.example.com/ads.list',
                    },
                    updateInterval: 86400,
                },
            ],
            produceBuiltinArtifact: async () =>
                'Node A = ss, host.example.com, 443\n',
        });

        expect(result.body).to.contain(
            '[server_local]\nNode A = ss, host.example.com, 443',
        );
        expect(result.body).to.contain(
            '[general]\nresource_parser_url=https://raw.githubusercontent.com/KOP-XIAO/QuantumultX/master/Scripts/resource-parser.js',
        );
        expect(result.body).to.contain('[dns]');
        expect(result.body).to.contain('[mitm]');
        expect(result.body).to.contain(
            '[server_remote]\nhttps://sub.example.com/download/collection/all/QX, tag=Main, update-interval=43200, opt-parser=true',
        );
        expect(result.body).to.contain(
            '[policy]\nstatic=Proxy, DIRECT, resource-tag-regex=^Main$',
        );
        expect(result.body).to.contain(
            '[filter_local]\nhost-suffix, example.com, Proxy\nfinal, direct',
        );
        expect(result.body).to.not.contain('process-name, Example, Proxy');
        expect(result.body).to.contain(
            '[filter_remote]\nhttps://rules.example.com/ads.list, tag=ads, force-policy=reject, update-interval=86400, opt-parser=true, enabled=true',
        );
        expect(
            result.warnings.some(
                (warning) => warning.path === 'rules.PROCESS-NAME',
            ),
        ).to.equal(true);
        expect(result.stats.nodeCount).to.equal(1);
    });

    it('does not choose a Quantumult X remote-source interval by group order', async function () {
        const project = {
            name: 'qx-shared-source-intervals',
            remoteProxySources: [
                {
                    name: 'nodes',
                    source: {
                        kind: 'sub-store',
                        type: 'collection',
                        name: 'all',
                        publicBaseUrl: 'https://sub.example.com',
                    },
                },
            ],
            groups: [
                {
                    name: 'First',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    remoteProxySource: 'nodes',
                    policyUpdateInterval: 7200,
                },
                {
                    name: 'Second',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'REJECT' }],
                    remoteProxySource: 'nodes',
                    policyUpdateInterval: 3600,
                },
            ],
            rules: [{ kind: 'final', policy: 'First' }],
            outputs: { qx: { independentConfig: '' } },
        };

        const ambiguous = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const remoteLine = ambiguous.body
            .split('\n')
            .find((line) => line.startsWith('https://sub.example.com/'));
        expect(remoteLine).to.contain('update-interval=3600');
        expect(ambiguous.warnings).to.deep.include({
            path: 'remoteProxySources.nodes.targetOptions.qx.updateInterval',
            message:
                'Multiple Quantumult X groups use remote proxy source nodes with conflicting policyUpdateInterval values (3600, 7200); the smallest value 3600 was used because Quantumult X supports one update interval per remote source. Align the group intervals or set remoteProxySources.nodes.targetOptions.qx.updateInterval to override it.',
        });

        project.remoteProxySources[0].targetOptions = {
            qx: { updateInterval: 1800 },
        };
        const explicit = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(explicit.body).to.contain('update-interval=1800');
        expect(
            explicit.warnings.some(
                (warning) =>
                    warning.path ===
                    'remoteProxySources.nodes.targetOptions.qx.updateInterval',
            ),
        ).to.equal(false);
    });

    it('uses the shared rule name for Quantumult X resources while Surge ignores it', async function () {
        const project = {
            name: 'named-remote-rule',
            remoteProxySources: [],
            groups: [],
            rules: [
                {
                    kind: 'remote',
                    name: 'Advertising',
                    ruleSet: 'internal-rule-set-id',
                    policy: 'REJECT',
                },
            ],
            outputs: { surge: {}, qx: {} },
        };
        const ruleSets = [
            {
                name: 'internal-rule-set-id',
                source: {
                    kind: 'url',
                    url: 'https://rules.example.com/ads.list',
                },
            },
        ];

        const qx = await generateQXConfig({
            project,
            ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        const surge = await generateSurgeConfig({
            project,
            ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(qx.body).to.contain(
            'https://rules.example.com/ads.list, tag=Advertising, force-policy=reject',
        );
        expect(qx.body).to.not.contain('tag=internal-rule-set-id');
        expect(surge.body).to.contain(
            'RULE-SET, https://rules.example.com/ads.list, REJECT',
        );
        expect(surge.body).to.not.contain('Advertising');
    });

    it('allocates an internal Quantumult X resource tag when the rule name is omitted', async function () {
        const { input } = createUnnamedRemoteRuleFixture();
        const qx = await generateQXConfig(input);
        expect(qx.body).to.contain('tag=internal-rule-set-id');
    });

    it('allocates an internal Clash provider key when the rule name is omitted', async function () {
        const { input } = createUnnamedRemoteRuleFixture();
        const clash = YAML.safeLoad((await generateClashConfig(input)).body);

        expect(clash['rule-providers']).to.have.property(
            'internal-rule-set-id',
        );
        expect(clash.rules).to.include('RULE-SET,internal-rule-set-id,REJECT');
    });

    it('does not expose the internal rule-set id in unnamed Loon output', async function () {
        const { input } = createUnnamedRemoteRuleFixture();
        const loon = await generateLoonConfig(input);

        expect(loon.body).to.not.contain('internal-rule-set-id');
        expect(loon.body).to.contain(
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list, policy=REJECT, enabled=true',
        );
    });

    it('does not expose the internal rule-set id in unnamed Surge output', async function () {
        const { input } = createUnnamedRemoteRuleFixture();
        const surge = await generateSurgeConfig(input);

        expect(surge.body).to.not.contain('internal-rule-set-id');
        expect(surge.body).to.contain(
            'RULE-SET, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list, REJECT',
        );
    });

    it('does not mutate unnamed rules or rule sets while previewing every target', async function () {
        const { project, ruleSets, input } = createUnnamedRemoteRuleFixture();
        const original = JSON.parse(JSON.stringify({ project, ruleSets }));

        await generateSurgeConfig(input);
        await generateQXConfig(input);
        await generateClashConfig(input);
        await generateLoonConfig(input);

        expect({ project, ruleSets }).to.deep.equal(original);
        expect(project.rules[0]).to.not.have.property('name');
    });

    it('separates generated policy groups with blank lines for readable previews', async function () {
        const project = {
            name: 'readable-policy-groups',
            remoteProxySources: [],
            groups: [
                {
                    name: 'One',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
                {
                    name: 'Two',
                    type: 'select',
                    members: [{ kind: 'group', value: 'One' }],
                },
            ],
            rules: [],
            outputs: { surge: {}, qx: {} },
        };

        const qx = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const surge = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(qx.body).to.contain(
            '[policy]\nstatic=One, DIRECT\n\nstatic=Two, One',
        );
        expect(surge.body).to.contain(
            '[Proxy Group]\nOne = select, DIRECT\n\nTwo = select, One',
        );
    });

    it('maps shared policy groups to Quantumult X while preserving members, references, and order', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-policy-mapping',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Manual',
                        type: 'select',
                        members: [
                            { kind: 'proxy', value: 'Node A' },
                            { kind: 'builtin', value: 'DIRECT' },
                        ],
                    },
                    {
                        name: 'Available',
                        type: 'fallback',
                        members: [
                            { kind: 'group', value: 'Manual' },
                            { kind: 'proxy', value: 'Node B' },
                        ],
                    },
                    {
                        name: 'Fast',
                        type: 'url-test',
                        members: [
                            { kind: 'group', value: 'Available' },
                            { kind: 'builtin', value: 'DIRECT' },
                        ],
                        interval: 600,
                        tolerance: 50,
                    },
                ],
                rules: [{ kind: 'final', policy: 'Fast' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        const policySection = result.body.slice(
            result.body.indexOf('[policy]'),
            result.body.indexOf('[filter_local]'),
        );
        expect(policySection).to.equal(
            '[policy]\n' +
                'static=Manual, Node A, DIRECT\n\n' +
                'available=Available, Manual, Node B\n\n' +
                'url-latency-benchmark=Fast, Available, DIRECT, check-interval=600, tolerance=50\n',
        );
        expect(result.warnings).to.deep.equal([]);

        const imported = importQXConfig(
            `${policySection}[filter_local]\nfinal, Fast\n`,
        );
        expect(
            imported.project.groups.map(({ name, type, members }) => ({
                name,
                type,
                members,
            })),
        ).to.deep.equal([
            {
                name: 'Manual',
                type: 'select',
                members: [
                    { kind: 'proxy', value: 'Node A' },
                    { kind: 'builtin', value: 'DIRECT' },
                ],
            },
            {
                name: 'Available',
                type: 'fallback',
                members: [
                    { kind: 'group', value: 'Manual' },
                    { kind: 'proxy', value: 'Node B' },
                ],
            },
            {
                name: 'Fast',
                type: 'url-test',
                members: [
                    { kind: 'group', value: 'Available' },
                    { kind: 'builtin', value: 'DIRECT' },
                ],
            },
        ]);
        const roundTrip = await generateQXConfig({
            project: { ...imported.project, name: 'qx-policy-round-trip' },
            ruleSets: imported.ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        expect(roundTrip.body).to.contain(
            '[policy]\n' +
                'static=Manual, Node A, DIRECT\n\n' +
                'available=Available, Manual, Node B\n\n' +
                'url-latency-benchmark=Fast, Available, DIRECT, check-interval=600, tolerance=50',
        );
    });

    it('merges Quantumult X policy groups by name while retaining independent entries and comments', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-independent-groups',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Main',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                    },
                    {
                        name: 'Generated',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'REJECT' }],
                    },
                ],
                rules: [],
                outputs: {
                    qx: {
                        independentConfig:
                            '[general]\n\n[policy]\n# legacy group\nstatic=Legacy, DIRECT\n\n# keep this comment\nstatic=Main, OLD\n\nstatic=Tail, REJECT\n\n[dns]\n\n[mitm]\n',
                    },
                },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const policy = parseProfileSections(result.body).sections.find(
            (section) => section.name === 'policy',
        ).body;
        expect(policy).to.include('# legacy group');
        expect(policy).to.include('# keep this comment');
        expect(policy).to.include('static=Legacy, DIRECT');
        expect(policy).to.include('static=Tail, REJECT');
        expect(policy).to.include('static=Main, DIRECT');
        expect(policy).to.include('static=Generated, REJECT');
        expect(
            policy.filter((line) => /^\s*\w+=Main,/.test(line)),
        ).to.have.length(1);
        expect(policy).to.not.include('static=Main, OLD');
        expect(policy.indexOf('static=Legacy, DIRECT')).to.be.lessThan(
            policy.indexOf('static=Main, DIRECT'),
        );
        expect(policy.indexOf('static=Main, DIRECT')).to.be.lessThan(
            policy.indexOf('static=Tail, REJECT'),
        );
        expect(policy.indexOf('static=Tail, REJECT')).to.be.lessThan(
            policy.indexOf('static=Generated, REJECT'),
        );
    });

    it('preserves an independent Quantumult X policy section when no groups are generated', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-independent-only',
                remoteProxySources: [],
                groups: [],
                rules: [],
                outputs: {
                    qx: {
                        independentConfig:
                            '[general]\n\n[policy]\n# manually authored\nstatic=Legacy, DIRECT\n\n[dns]\n\n[mitm]\n',
                    },
                },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(result.body).to.contain(
            '[policy]\n# manually authored\nstatic=Legacy, DIRECT',
        );
    });

    it('approximates includeOtherGroups as deduplicated nested Quantumult X policy members', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-included-groups',
                remoteProxySources: [
                    {
                        name: 'nodes',
                        source: {
                            kind: 'sub-store',
                            type: 'collection',
                            name: 'all',
                            publicBaseUrl: 'https://sub.example.com',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Child',
                        type: 'select',
                        members: [{ kind: 'proxy', value: 'Node A' }],
                    },
                    {
                        name: 'Main',
                        type: 'select',
                        members: [
                            { kind: 'group', value: 'Child' },
                            { kind: 'builtin', value: 'DIRECT' },
                        ],
                        includeOtherGroups: ['Child'],
                        remoteProxySource: 'nodes',
                    },
                ],
                rules: [{ kind: 'final', policy: 'Main' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'static=Main, Child, DIRECT, resource-tag-regex=^nodes$',
        );
        expect(result.body).to.not.contain('static=Main, Child, DIRECT, Child');
        expect(result.body).to.contain(
            'https://sub.example.com/download/collection/all/QX, tag=nodes',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Main.includeOtherGroups',
            message:
                'Quantumult X cannot flatten nodes from included policy groups; referenced group names were appended as nested policy members instead.',
        });
    });

    it('omits includeOtherGroups from QX automatic groups and rejects an empty projection', async function () {
        const project = {
            name: 'qx-automatic-included-groups',
            remoteProxySources: [],
            groups: [
                {
                    name: 'Child',
                    type: 'select',
                    members: [{ kind: 'proxy', value: 'Node A' }],
                    disabled: true,
                },
                {
                    name: 'Auto',
                    type: 'url-test',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    includeOtherGroups: ['Child'],
                },
            ],
            rules: [{ kind: 'final', policy: 'Auto' }],
            outputs: { qx: { independentConfig: '' } },
        };
        const result = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain('url-latency-benchmark=Auto, DIRECT');
        expect(result.body).to.not.contain(
            'url-latency-benchmark=Auto, DIRECT, Child',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Auto.includeOtherGroups',
            message:
                'Quantumult X url-latency-benchmark cannot safely approximate flattened nodes from another policy group; includeOtherGroups was omitted.',
        });

        project.groups[1].members = [];
        let caught;
        try {
            await generateQXConfig({
                project,
                ruleSets: [],
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            caught = error;
        }
        expect(caught).to.be.instanceOf(ConfigGeneratorValidationError);
        expect(caught.issues).to.deep.include({
            path: 'groups.Auto.members',
            message:
                'Quantumult X url-latency-benchmark has no usable policy members after target projection',
        });
    });

    it('rejects cycles spanning explicit and included policy-group references', function () {
        expect(() =>
            validateProject(
                {
                    name: 'mixed-group-cycle',
                    remoteProxySources: [],
                    groups: [
                        {
                            name: 'One',
                            type: 'select',
                            members: [{ kind: 'group', value: 'Two' }],
                        },
                        {
                            name: 'Two',
                            type: 'select',
                            members: [],
                            includeOtherGroups: ['One'],
                        },
                    ],
                    rules: [],
                    outputs: { qx: {} },
                },
                [],
            ),
        ).to.throw(ConfigGeneratorValidationError);
    });

    it('round-trips Quantumult X native policy groups, alive-checking, and shared icons', async function () {
        const draft = importQXConfig(
            '[policy]\n' +
                'round-robin=Round, Node A, Node B, img-url=https://example.com/round.png\n' +
                'dest-hash=Hash, Round, Node C\n' +
                'ssid=Network, DIRECT, LINK_22E171:Round\n' +
                'url-latency-benchmark=Fast, Hash, DIRECT, check-interval=600, tolerance=50, alive-checking=true\n' +
                '[filter_local]\nfinal, Fast\n',
        );

        expect(
            draft.project.groups.map(
                ({ name, type, members, iconUrl, targetOptions }) => ({
                    name,
                    type,
                    members,
                    iconUrl,
                    targetOptions,
                }),
            ),
        ).to.deep.equal([
            {
                name: 'Round',
                type: 'round-robin',
                members: [
                    { kind: 'proxy', value: 'Node A' },
                    { kind: 'proxy', value: 'Node B' },
                ],
                iconUrl: 'https://example.com/round.png',
                targetOptions: undefined,
            },
            {
                name: 'Hash',
                type: 'dest-hash',
                members: [
                    { kind: 'group', value: 'Round' },
                    { kind: 'proxy', value: 'Node C' },
                ],
                iconUrl: undefined,
                targetOptions: undefined,
            },
            {
                name: 'Network',
                type: 'ssid',
                members: [
                    { kind: 'builtin', value: 'DIRECT' },
                    {
                        kind: 'conditional',
                        value: 'LINK_22E171:Round',
                        policy: 'Round',
                    },
                ],
                iconUrl: undefined,
                targetOptions: undefined,
            },
            {
                name: 'Fast',
                type: 'url-test',
                members: [
                    { kind: 'group', value: 'Hash' },
                    { kind: 'builtin', value: 'DIRECT' },
                ],
                iconUrl: undefined,
                targetOptions: { qx: { aliveChecking: true } },
            },
        ]);

        const generated = await generateQXConfig({
            project: { ...draft.project, name: 'qx-native-round-trip' },
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        expect(generated.body).to.contain(
            '[policy]\n' +
                'round-robin=Round, Node A, Node B, img-url=https://example.com/round.png\n\n' +
                'dest-hash=Hash, Round, Node C\n\n' +
                'ssid=Network, DIRECT, LINK_22E171:Round\n\n' +
                'url-latency-benchmark=Fast, Hash, DIRECT, check-interval=600, tolerance=50, alive-checking=true',
        );
        expect(generated.warnings).to.deep.equal([]);
    });

    it('round-trips Quantumult X tolerance zero and disabled remote auto sync', async function () {
        const draft = importQXConfig(
            '[server_remote]\n' +
                'https://example.com/sample.conf, tag=Sample-01, update-interval=-1\n' +
                '[policy]\n' +
                'url-latency-benchmark=Benchmark, resource-tag-regex=^Sample-01$, check-interval=600, alive-checking=false, tolerance=0\n' +
                '[filter_local]\n' +
                'final, Benchmark\n',
        );
        draft.project.name = 'qx-native-numeric-boundaries';

        expect(
            draft.project.remoteProxySources[0].targetOptions.qx.updateInterval,
        ).to.equal(-1);
        expect(draft.project.groups[0].tolerance).to.equal(0);

        const generated = await generateQXConfig({
            project: draft.project,
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(generated.body).to.contain(
            'https://example.com/sample.conf, tag=Sample-01, update-interval=-1',
        );
        expect(generated.body).to.contain(
            'url-latency-benchmark=Benchmark, resource-tag-regex=^Sample-01$, check-interval=600, tolerance=0, alive-checking=false',
        );
    });

    it('validates policy groups referenced by QX ssid conditions', async function () {
        const draft = importQXConfig(
            '[policy]\n' +
                'static=Round, DIRECT\n' +
                'ssid=Network, DIRECT, LINK_22E171:Round\n' +
                '[filter_local]\n' +
                'final, Network\n',
        );
        draft.project.name = 'qx-ssid-policy-reference';
        draft.project.groups.find(
            (group) => group.name === 'Round',
        ).disabled = true;

        let validationError;
        try {
            await generateQXConfig({
                project: draft.project,
                ruleSets: draft.ruleSets,
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            validationError = error;
        }

        expect(validationError).to.be.instanceOf(
            ConfigGeneratorValidationError,
        );
        expect(validationError.issues).to.deep.include({
            path: 'groups[1].members[1].policy',
            message:
                'references policy group Round, which is disabled for Quantumult X',
        });

        const mismatched = importQXConfig(
            '[policy]\n' +
                'static=Round, DIRECT\n' +
                'static=Other, DIRECT\n' +
                'ssid=Network, DIRECT, LINK_22E171:Round\n' +
                '[filter_local]\n' +
                'final, Network\n',
        );
        mismatched.project.name = 'qx-ssid-mismatched-reference';
        mismatched.project.groups[2].members[1].policy = 'Other';

        expect(() => validateProject(mismatched.project, [], 'qx')).to.throw(
            ConfigGeneratorValidationError,
        );
        try {
            validateProject(mismatched.project, [], 'qx');
        } catch (error) {
            expect(error.issues).to.deep.include({
                path: 'groups[2].members[1].value',
                message: 'must end with the referenced policy',
            });
        }
    });

    it('preserves unbound QX resource tag regex and rejects ambiguous source bindings', async function () {
        const draft = importQXConfig(
            '[policy]\nstatic=Proxy, DIRECT, resource-tag-regex=^HK|TW$\n[filter_local]\nfinal, Proxy\n',
        );
        expect(draft.project.groups[0].targetOptions).to.deep.equal({
            qx: { resourceTagRegex: '^HK|TW$' },
        });

        const generated = await generateQXConfig({
            project: { ...draft.project, name: 'raw-resource-regex' },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(generated.body).to.contain(
            'static=Proxy, DIRECT, resource-tag-regex=^HK|TW$',
        );

        const ambiguous = {
            ...draft.project,
            name: 'ambiguous-resource-source',
            remoteProxySources: [
                {
                    name: 'nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/qx-nodes.conf',
                        target: 'qx',
                    },
                },
            ],
            groups: [
                {
                    ...draft.project.groups[0],
                    remoteProxySource: 'nodes',
                },
            ],
        };
        expect(() => validateProject(ambiguous, [], 'qx')).to.throw(
            ConfigGeneratorValidationError,
        );
    });

    it('keeps QX remote sources required by an unbound resource tag regex', async function () {
        const draft = importQXConfig(
            '[server_remote]\n' +
                'https://example.com/hk.conf, tag=HK\n' +
                'https://example.com/tw.conf, tag=TW\n' +
                '[policy]\n' +
                'static=Proxy, resource-tag-regex=^(HK|TW)$\n' +
                '[filter_local]\n' +
                'final, Proxy\n',
        );

        expect(draft.project.groups[0].targetOptions).to.deep.equal({
            qx: { resourceTagRegex: '^(HK|TW)$' },
        });

        const generated = await generateQXConfig({
            project: { ...draft.project, name: 'raw-regex-remote-sources' },
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(generated.body).to.contain(
            'https://example.com/hk.conf, tag=HK',
        );
        expect(generated.body).to.contain(
            'https://example.com/tw.conf, tag=TW',
        );
        expect(generated.body).to.contain(
            'static=Proxy, resource-tag-regex=^(HK|TW)$',
        );
    });

    it('maps include-all proxies through QX server tag regex without producing an empty group', async function () {
        const project = {
            name: 'qx-include-all',
            embeddedSource: { type: 'subscription', name: 'nodes' },
            remoteProxySources: [],
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [],
                    includeAllProxies: true,
                },
            ],
            rules: [{ kind: 'final', policy: 'Main' }],
            outputs: { surge: {}, qx: {} },
        };

        const generated = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () =>
                'shadowsocks=example.com:443, method=aes-128-gcm, password=test, tag=Node A',
        });

        expect(generated.body).to.contain('static=Main, server-tag-regex=.*');
        expect(generated.warnings).to.deep.equal([]);

        const imported = importQXConfig(
            '[policy]\n' +
                'static=Main, server-tag-regex=HK|TW\n' +
                '[filter_local]\n' +
                'final, Main\n',
        );
        expect(imported.project.groups[0]).to.deep.include({
            includeAllProxies: true,
            nodeNameRegex: 'HK|TW',
        });

        const surge = await generateSurgeConfig({
            project: { ...imported.project, name: 'qx-include-all-round-trip' },
            ruleSets: imported.ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        expect(surge.body).to.contain(
            'Main = select, include-all-proxies=1, policy-regex-filter=HK|TW',
        );
    });

    it('rebinds escaped exact QX resource tags to a neutral Sub-Store source', async function () {
        const draft = importQXConfig(
            '[server_remote]\n' +
                'https://sub.example.com/download/collection/all/QX, tag=HK.Nodes\n' +
                '[policy]\n' +
                'static=Proxy, resource-tag-regex=^HK\\.Nodes$\n' +
                '[filter_local]\n' +
                'final, Proxy\n',
            {
                remoteProxySources: [
                    {
                        name: 'native',
                        source: {
                            kind: 'sub-store',
                            type: 'collection',
                            name: 'all',
                            publicBaseUrl: 'https://sub.example.com',
                        },
                    },
                ],
            },
        );

        expect(draft.project.groups[0].remoteProxySource).to.equal('HK.Nodes');
        expect(draft.project.groups[0].targetOptions).to.equal(undefined);

        const surge = await generateSurgeConfig({
            project: { ...draft.project, name: 'escaped-resource-tag' },
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        expect(surge.body).to.contain(
            'policy-path=https://sub.example.com/download/collection/all/Surge',
        );
    });

    it('rejects a required raw QX resource regex group when Surge has no candidates', async function () {
        const draft = importQXConfig(
            '[server_remote]\n' +
                'https://example.com/hk.conf, tag=HK\n' +
                'https://example.com/tw.conf, tag=TW\n' +
                '[policy]\n' +
                'static=Proxy, DIRECT, resource-tag-regex=^(HK|TW)$\n' +
                '[filter_local]\n' +
                'final, Proxy\n',
        );
        draft.project.name = 'qx-regex-without-surge-candidates';

        let validationError;
        try {
            await generateSurgeConfig({
                project: draft.project,
                ruleSets: draft.ruleSets,
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            validationError = error;
        }

        expect(validationError).to.be.instanceOf(
            ConfigGeneratorValidationError,
        );
        expect(validationError.issues).to.deep.include({
            path: 'groups[0].targetOptions.qx.resourceTagRegex',
            message:
                'uses a Quantumult X resource-tag-regex that cannot be represented by Surge; bind a Surge-compatible remote proxy source or remove the raw expression',
        });
    });

    it('warns when an unused raw QX resource regex is omitted from Surge', async function () {
        const draft = importQXConfig(
            '[policy]\n' +
                'static=Proxy, DIRECT, resource-tag-regex=^(HK|TW)$\n' +
                '[filter_local]\n' +
                'final, direct\n',
        );
        draft.project.name = 'unused-qx-resource-regex';

        const surge = await generateSurgeConfig({
            project: draft.project,
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(surge.warnings).to.deep.include({
            path: 'groups.Proxy.targetOptions.qx.resourceTagRegex',
            message:
                'Surge cannot represent the raw Quantumult X resource-tag-regex; it was omitted.',
        });
    });

    it('reuses only target-neutral Sub-Store sources across Surge and QX bindings', async function () {
        const baseProject = {
            name: 'target-aware-proxy-sources',
            remoteProxySources: [
                {
                    name: 'native',
                    source: {
                        kind: 'sub-store',
                        type: 'collection',
                        name: 'all',
                        publicBaseUrl: 'https://sub.example.com',
                    },
                },
                {
                    name: 'surge-url',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/proxies.conf',
                        target: 'qx',
                    },
                },
                {
                    name: 'qx-url-in-surge-field',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/qx-cross-field.conf',
                        target: 'qx',
                    },
                },
            ],
            groups: [
                {
                    name: 'Native',
                    type: 'select',
                    members: [],
                    targetOptions: {
                        surge: { remoteProxySource: 'native' },
                    },
                },
                {
                    name: 'SurgeOnly',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        surge: { remoteProxySource: 'surge-url' },
                    },
                },
                {
                    name: 'CrossFieldQXOwned',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        surge: {
                            remoteProxySource: 'qx-url-in-surge-field',
                        },
                    },
                },
            ],
            rules: [{ kind: 'final', policy: 'Native' }],
            outputs: { qx: { independentConfig: '' } },
        };
        const result = await generateQXConfig({
            project: baseProject,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'https://sub.example.com/download/collection/all/QX, tag=native',
        );
        expect(result.body).to.contain(
            'static=Native, resource-tag-regex=^native$',
        );
        expect(result.body).to.not.contain('https://example.com/proxies.conf');
        expect(result.body).to.not.contain(
            'https://example.com/qx-cross-field.conf',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.SurgeOnly.targetOptions.surge.remoteProxySource',
            message:
                'This URL remote proxy source is only bound to Surge and was omitted from Quantumult X.',
        });
        expect(result.warnings).to.deep.include({
            path: 'groups.CrossFieldQXOwned.targetOptions.surge.remoteProxySource',
            message:
                'This URL remote proxy source is only bound to Surge and was omitted from Quantumult X.',
        });
    });

    it('omits a target-less URL shared by both legacy target bindings while retaining static members', async function () {
        const project = {
            name: 'ambiguous-dual-target-legacy-url',
            remoteProxySources: [
                {
                    name: 'legacy-nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/shared-legacy.conf',
                    },
                },
            ],
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        surge: { remoteProxySource: 'legacy-nodes' },
                        qx: { remoteProxySource: 'legacy-nodes' },
                    },
                },
            ],
            rules: [{ kind: 'final', policy: 'Main' }],
            outputs: { surge: {}, qx: { independentConfig: '' } },
        };

        for (const generate of [generateSurgeConfig, generateQXConfig]) {
            const result = await generate({
                project,
                ruleSets: [],
                produceBuiltinArtifact: async () => '',
            });
            expect(result.body).to.contain('DIRECT');
            expect(result.body).to.not.contain(
                'https://example.com/shared-legacy.conf',
            );
            expect(
                result.warnings.some((warning) =>
                    warning.message.includes(
                        'bound by both legacy Surge and Quantumult X fields',
                    ),
                ),
            ).to.equal(true);
        }

        const neutralProject = {
            ...project,
            name: 'neutral-dual-target-legacy-source',
            remoteProxySources: [
                {
                    name: 'legacy-nodes',
                    source: {
                        kind: 'sub-store',
                        type: 'collection',
                        name: 'all',
                        publicBaseUrl: 'https://sub.example.com',
                    },
                },
            ],
        };
        const surge = await generateSurgeConfig({
            project: neutralProject,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const qx = await generateQXConfig({
            project: neutralProject,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(surge.body).to.contain(
            'policy-path=https://sub.example.com/download/collection/all/Surge',
        );
        expect(qx.body).to.contain(
            'https://sub.example.com/download/collection/all/QX, tag=legacy-nodes',
        );
    });

    it('applies target-less legacy URL ownership across policy groups', async function () {
        const project = {
            name: 'cross-group-legacy-url-ownership',
            remoteProxySources: [
                {
                    name: 'legacy-nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/shared-legacy.conf',
                    },
                },
            ],
            groups: [
                {
                    name: 'SurgeGroup',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        surge: { remoteProxySource: 'legacy-nodes' },
                    },
                },
                {
                    name: 'QxGroup',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        qx: { remoteProxySource: 'legacy-nodes' },
                    },
                },
            ],
            rules: [],
            outputs: { surge: {}, qx: { independentConfig: '' } },
        };

        const surge = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const qx = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(surge.body).to.not.contain(
            'https://example.com/shared-legacy.conf',
        );
        expect(qx.body).to.not.contain(
            'https://example.com/shared-legacy.conf',
        );
        [surge, qx].forEach((result) => {
            expect(
                result.warnings.some((warning) =>
                    warning.message.includes(
                        'bound by both legacy Surge and Quantumult X fields',
                    ),
                ),
            ).to.equal(true);
        });

        for (const [generate, policy] of [
            [generateSurgeConfig, 'SurgeGroup'],
            [generateQXConfig, 'QxGroup'],
        ]) {
            const result = await generate({
                project: {
                    ...project,
                    rules: [{ kind: 'final', policy }],
                },
                ruleSets: [],
                produceBuiltinArtifact: async () => '',
            });
            expect(
                result.warnings.some((warning) =>
                    warning.message.includes(
                        'bound by both legacy Surge and Quantumult X fields',
                    ),
                ),
            ).to.equal(true);
            expect(result.body).to.contain('DIRECT');
        }
    });

    it('keeps single-target legacy URL inference for existing projects', async function () {
        const legacyProject = (target) => ({
            name: `${target}-legacy-url`,
            remoteProxySources: [
                {
                    name: 'legacy-nodes',
                    source: {
                        kind: 'url',
                        url: `https://example.com/${target}-legacy.conf`,
                    },
                },
            ],
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    targetOptions: {
                        [target]: { remoteProxySource: 'legacy-nodes' },
                    },
                },
            ],
            rules: [{ kind: 'final', policy: 'Main' }],
            outputs: { surge: {}, qx: { independentConfig: '' } },
        });

        const surge = await generateSurgeConfig({
            project: legacyProject('surge'),
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const qx = await generateQXConfig({
            project: legacyProject('qx'),
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(surge.body).to.contain(
            'policy-path=https://example.com/surge-legacy.conf',
        );
        expect(qx.body).to.contain(
            'https://example.com/qx-legacy.conf, tag=legacy-nodes',
        );
    });

    it('uses exact shared sources and explicit QX parser fallbacks without leaking QX URLs into Surge', async function () {
        const project = {
            name: 'shared-source-binding',
            remoteProxySources: [
                {
                    name: 'native',
                    source: {
                        kind: 'sub-store',
                        type: 'collection',
                        name: 'all',
                        publicBaseUrl: 'https://sub.example.com',
                    },
                },
                {
                    name: 'surge-nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/surge-nodes.conf',
                        target: 'surge',
                    },
                },
                {
                    name: 'qx-nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/qx-nodes.conf',
                        target: 'qx',
                    },
                },
            ],
            groups: [
                {
                    name: 'Native',
                    type: 'select',
                    members: [],
                    remoteProxySource: 'native',
                },
                {
                    name: 'SurgeNodes',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    remoteProxySource: 'surge-nodes',
                },
                {
                    name: 'QXNodes',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                    remoteProxySource: 'qx-nodes',
                },
            ],
            rules: [{ kind: 'final', policy: 'Native' }],
            outputs: { surge: {}, qx: { independentConfig: '' } },
        };

        const surge = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const qx = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(surge.body).to.contain(
            'Native = select, policy-path=https://sub.example.com/download/collection/all/Surge',
        );
        expect(surge.body).to.contain(
            'SurgeNodes = select, DIRECT, policy-path=https://example.com/surge-nodes.conf',
        );
        expect(surge.body).to.not.contain('https://example.com/qx-nodes.conf');
        expect(qx.body).to.contain(
            'https://sub.example.com/download/collection/all/QX, tag=native',
        );
        expect(qx.body).to.contain(
            'https://example.com/qx-nodes.conf, tag=qx-nodes',
        );
        expect(qx.body).to.contain(
            'https://example.com/surge-nodes.conf, tag=surge-nodes, opt-parser=true',
        );
        expect(
            surge.warnings.some(
                (warning) =>
                    warning.path === 'groups.QXNodes.remoteProxySource',
            ),
        ).to.equal(true);
        expect(qx.warnings).to.deep.include({
            path: 'groups.SurgeNodes.remoteProxySource',
            message:
                'The Surge-owned HTTP(S) proxy source was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('routes automatic URL proxy sources through Sub-Store for every target', async function () {
        const project = {
            name: 'automatic-source',
            remoteProxySources: [
                {
                    name: 'Shared Nodes',
                    source: {
                        kind: 'url',
                        url: 'https://origin.example.com/subscription',
                        mode: 'auto',
                        publicBaseUrl: 'https://sub.example.com/base/',
                    },
                },
            ],
            groups: [
                {
                    name: 'Proxy',
                    type: 'select',
                    members: [],
                    remoteProxySource: 'Shared Nodes',
                },
            ],
            rules: [{ kind: 'final', policy: 'Proxy' }],
            outputs: { surge: {}, qx: {}, clash: {} },
        };

        const surge = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const qx = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const clash = await generateClashConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => [],
        });

        const baseUrl =
            'https://sub.example.com/base/download/config-project/automatic-source/proxy-source/Shared%20Nodes';
        expect(surge.body).to.contain(`policy-path=${baseUrl}/Surge`);
        expect(qx.body).to.contain(`${baseUrl}/QX, tag=Shared Nodes`);
        expect(
            Object.values(YAML.safeLoad(clash.body)['proxy-providers'])[0].url,
        ).to.equal(`${baseUrl}/Clash`);
        [surge.body, qx.body, clash.body].forEach((body) => {
            expect(body).to.not.contain(
                'https://origin.example.com/subscription',
            );
        });
    });

    it('imports target-owned proxy URLs into the shared group binding', function () {
        const surge = importSurgeConfig(
            '[Proxy Group]\nRemote = select, policy-path=https://example.com/surge.conf\n[Rule]\nFINAL, Remote\n',
        );
        expect(surge.project.groups[0].remoteProxySource).to.equal('remote-1');
        expect(surge.project.remoteProxySources[0].source).to.deep.equal({
            kind: 'url',
            url: 'https://example.com/surge.conf',
            mode: 'passthrough',
            target: 'surge',
        });

        const qx = importQXConfig(
            '[server_remote]\n' +
                'https://example.com/qx.conf, tag=Remote\n' +
                '[policy]\n' +
                'static=Proxy, DIRECT, resource-tag-regex=^Remote$\n' +
                '[filter_local]\n' +
                'final, Proxy\n',
        );
        expect(qx.project.groups[0].remoteProxySource).to.equal('Remote');
        expect(qx.project.remoteProxySources[0].source).to.deep.equal({
            kind: 'url',
            url: 'https://example.com/qx.conf',
            mode: 'passthrough',
            target: 'qx',
        });

        const native = importSurgeConfig(
            '[Proxy Group]\nRemote = select, policy-path=https://sub.example.com/download/collection/all/Surge\n[Rule]\nFINAL, Remote\n',
            {
                remoteProxySources: [
                    {
                        name: 'all',
                        source: {
                            kind: 'sub-store',
                            type: 'collection',
                            name: 'all',
                            publicBaseUrl: 'https://sub.example.com',
                        },
                    },
                ],
            },
        );
        expect(native.project.remoteProxySources[0].source).to.deep.equal({
            kind: 'sub-store',
            type: 'collection',
            name: 'all',
            publicBaseUrl: 'https://sub.example.com',
        });
    });

    it('materializes Surge smart groups and Surge-owned proxy URLs through explicit QX fallbacks', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-smart-fallback',
                remoteProxySources: [
                    {
                        name: 'speedtest-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/surge-nodes.conf',
                            target: 'surge',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Auto',
                        type: 'smart',
                        members: [],
                        remoteProxySource: 'speedtest-nodes',
                        interval: 600,
                        tolerance: 50,
                    },
                    {
                        name: 'Streaming',
                        type: 'select',
                        members: [{ kind: 'group', value: 'Auto' }],
                    },
                    {
                        name: 'Speedtest',
                        type: 'select',
                        members: [{ kind: 'group', value: 'Auto' }],
                    },
                ],
                rules: [
                    {
                        kind: 'inline',
                        type: 'DOMAIN',
                        value: 'example.com',
                        policy: 'Streaming',
                    },
                    { kind: 'final', policy: 'Speedtest' },
                ],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'url-latency-benchmark=Auto, resource-tag-regex=^speedtest-nodes$, check-interval=600, tolerance=50',
        );
        expect(result.body).to.contain('static=Streaming, Auto');
        expect(result.body).to.contain('static=Speedtest, Auto');
        expect(result.body).to.contain(
            'https://example.com/surge-nodes.conf, tag=speedtest-nodes, opt-parser=true',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Auto.type',
            message:
                'Surge smart was approximated as Quantumult X url-latency-benchmark. Adaptive retry, per-site tuning, historical quality scoring, and policy-priority weights are not available.',
        });
        expect(result.warnings).to.deep.include({
            path: 'groups.Auto.remoteProxySource',
            message:
                'The Surge-owned HTTP(S) proxy source was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('does not pass a Clash-owned proxy URL to Quantumult X opt-parser', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-rejects-clash-owned-proxy-source',
                remoteProxySources: [
                    {
                        name: 'clash-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/clash-provider.yaml',
                            target: 'clash',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'clash-nodes',
                    },
                ],
                rules: [{ kind: 'final', policy: 'Proxy' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain('static=Proxy, DIRECT');
        expect(result.body).to.not.contain(
            'https://example.com/clash-provider.yaml',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Proxy.remoteProxySource',
            message:
                'This URL remote proxy source is only bound to Clash and was omitted from Quantumult X.',
        });
    });

    it('does not treat a legacy Clash binding as an unclassified Quantumult X source', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-rejects-legacy-clash-binding',
                remoteProxySources: [
                    {
                        name: 'legacy-clash-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/clash-provider.yaml',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        targetOptions: {
                            clash: {
                                remoteProxySource: 'legacy-clash-nodes',
                            },
                        },
                    },
                ],
                rules: [{ kind: 'final', policy: 'Proxy' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain('static=Proxy, DIRECT');
        expect(result.body).to.not.contain(
            'https://example.com/clash-provider.yaml',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Proxy.targetOptions.clash.remoteProxySource',
            message:
                'This URL remote proxy source is only bound to Clash and was omitted from Quantumult X.',
        });
    });

    it('infers Clash ownership before applying a shared Quantumult X source fallback', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-infers-legacy-clash-source-ownership',
                remoteProxySources: [
                    {
                        name: 'legacy-clash-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/clash-provider.yaml',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'legacy-clash-nodes',
                        targetOptions: {
                            clash: {
                                remoteProxySource: 'legacy-clash-nodes',
                            },
                        },
                    },
                ],
                rules: [{ kind: 'final', policy: 'Proxy' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain('static=Proxy, DIRECT');
        expect(result.body).to.not.contain(
            'https://example.com/clash-provider.yaml',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Proxy.remoteProxySource',
            message:
                'This URL remote proxy source is only bound to Clash and was omitted from Quantumult X.',
        });
    });

    it('keeps a truly unclassified shared URL as an explicit Quantumult X parser fallback', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-unclassified-source-fallback',
                remoteProxySources: [
                    {
                        name: 'legacy-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/legacy-nodes.conf',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'legacy-nodes',
                    },
                ],
                rules: [{ kind: 'final', policy: 'Proxy' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'https://example.com/legacy-nodes.conf, tag=legacy-nodes, opt-parser=true',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Proxy.remoteProxySource',
            message:
                'The unclassified HTTP(S) proxy source was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('keeps unique legacy Surge ownership when the shared binding is generated for Quantumult X', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-shared-legacy-surge-fallback',
                remoteProxySources: [
                    {
                        name: 'legacy-surge-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/surge-nodes.conf',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'legacy-surge-nodes',
                        targetOptions: {
                            surge: {
                                remoteProxySource: 'legacy-surge-nodes',
                            },
                        },
                    },
                ],
                rules: [{ kind: 'final', policy: 'Proxy' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'https://example.com/surge-nodes.conf, tag=legacy-surge-nodes, opt-parser=true',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Proxy.remoteProxySource',
            message:
                'The Surge-owned HTTP(S) proxy source was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('omits ambiguous legacy ownership reached through a shared source binding when static members remain', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-shared-ambiguous-legacy-source',
                remoteProxySources: [
                    {
                        name: 'legacy-nodes',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/shared-legacy.conf',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'legacy-nodes',
                        targetOptions: {
                            surge: { remoteProxySource: 'legacy-nodes' },
                            qx: { remoteProxySource: 'legacy-nodes' },
                        },
                    },
                ],
                rules: [{ kind: 'final', policy: 'Proxy' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain('static=Proxy, DIRECT');
        expect(result.body).to.not.contain(
            'https://example.com/shared-legacy.conf',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Proxy.remoteProxySource',
            message:
                'This target-less URL remote proxy source is bound by both legacy Surge and Quantumult X fields; select explicit target ownership before generating.',
        });
    });

    it('uses documented approximate policy fallbacks without changing exact mappings', async function () {
        const qx = await generateQXConfig({
            project: {
                name: 'qx-load-balance-fallback',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Balanced',
                        type: 'load-balance',
                        members: [
                            { kind: 'proxy', value: 'Node A' },
                            { kind: 'proxy', value: 'Node B' },
                        ],
                    },
                ],
                rules: [{ kind: 'final', policy: 'Balanced' }],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(qx.body).to.contain('round-robin=Balanced, Node A, Node B');
        expect(qx.warnings).to.deep.include({
            path: 'groups.Balanced.type',
            message:
                'Surge load-balance was approximated as Quantumult X round-robin. Random distribution and availability behavior may differ.',
        });

        const surge = await generateSurgeConfig({
            project: {
                name: 'surge-qx-policy-fallbacks',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Rotate',
                        type: 'round-robin',
                        members: [{ kind: 'proxy', value: 'Node A' }],
                    },
                    {
                        name: 'Sticky',
                        type: 'dest-hash',
                        members: [{ kind: 'proxy', value: 'Node B' }],
                    },
                    {
                        name: 'Main',
                        type: 'select',
                        members: [
                            { kind: 'group', value: 'Rotate' },
                            { kind: 'group', value: 'Sticky' },
                        ],
                    },
                ],
                rules: [{ kind: 'final', policy: 'Main' }],
                outputs: { surge: {} },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(surge.body).to.contain(
            'Rotate = load-balance, Node A, persistent=0',
        );
        expect(surge.body).to.contain(
            'Sticky = load-balance, Node B, persistent=1',
        );
        expect(surge.warnings).to.deep.include({
            path: 'groups.Rotate.type',
            message:
                'Quantumult X round-robin was approximated as Surge load-balance. Surge selects an available policy randomly rather than in strict rotation.',
        });
        expect(surge.warnings).to.deep.include({
            path: 'groups.Sticky.type',
            message:
                'Quantumult X dest-hash was approximated as Surge load-balance with persistent=1. Destination affinity is similar but hashing behavior may differ.',
        });
    });

    it('projects included policy groups from resolved target capabilities', function () {
        const cases = [
            ['surge', 'select', 'native', 'select', true],
            ['qx', 'select', 'nested-group', 'select', true],
            ['clash', 'select', 'nested-group', 'select', true],
            ['qx', 'smart', 'omit', 'url-test', false],
            ['clash', 'smart', 'nested-group', 'url-test', false],
            ['loon', 'smart', 'nested-group', 'url-test', false],
            ['surge', 'round-robin', 'native', 'load-balance', false],
            ['clash', 'round-robin', 'nested-group', 'load-balance', false],
            ['loon', 'round-robin', 'nested-group', 'load-balance', false],
            ['surge', 'dest-hash', 'native', 'load-balance', false],
            ['clash', 'dest-hash', 'nested-group', 'load-balance', false],
            ['loon', 'dest-hash', 'nested-group', 'load-balance', false],
            ['qx', 'load-balance', 'omit', 'round-robin', false],
            ['clash', 'load-balance', 'nested-group', 'load-balance', false],
            ['loon', 'load-balance', 'nested-group', 'load-balance', true],
        ];

        cases.forEach(
            ([target, type, mode, outputSharedType, exact], index) => {
                const group = {
                    name: `Group ${index}`,
                    type,
                    includeOtherGroups: ['Child'],
                };
                const capability = resolvePolicyGroupCapability(target, type);
                const projection = projectIncludedPolicyGroups(
                    group,
                    capability,
                    target,
                );

                expect(capability.includedPolicyGroupsMode).to.equal(mode);
                expect(capability.outputSharedType).to.equal(outputSharedType);
                expect(capability.exact).to.equal(exact);
                expect(projection.mode).to.equal(mode);
                expect(projection.members).to.deep.equal(
                    mode === 'nested-group' ? ['Child'] : [],
                );
                expect(projection.dependencies).to.deep.equal(
                    mode === 'omit' ? [] : ['Child'],
                );
                expect(projection.diagnostics).to.have.length(
                    mode === 'native' ? 0 : 1,
                );
                expect(
                    policyGroupCapabilityDiagnostics(group, capability),
                ).to.have.length(exact ? 0 : 1);
            },
        );
    });

    it('classifies remote proxy source projection before target serialization', function () {
        const remoteProxySources = [
            {
                name: 'ready',
                source: {
                    kind: 'sub-store',
                    type: 'collection',
                    name: 'all',
                    publicBaseUrl: 'https://sub.example.com',
                },
            },
            {
                name: 'disabled',
                enabled: false,
                source: {
                    kind: 'url',
                    url: 'https://example.com/clash.yaml',
                    target: 'clash',
                },
            },
            {
                name: 'qx-owned',
                source: {
                    kind: 'url',
                    url: 'https://example.com/qx.conf',
                    target: 'qx',
                },
            },
            {
                name: 'surge-owned',
                source: {
                    kind: 'url',
                    url: 'https://example.com/surge.conf',
                    target: 'surge',
                },
            },
            {
                name: 'legacy-a',
                source: {
                    kind: 'sub-store',
                    type: 'collection',
                    name: 'legacy-a',
                    publicBaseUrl: 'https://sub.example.com',
                },
            },
            {
                name: 'legacy-b',
                source: {
                    kind: 'sub-store',
                    type: 'collection',
                    name: 'legacy-b',
                    publicBaseUrl: 'https://sub.example.com',
                },
            },
        ];
        const groups = [
            { name: 'None', type: 'select', members: [] },
            {
                name: 'Unsupported',
                type: 'ssid',
                members: [],
                remoteProxySource: 'ready',
            },
            {
                name: 'Missing',
                type: 'select',
                members: [],
                remoteProxySource: 'missing',
            },
            {
                name: 'Incompatible',
                type: 'select',
                members: [],
                remoteProxySource: 'qx-owned',
            },
            {
                name: 'Disabled',
                type: 'select',
                members: [],
                remoteProxySource: 'disabled',
            },
            {
                name: 'Ready',
                type: 'select',
                members: [],
                remoteProxySource: 'ready',
            },
            {
                name: 'Fallback',
                type: 'select',
                members: [],
                remoteProxySource: 'surge-owned',
            },
            {
                name: 'AmbiguousLegacy',
                type: 'select',
                members: [],
                targetOptions: {
                    surge: { remoteProxySource: 'legacy-a' },
                    clash: { remoteProxySource: 'legacy-b' },
                },
            },
            {
                name: 'SharedLegacy',
                type: 'select',
                members: [],
                targetOptions: {
                    surge: { remoteProxySource: 'ready' },
                    clash: { remoteProxySource: 'ready' },
                },
            },
        ];
        const sourceContext = createRemoteProxySourceContext({
            groups,
            remoteProxySources,
        });
        const cases = [
            ['None', 'qx', 'none'],
            ['Unsupported', 'qx', 'unsupported-field'],
            ['Missing', 'qx', 'missing'],
            ['Incompatible', 'clash', 'incompatible'],
            ['Disabled', 'clash', 'disabled'],
            ['Ready', 'clash', 'ready'],
            ['Fallback', 'qx', 'ready'],
            ['AmbiguousLegacy', 'qx', 'incompatible'],
            ['SharedLegacy', 'qx', 'ready'],
        ];

        cases.forEach(([name, target, status]) => {
            const group = groups.find((item) => item.name === name);
            expect(
                projectGroupRemoteProxySource(group, target, sourceContext)
                    .status,
            ).to.equal(status);
        });
        const fallback = projectGroupRemoteProxySource(
            groups.find((group) => group.name === 'Fallback'),
            'qx',
            sourceContext,
        );
        expect(fallback.supportLevel).to.equal('fallback');
        expect(fallback.fallback.forceOptParser).to.equal(true);

        const ambiguous = projectGroupRemoteProxySource(
            groups.find((group) => group.name === 'AmbiguousLegacy'),
            'qx',
            sourceContext,
        );
        expect(ambiguous.reason).to.equal('ambiguous-multiple-legacy-sources');
        expect(ambiguous.path).to.equal('groups.AmbiguousLegacy.targetOptions');
        expect(ambiguous.candidateSourceNames).to.deep.equal([
            'legacy-a',
            'legacy-b',
        ]);

        expect(() =>
            validateProject(
                {
                    name: 'ambiguous-legacy-source-projection',
                    remoteProxySources,
                    groups: [
                        {
                            ...groups.find(
                                (group) => group.name === 'AmbiguousLegacy',
                            ),
                            members: [{ kind: 'builtin', value: 'DIRECT' }],
                        },
                    ],
                    rules: [{ kind: 'final', policy: 'AmbiguousLegacy' }],
                    outputs: { qx: {} },
                },
                [],
                'qx',
            ),
        ).to.not.throw();
    });

    it('falls back QX remote filters for Surge built-ins and Surge-owned URLs', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-rule-set-fallbacks',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                    },
                ],
                rules: [
                    { kind: 'remote', ruleSet: 'LAN Rules', policy: 'DIRECT' },
                    {
                        kind: 'remote',
                        ruleSet: 'System Rules',
                        policy: 'Proxy',
                    },
                    { kind: 'remote', ruleSet: 'Private', policy: 'Proxy' },
                    { kind: 'final', policy: 'Proxy' },
                ],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [
                {
                    name: 'LAN Rules',
                    source: { kind: 'builtin', value: 'LAN' },
                },
                {
                    name: 'System Rules',
                    source: { kind: 'builtin', value: 'SYSTEM' },
                },
                {
                    name: 'Private',
                    source: {
                        kind: 'url',
                        url: 'https://rules.example.com/private.list',
                        target: 'surge',
                    },
                },
            ],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'FILTER_LAN, tag=LAN Rules, force-policy=direct, inserted-resource=true, enabled=true',
        );
        expect(result.body).to.contain('host, api.smoot.apple.com, Proxy');
        expect(result.body).to.contain(
            'user-agent, *WeatherFoundation*, Proxy',
        );
        expect(result.body).to.contain(
            'https://rules.example.com/private.list, tag=Private, force-policy=Proxy, opt-parser=true, enabled=true',
        );
        expect(result.warnings).to.deep.include({
            path: 'rules.LAN Rules',
            message:
                "Surge LAN was mapped to Quantumult X FILTER_LAN. The clients' built-in LAN definitions may differ.",
        });
        expect(result.warnings).to.deep.include({
            path: 'rules.System Rules',
            message:
                'Surge SYSTEM was approximated with a portable Quantumult X local-rule snapshot. Surge may change its built-in rules and PROCESS-NAME entries were omitted.',
        });
        expect(result.warnings).to.deep.include({
            path: 'rules.Private.source.url',
            message:
                'The Surge-owned HTTP(S) rule set was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('rejects target-dangling policy references but omits unreferenced unsupported groups', async function () {
        const disabledReference = {
            name: 'disabled-reference',
            remoteProxySources: [],
            groups: [
                {
                    name: 'Disabled',
                    type: 'select',
                    members: [],
                    disabled: true,
                },
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'group', value: 'Disabled' }],
                },
            ],
            rules: [{ kind: 'final', policy: 'Main' }],
            outputs: { qx: { independentConfig: '' } },
        };
        let disabledError;
        try {
            validateProject(disabledReference, [], 'qx');
        } catch (error) {
            disabledError = error;
        }
        expect(disabledError).to.be.instanceOf(ConfigGeneratorValidationError);
        expect(
            disabledError.issues.some(
                (item) => item.path === 'groups[1].members[0].value',
            ),
        ).to.equal(true);

        const unsupportedRule = {
            name: 'unsupported-rule-policy',
            remoteProxySources: [],
            groups: [
                {
                    name: 'QXNetwork',
                    type: 'ssid',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
            ],
            rules: [{ kind: 'final', policy: 'QXNetwork' }],
            outputs: { surge: {} },
        };
        let unsupportedError;
        try {
            await generateSurgeConfig({
                project: unsupportedRule,
                ruleSets: [],
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            unsupportedError = error;
        }
        expect(unsupportedError).to.be.instanceOf(
            ConfigGeneratorValidationError,
        );
        expect(
            unsupportedError.issues.some(
                (item) => item.path === 'rules[0].policy',
            ),
        ).to.equal(true);

        const unreferenced = {
            name: 'unreferenced-qx-group',
            remoteProxySources: [],
            groups: [
                {
                    name: 'QXNetwork',
                    type: 'ssid',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
            ],
            rules: [{ kind: 'final', policy: 'Main' }],
            outputs: { surge: {} },
        };
        const generated = await generateSurgeConfig({
            project: unreferenced,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        expect(generated.body).to.not.contain('QXNetwork =');
        expect(generated.body).to.contain('Main = select, DIRECT');
        expect(generated.warnings).to.deep.include({
            path: 'groups.QXNetwork',
            message: 'Surge does not support the ssid policy group type',
        });
    });

    it('rejects required incompatible sources before producing Surge output', async function () {
        let produceCalled = false;
        const produceBuiltinArtifact = async () => {
            produceCalled = true;
            return '';
        };
        const baseProject = {
            name: 'target-source-validation',
            embeddedSource: { type: 'collection', name: 'all' },
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [],
                    remoteProxySource: 'nodes',
                },
            ],
            rules: [{ kind: 'final', policy: 'Main' }],
            outputs: { surge: {} },
        };

        const qxOwnedProject = {
            ...baseProject,
            remoteProxySources: [
                {
                    name: 'nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/qx-nodes.conf',
                        target: 'qx',
                    },
                },
            ],
        };
        let qxOwnedError;
        try {
            await generateSurgeConfig({
                project: qxOwnedProject,
                ruleSets: [],
                produceBuiltinArtifact,
            });
        } catch (error) {
            qxOwnedError = error;
        }
        expect(qxOwnedError).to.be.instanceOf(ConfigGeneratorValidationError);
        expect(qxOwnedError.issues).to.deep.include({
            path: 'groups.Main.remoteProxySource',
            message:
                'references a remote proxy source that is not compatible with Surge',
        });
        expect(produceCalled).to.equal(false);

        const disabledProject = {
            ...baseProject,
            remoteProxySources: [
                {
                    name: 'nodes',
                    enabled: false,
                    source: {
                        kind: 'url',
                        url: 'https://example.com/surge-nodes.conf',
                        target: 'surge',
                    },
                },
            ],
        };
        let disabledError;
        try {
            await generateSurgeConfig({
                project: disabledProject,
                ruleSets: [],
                produceBuiltinArtifact,
            });
        } catch (error) {
            disabledError = error;
        }
        expect(disabledError).to.be.instanceOf(ConfigGeneratorValidationError);
        expect(disabledError.issues).to.deep.include({
            path: 'groups.Main.remoteProxySource',
            message:
                'references a remote proxy source that is disabled for Surge',
        });
        expect(produceCalled).to.equal(false);

        const wrongTargetRuleProject = {
            ...baseProject,
            remoteProxySources: [],
            groups: [
                {
                    name: 'Main',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
            ],
            rules: [
                { kind: 'remote', ruleSet: 'private', policy: 'Main' },
                { kind: 'final', policy: 'Main' },
            ],
        };
        let wrongTargetRuleError;
        try {
            await generateSurgeConfig({
                project: wrongTargetRuleProject,
                ruleSets: [
                    {
                        name: 'private',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/qx-private.list',
                            target: 'qx',
                        },
                    },
                ],
                produceBuiltinArtifact,
            });
        } catch (error) {
            wrongTargetRuleError = error;
        }
        expect(wrongTargetRuleError).to.be.instanceOf(
            ConfigGeneratorValidationError,
        );
        expect(
            wrongTargetRuleError.issues.some(
                (item) => item.path === 'rules[0].ruleSet',
            ),
        ).to.equal(true);
        expect(produceCalled).to.equal(false);
    });

    it('validates remote sources reached through Surge subnet policies', async function () {
        const project = {
            name: 'subnet-source-validation',
            remoteProxySources: [
                {
                    name: 'qx-nodes',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/qx-nodes.conf',
                        target: 'qx',
                    },
                },
                {
                    name: 'disabled-nodes',
                    enabled: false,
                    source: {
                        kind: 'url',
                        url: 'https://example.com/surge-nodes.conf',
                        target: 'surge',
                    },
                },
            ],
            groups: [
                {
                    name: 'QXRemote',
                    type: 'select',
                    members: [],
                    remoteProxySource: 'qx-nodes',
                },
                {
                    name: 'DisabledRemote',
                    type: 'select',
                    members: [],
                    remoteProxySource: 'disabled-nodes',
                },
                {
                    name: 'Network',
                    type: 'subnet',
                    members: [],
                    targetOptions: {
                        surge: {
                            subnetDefault: 'QXRemote',
                            subnetRules: [
                                {
                                    expression: 'TYPE:WIFI',
                                    policy: 'DisabledRemote',
                                },
                            ],
                        },
                    },
                },
            ],
            rules: [{ kind: 'final', policy: 'Network' }],
            outputs: { surge: {} },
        };

        let validationError;
        try {
            await generateSurgeConfig({
                project,
                ruleSets: [],
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            validationError = error;
        }
        expect(validationError).to.be.instanceOf(
            ConfigGeneratorValidationError,
        );
        expect(validationError.issues).to.deep.include({
            path: 'groups.QXRemote.remoteProxySource',
            message:
                'references a remote proxy source that is not compatible with Surge',
        });
        expect(validationError.issues).to.deep.include({
            path: 'groups.DisabledRemote.remoteProxySource',
            message:
                'references a remote proxy source that is disabled for Surge',
        });
    });

    it('emits only QX options supported by the selected policy type and warns for omitted shared rules', async function () {
        const result = await generateQXConfig({
            project: {
                name: 'qx-option-capabilities',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Manual',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        interval: 600,
                        tolerance: 50,
                        timeout: 5,
                        testUrl: 'https://example.com/generate_204',
                        targetOptions: {
                            qx: { aliveChecking: true },
                            surge: { evaluateBeforeUse: true },
                        },
                    },
                ],
                rules: [
                    { kind: 'comment', text: 'shared note' },
                    { kind: 'blank' },
                    { kind: 'final', policy: 'Manual' },
                ],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain('[policy]\nstatic=Manual, DIRECT');
        expect(result.body).to.not.contain('check-interval=');
        expect(result.body).to.not.contain('tolerance=');
        expect(result.body).to.not.contain('alive-checking=');
        expect(result.body).to.not.contain('generate_204');
        [
            'groups.Manual.interval',
            'groups.Manual.tolerance',
            'groups.Manual.timeout',
            'groups.Manual.testUrl',
            'groups.Manual.targetOptions.qx.aliveChecking',
            'groups.Manual.targetOptions.surge.evaluateBeforeUse',
            'rules[0]',
            'rules[1]',
        ].forEach((path) => {
            expect(
                result.warnings.some((warning) => warning.path === path),
                `missing warning for ${path}`,
            ).to.equal(true);
        });
    });

    it('resolves known rule-set providers per target and protects unknown target-bound URLs', async function () {
        const project = {
            name: 'target-rule-sets',
            remoteProxySources: [],
            groups: [
                {
                    name: 'Proxy',
                    type: 'select',
                    members: [{ kind: 'builtin', value: 'DIRECT' }],
                },
            ],
            rules: [
                { kind: 'remote', ruleSet: 'Advertising', policy: 'REJECT' },
                { kind: 'remote', ruleSet: 'Private', policy: 'Proxy' },
                { kind: 'remote', ruleSet: 'QXAdvertising', policy: 'Proxy' },
                { kind: 'final', policy: 'Proxy' },
            ],
            outputs: { surge: {}, qx: { independentConfig: '' } },
        };
        const ruleSets = [
            {
                name: 'Advertising',
                source: {
                    kind: 'url',
                    url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list',
                    target: 'surge',
                },
            },
            {
                name: 'Private',
                source: {
                    kind: 'url',
                    url: 'https://rules.example.com/private.list',
                    target: 'surge',
                },
            },
            {
                name: 'QXAdvertising',
                source: {
                    kind: 'url',
                    url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Advertising/Advertising.list',
                    target: 'qx',
                },
            },
        ];

        const surge = await generateSurgeConfig({
            project,
            ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        const qxProject = {
            ...project,
            rules: project.rules.filter((rule) => rule.ruleSet !== 'Private'),
        };
        const qx = await generateQXConfig({
            project: qxProject,
            ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(surge.body).to.contain(
            'RULE-SET, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list, REJECT',
        );
        expect(surge.body).to.contain(
            'RULE-SET, https://rules.example.com/private.list, Proxy',
        );
        expect(surge.body).to.contain(
            'RULE-SET, https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list, Proxy',
        );
        expect(qx.body).to.contain(
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Advertising/Advertising.list, tag=Advertising, force-policy=reject',
        );
        expect(qx.body).to.contain(
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/QuantumultX/Advertising/Advertising.list, tag=QXAdvertising, force-policy=Proxy',
        );
        expect(qx.body).to.not.contain(
            'tag=Advertising, force-policy=reject, opt-parser=',
        );
        expect(qx.body).to.not.contain(
            'tag=QXAdvertising, force-policy=Proxy, opt-parser=',
        );
        expect(qx.body).to.not.contain(
            'https://rules.example.com/private.list',
        );

        const qxWithFallback = await generateQXConfig({
            project,
            ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        expect(qxWithFallback.body).to.contain(
            'https://rules.example.com/private.list, tag=Private, force-policy=Proxy, opt-parser=true',
        );
        expect(qxWithFallback.warnings).to.deep.include({
            path: 'rules.Private.source.url',
            message:
                'The Surge-owned HTTP(S) rule set was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('round-trips the Quantumult X FILTER_LAN inserted resource fallback', async function () {
        const generated = await generateQXConfig({
            project: {
                name: 'qx-lan-round-trip',
                remoteProxySources: [],
                groups: [],
                rules: [
                    {
                        kind: 'remote',
                        name: 'Local Network',
                        ruleSet: 'lan-internal-id',
                        policy: 'DIRECT',
                    },
                ],
                outputs: { qx: { independentConfig: '' } },
            },
            ruleSets: [
                {
                    name: 'lan-internal-id',
                    source: { kind: 'builtin', value: 'LAN' },
                },
            ],
            produceBuiltinArtifact: async () => '',
        });

        expect(generated.body).to.contain(
            'FILTER_LAN, tag=Local Network, force-policy=direct, inserted-resource=true, enabled=true',
        );

        const imported = importQXConfig(generated.body);
        expect(imported.ruleSets).to.have.length(1);
        expect(imported.ruleSets[0]).to.deep.include({
            source: { kind: 'builtin', value: 'LAN' },
        });
        expect(imported.project.rules[0]).to.deep.include({
            kind: 'remote',
            name: 'Local Network',
            ruleSet: imported.ruleSets[0].name,
            policy: 'DIRECT',
        });
        expect(
            imported.warnings.some((warning) =>
                warning.message.includes(
                    'Unsupported Quantumult X remote filter',
                ),
            ),
        ).to.equal(false);
    });

    it('keeps imported Quantumult X remote-filter state on each binding instead of disabling the shared rule set', async function () {
        const draft = importQXConfig(
            '[filter_remote]\n' +
                'https://rules.example.com/ads.list, tag=ads, force-policy=reject, enabled=false\n',
        );
        draft.project.name = 'qx-disabled-remote-filter';

        expect(draft.ruleSets).to.have.length(1);
        expect(draft.ruleSets[0].enabled).to.not.equal(false);
        expect(draft.project.rules).to.have.length(1);
        expect(draft.project.rules[0]).to.deep.include({
            kind: 'remote',
            name: 'ads',
            ruleSet: 'ads',
            policy: 'REJECT',
            disabled: true,
        });

        draft.project.rules.push({
            ...draft.project.rules[0],
            name: 'ads-shared',
            policy: 'DIRECT',
            disabled: false,
        });
        const generatedFromSharedBinding = await generateQXConfig({
            project: draft.project,
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(generatedFromSharedBinding.body).to.not.contain('tag=ads,');
        expect(generatedFromSharedBinding.body).to.contain(
            'https://rules.example.com/ads.list, tag=ads-shared, force-policy=direct, opt-parser=true, enabled=true',
        );

        draft.project.rules[0].disabled = false;
        const generatedAfterReenable = await generateQXConfig({
            project: draft.project,
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });

        expect(generatedAfterReenable.body).to.contain(
            'https://rules.example.com/ads.list, tag=ads, force-policy=reject, opt-parser=true, enabled=true',
        );
        expect(generatedAfterReenable.body).to.contain(
            'https://rules.example.com/ads.list, tag=ads-shared, force-policy=direct, opt-parser=true, enabled=true',
        );
    });

    it('rejects unsupported rule-set target ownership', function () {
        expect(() =>
            validateProject(
                {
                    name: 'invalid-rule-target',
                    remoteProxySources: [],
                    groups: [{ name: 'Proxy', type: 'select', members: [] }],
                    rules: [
                        { kind: 'remote', ruleSet: 'ads', policy: 'Proxy' },
                    ],
                    outputs: { surge: {} },
                },
                [
                    {
                        name: 'ads',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/ads.list',
                            target: 'unknown-target',
                        },
                    },
                ],
            ),
        ).to.throw(ConfigGeneratorValidationError);
    });

    it('does not provider-rewrite a blackmatrix7 URL whose ref is named rule and uses the QX parser fallback', function () {
        const url =
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/rule/Surge/Advertising/Advertising.list';
        const result = resolveRuleSetUrl(
            {
                name: 'lookalike',
                source: { kind: 'url', url, target: 'surge' },
            },
            'qx',
        );

        expect(result.url).to.equal(url);
        expect(result.provider).to.equal(undefined);
        expect(result.forceOptParser).to.equal(true);
        expect(result.warning).to.deep.equal({
            message:
                'The Surge-owned HTTP(S) rule set was kept for Quantumult X with opt-parser=true. Conversion depends on the configured resource_parser_url and may be lossy.',
        });
    });

    it('imports supported Quantumult X sections without guessing unsupported semantics', async function () {
        const nativeSource = {
            name: 'all-nodes',
            source: {
                kind: 'sub-store',
                type: 'collection',
                name: 'all',
                publicBaseUrl: 'https://sub.example.com',
            },
        };
        const draft = importQXConfig(
            `[general]\nserver_check_url=http://cp.cloudflare.com/generate_204\n[server_remote]\nhttps://sub.example.com/download/collection/all, tag=Main, update-interval=43200, opt-parser=true\n[policy]\nstatic=Apple, DIRECT, PROXY, resource-tag-regex=^Main$, server-tag-regex=HK|Hong Kong\n[filter_local]\nhost-suffix, example.com, Apple\nprocess-name, Example, Apple\nfinal, direct\n[filter_remote]\nhttps://rules.example.com/ads.list, tag=ads, force-policy=proxy, update-interval=86400, opt-parser=true\n`,
            {
                remoteProxySources: [nativeSource],
            },
        );

        expect(draft.project.remoteProxySources[0]).to.deep.include({
            name: 'Main',
            source: nativeSource.source,
        });
        expect(draft.project.groups[0].remoteProxySource).to.equal('Main');
        expect(draft.project.groups[0].nodeNameRegex).to.equal('HK|Hong Kong');
        expect(
            draft.project.groups.find((group) => group.name === 'PROXY'),
        ).to.deep.include({
            remoteProxySource: 'Main',
        });
        expect(draft.project.rules).to.deep.include({
            kind: 'inline',
            type: 'DOMAIN-SUFFIX',
            value: 'example.com',
            policy: 'Apple',
        });
        expect(draft.ruleSets[0]).to.deep.include({
            name: 'ads',
            source: {
                kind: 'url',
                url: 'https://rules.example.com/ads.list',
                target: 'qx',
            },
            updateInterval: 86400,
            targetOptions: { qx: { optParser: true } },
        });
        expect(
            draft.project.rules.some((rule) => rule.type === 'PROCESS-NAME'),
        ).to.equal(false);
        expect(
            draft.warnings.some(
                (warning) =>
                    warning.path === 'filter_local' &&
                    warning.message.includes('process-name'),
            ),
        ).to.equal(true);
        expect(draft.project.outputs.qx.independentConfig).to.contain(
            '[general]\nserver_check_url=http://cp.cloudflare.com/generate_204',
        );
        expect(
            draft.project.rules.some(
                (rule) => rule.kind === 'remote' && rule.policy === 'PROXY',
            ),
        ).to.equal(true);
        const surgeProject = {
            ...draft.project,
            name: 'imported-qx',
            rules: draft.project.rules.map((rule) =>
                rule.kind === 'remote' ? { ...rule, disabled: true } : rule,
            ),
        };
        const surge = await generateSurgeConfig({
            project: surgeProject,
            ruleSets: draft.ruleSets,
            produceBuiltinArtifact: async () => '',
        });
        expect(surge.body).to.contain(
            'policy-path=https://sub.example.com/download/collection/all/Surge',
        );

        let wrongTargetError;
        try {
            await generateSurgeConfig({
                project: { ...draft.project, name: 'imported-qx' },
                ruleSets: draft.ruleSets,
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            wrongTargetError = error;
        }
        expect(wrongTargetError).to.be.instanceOf(
            ConfigGeneratorValidationError,
        );
        expect(
            wrongTargetError.issues.some(
                (item) => item.path === 'rules[1].ruleSet',
            ),
        ).to.equal(true);
    });

    it('keeps Surge and Quantumult X independent configuration separate', async function () {
        const project = {
            name: 'target-independent',
            remoteProxySources: [],
            groups: [],
            rules: [],
            outputs: {
                surge: {
                    independentConfig:
                        '[General]\nloglevel = notify\n\n[Host]\nexample.com = 1.1.1.1\n\n[MITM]\n',
                },
                qx: {
                    independentConfig:
                        '[general]\nserver_check_url=http://cp.cloudflare.com/generate_204\n\n[dns]\n\n[mitm]\n',
                },
            },
        };
        const surge = await generateSurgeConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const qx = await generateQXConfig({
            project,
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(surge.body).to.contain('loglevel = notify');
        expect(surge.body).to.contain('example.com = 1.1.1.1');
        expect(surge.body).to.not.contain('server_check_url=');
        expect(qx.body).to.contain(
            'server_check_url=http://cp.cloudflare.com/generate_204',
        );
        expect(qx.body).to.not.contain('loglevel = notify');
    });

    it('generates a classic Clash profile from the shared project model', async function () {
        const project = {
            name: 'clash-main',
            revision: 7,
            embeddedSource: { type: 'subscription', name: 'nodes' },
            remoteProxySources: [
                {
                    name: 'all-nodes',
                    source: {
                        kind: 'sub-store',
                        type: 'collection',
                        name: 'all',
                        publicBaseUrl: 'https://sub.example.com',
                    },
                    targetOptions: {
                        clash: { updateInterval: 43200 },
                    },
                },
            ],
            groups: [
                {
                    name: 'Child',
                    type: 'select',
                    members: [{ kind: 'proxy', value: 'Node A' }],
                },
                {
                    name: 'Main',
                    type: 'select',
                    members: [
                        { kind: 'group', value: 'Child' },
                        { kind: 'builtin', value: 'DIRECT' },
                    ],
                    includeOtherGroups: ['Child'],
                    includeAllProxies: true,
                    nodeNameRegex: '^Node',
                    remoteProxySource: 'all-nodes',
                    iconUrl: 'https://example.com/main.png',
                },
                {
                    name: 'Smart',
                    type: 'smart',
                    members: [{ kind: 'group', value: 'Main' }],
                    includeOtherGroups: ['Child'],
                    testUrl: 'https://example.com/generate_204',
                    interval: 300,
                },
                {
                    name: 'Round',
                    type: 'round-robin',
                    members: [{ kind: 'group', value: 'Main' }],
                },
                {
                    name: 'Hash',
                    type: 'dest-hash',
                    members: [{ kind: 'group', value: 'Main' }],
                },
                {
                    name: 'Balanced',
                    type: 'load-balance',
                    members: [{ kind: 'group', value: 'Main' }],
                },
                {
                    name: 'Available',
                    type: 'fallback',
                    members: [{ kind: 'group', value: 'Main' }],
                },
            ],
            rules: [
                {
                    kind: 'inline',
                    type: 'DOMAIN-SUFFIX',
                    value: 'example.com',
                    policy: 'Main',
                },
                {
                    kind: 'inline',
                    type: 'PROCESS-NAME',
                    value: 'Example.exe',
                    policy: 'Main',
                },
                {
                    kind: 'inline',
                    type: 'USER-AGENT',
                    value: 'Example*',
                    policy: 'Main',
                },
                {
                    kind: 'remote',
                    name: 'Advertising',
                    ruleSet: 'ads',
                    policy: 'REJECT',
                },
                { kind: 'remote', ruleSet: 'lan', policy: 'DIRECT' },
                { kind: 'remote', ruleSet: 'system', policy: 'DIRECT' },
                { kind: 'final', policy: 'Smart' },
            ],
            outputs: {
                clash: {
                    independentConfig: 'port: 7890\nmode: rule\n',
                },
            },
        };
        const result = await generateClashConfig({
            project,
            ruleSets: [
                {
                    name: 'ads',
                    source: {
                        kind: 'url',
                        url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list',
                        target: 'surge',
                    },
                    updateInterval: 3600,
                },
                {
                    name: 'lan',
                    source: { kind: 'builtin', value: 'LAN' },
                },
                {
                    name: 'system',
                    source: { kind: 'builtin', value: 'SYSTEM' },
                },
            ],
            produceBuiltinArtifact: async (input) => {
                expect(input.platform).to.equal('Clash');
                expect(input.produceType).to.equal('internal');
                return [
                    {
                        name: 'Node A',
                        type: 'ss',
                        server: 'a.example.com',
                        port: 443,
                        cipher: 'aes-128-gcm',
                        password: 'a',
                    },
                    {
                        name: 'Node B',
                        type: 'ss',
                        server: 'b.example.com',
                        port: 443,
                        cipher: 'aes-128-gcm',
                        password: 'b',
                    },
                ];
            },
        });
        const generated = YAML.safeLoad(result.body);

        expect(generated.port).to.equal(7890);
        expect(generated.proxies.map((proxy) => proxy.name)).to.deep.equal([
            'Node A',
            'Node B',
        ]);
        expect(generated['proxy-providers']).to.have.property('all-nodes-Main');
        expect(generated['proxy-providers']['all-nodes-Main']).to.deep.include({
            type: 'http',
            url: 'https://sub.example.com/download/collection/all/Clash',
            interval: 43200,
            path: './providers/all-nodes.yaml',
            filter: '^Node',
        });
        const main = generated['proxy-groups'].find(
            (group) => group.name === 'Main',
        );
        expect(main.proxies).to.deep.equal([
            'Child',
            'DIRECT',
            'Node A',
            'Node B',
        ]);
        expect(main.use).to.deep.equal(['all-nodes-Main']);
        const smart = generated['proxy-groups'].find(
            (group) => group.name === 'Smart',
        );
        expect(smart).to.deep.include({
            type: 'url-test',
            url: 'https://example.com/generate_204',
            interval: 300,
        });
        expect(smart.proxies).to.deep.equal(['Main', 'Child']);
        expect(
            generated['proxy-groups'].find((group) => group.name === 'Round'),
        ).to.deep.include({
            type: 'load-balance',
            strategy: 'round-robin',
        });
        expect(
            generated['proxy-groups'].find((group) => group.name === 'Hash'),
        ).to.deep.include({
            type: 'load-balance',
            strategy: 'consistent-hashing',
        });
        expect(
            generated['proxy-groups'].find(
                (group) => group.name === 'Balanced',
            ),
        ).to.deep.include({
            type: 'load-balance',
            strategy: 'consistent-hashing',
        });
        expect(
            generated['proxy-groups'].find(
                (group) => group.name === 'Available',
            ).type,
        ).to.equal('fallback');
        expect(generated['rule-providers'].Advertising).to.deep.include({
            type: 'http',
            behavior: 'classical',
            url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.yaml',
            interval: 3600,
        });
        expect(generated.rules).to.include('DOMAIN-SUFFIX,example.com,Main');
        expect(generated.rules).to.include('PROCESS-NAME,Example.exe,Main');
        expect(generated.rules).to.include('RULE-SET,Advertising,REJECT');
        expect(generated.rules).to.include(
            'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
        );
        expect(generated.rules).to.include('DOMAIN,captive.apple.com,DIRECT');
        expect(generated.rules.at(-1)).to.equal('MATCH,Smart');
        expect(result.warnings).to.deep.include({
            path: 'groups.Main.includeOtherGroups',
            message:
                'Clash cannot flatten nodes from included policy groups; referenced group names were appended as nested policy members instead.',
        });
        expect(
            result.warnings.some(
                (warning) => warning.path === 'groups.Smart.type',
            ),
        ).to.equal(true);
        expect(result.warnings).to.deep.include({
            path: 'groups.Smart.includeOtherGroups',
            message:
                'Clash cannot flatten nodes from included policy groups; referenced group names were appended as nested policy members instead.',
        });
        expect(
            result.warnings.some(
                (warning) => warning.path === 'groups.Balanced.type',
            ),
        ).to.equal(true);
        expect(
            result.warnings.some(
                (warning) => warning.path === 'groups.Main.iconUrl',
            ),
        ).to.equal(true);
        expect(
            result.warnings.some(
                (warning) => warning.path === 'rules.USER-AGENT',
            ),
        ).to.equal(true);
        expect(result.stats).to.deep.equal({
            nodeCount: 2,
            groupCount: 7,
            ruleCount: generated.rules.length,
        });
    });

    it('merges independent Clash policy groups and retains providers used by them', async function () {
        const result = await generateClashConfig({
            project: {
                name: 'clash-independent-groups',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Main',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                    },
                    {
                        name: 'Generated',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'REJECT' }],
                    },
                ],
                rules: [],
                outputs: {
                    clash: {
                        independentConfig: YAML.safeDump(
                            {
                                port: 7890,
                                'proxy-providers': {
                                    'legacy-provider': {
                                        type: 'http',
                                        url: 'https://example.com/legacy.yaml',
                                        path: './providers/legacy.yaml',
                                    },
                                },
                                'proxy-groups': [
                                    {
                                        name: 'Legacy',
                                        type: 'select',
                                        use: ['legacy-provider'],
                                    },
                                    {
                                        name: 'Main',
                                        type: 'url-test',
                                        proxies: ['OLD'],
                                    },
                                    {
                                        name: 'Tail',
                                        type: 'select',
                                        proxies: ['DIRECT'],
                                    },
                                ],
                            },
                            { lineWidth: 0, noRefs: true },
                        ),
                    },
                },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const generated = YAML.safeLoad(result.body);
        expect(generated.port).to.equal(7890);
        expect(
            generated['proxy-groups'].map((group) => group.name),
        ).to.deep.equal(['Legacy', 'Main', 'Tail', 'Generated']);
        expect(
            generated['proxy-groups'].filter((group) => group.name === 'Main'),
        ).to.have.length(1);
        expect(
            generated['proxy-groups'].find((group) => group.name === 'Main'),
        ).to.deep.include({
            name: 'Main',
            type: 'select',
            proxies: ['DIRECT'],
        });
        expect(
            generated['proxy-groups'].find((group) => group.name === 'Legacy'),
        ).to.deep.include({ use: ['legacy-provider'] });
        expect(generated['proxy-providers']['legacy-provider']).to.deep.include(
            {
                type: 'http',
                url: 'https://example.com/legacy.yaml',
                path: './providers/legacy.yaml',
            },
        );
    });

    it('approximates Clash automatic includeOtherGroups as nested policy members', async function () {
        const result = await generateClashConfig({
            project: {
                name: 'clash-nested-automatic-group',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Child',
                        type: 'select',
                        members: [{ kind: 'proxy', value: 'Node A' }],
                    },
                    {
                        name: 'Auto',
                        type: 'url-test',
                        members: [],
                        includeOtherGroups: ['Child'],
                    },
                ],
                rules: [{ kind: 'final', policy: 'Auto' }],
                outputs: { clash: {} },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        const generated = YAML.safeLoad(result.body);
        expect(
            generated['proxy-groups'].find((group) => group.name === 'Auto')
                .proxies,
        ).to.deep.equal(['Child']);
        expect(result.warnings).to.deep.include({
            path: 'groups.Auto.includeOtherGroups',
            message:
                'Clash cannot flatten nodes from included policy groups; referenced group names were appended as nested policy members instead.',
        });
    });

    it('downloads and converts custom Surge rule lists inline for classic Clash', async function () {
        const downloaded = [];
        const result = await generateClashConfig({
            project: {
                name: 'clash-custom-surge-rule-list',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                    },
                ],
                rules: [
                    {
                        kind: 'remote',
                        name: 'Talkatone',
                        ruleSet: 'talkatone',
                        policy: 'Proxy',
                    },
                    { kind: 'final', policy: 'Proxy' },
                ],
                outputs: { clash: {} },
            },
            ruleSets: [
                {
                    name: 'talkatone',
                    source: {
                        kind: 'url',
                        url: 'https://raw.githubusercontent.com/mottzz87/crules/main/rule/talkatone.list',
                        target: 'surge',
                    },
                },
            ],
            produceBuiltinArtifact: async () => '',
            downloadRuleSet: async (url) => {
                downloaded.push(url);
                return '# Talkatone\nDOMAIN-SUFFIX,talkatone.com\nIP-CIDR,192.0.2.0/24,no-resolve\nUSER-AGENT,Talkatone*\n';
            },
        });

        const generated = YAML.safeLoad(result.body);
        expect(downloaded).to.deep.equal([
            'https://raw.githubusercontent.com/mottzz87/crules/main/rule/talkatone.list',
        ]);
        expect(generated['rule-providers']).to.deep.equal({});
        expect(generated.rules).to.include('DOMAIN-SUFFIX,talkatone.com,Proxy');
        expect(generated.rules).to.include(
            'IP-CIDR,192.0.2.0/24,Proxy,no-resolve',
        );
        expect(generated.rules).to.not.include('USER-AGENT,Talkatone*,Proxy');
        expect(generated.rules.at(-1)).to.equal('MATCH,Proxy');
        expect(
            result.warnings.some(
                (warning) =>
                    warning.path === 'rules.talkatone.source.url' &&
                    warning.message.includes('Sub-Store cache'),
            ),
        ).to.equal(true);
    });

    it('uses safe Clash provider paths and the documented interval precedence', async function () {
        const result = await generateClashConfig({
            project: {
                name: 'clash-provider-paths',
                remoteProxySources: [
                    {
                        name: 'same/name',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/one.yaml',
                            target: 'clash',
                        },
                        targetOptions: {
                            clash: { updateInterval: 60 },
                        },
                    },
                    {
                        name: 'same\\name',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/two.yaml',
                            target: 'clash',
                        },
                    },
                    {
                        name: 'default',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/default.yaml',
                            target: 'clash',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'One',
                        type: 'select',
                        members: [],
                        remoteProxySource: 'same/name',
                        policyUpdateInterval: 120,
                    },
                    {
                        name: 'Two',
                        type: 'select',
                        members: [],
                        remoteProxySource: 'same\\name',
                        policyUpdateInterval: 240,
                    },
                    {
                        name: 'Default',
                        type: 'select',
                        members: [],
                        remoteProxySource: 'default',
                    },
                ],
                rules: [
                    {
                        kind: 'remote',
                        ruleSet: 'same/rules',
                        policy: 'DIRECT',
                    },
                    {
                        kind: 'remote',
                        ruleSet: 'same\\rules',
                        policy: 'REJECT',
                    },
                ],
                outputs: { clash: {} },
            },
            ruleSets: [
                {
                    name: 'same/rules',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/rules-one.yaml',
                        target: 'clash',
                    },
                },
                {
                    name: 'same\\rules',
                    source: {
                        kind: 'url',
                        url: 'https://example.com/rules-two.yaml',
                        target: 'clash',
                    },
                },
            ],
            produceBuiltinArtifact: async () => '',
        });
        const providers = Object.values(
            YAML.safeLoad(result.body)['proxy-providers'],
        );

        expect(providers.map((provider) => provider.interval)).to.deep.equal([
            60, 240, 86400,
        ]);
        expect(
            new Set(providers.map((provider) => provider.path)).size,
        ).to.equal(3);
        providers.forEach((provider) => {
            expect(provider.path).to.match(/^\.\/providers\/[^/\\]+\.yaml$/);
        });
        const ruleProviders = Object.values(
            YAML.safeLoad(result.body)['rule-providers'],
        );
        expect(
            new Set(ruleProviders.map((provider) => provider.path)).size,
        ).to.equal(2);
        ruleProviders.forEach((provider) => {
            expect(provider.path).to.match(/^\.\/rules\/[^/\\]+\.yaml$/);
        });
    });

    it('reuses equivalent Clash proxy-provider variants across policy groups', async function () {
        const result = await generateClashConfig({
            project: {
                name: 'clash-provider-reuse',
                remoteProxySources: [
                    {
                        name: 'shared',
                        source: {
                            kind: 'url',
                            url: 'https://example.com/shared.yaml',
                            target: 'clash',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Manual A',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'shared',
                    },
                    {
                        name: 'Manual B',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'REJECT' }],
                        remoteProxySource: 'shared',
                    },
                    {
                        name: 'Filtered',
                        type: 'select',
                        members: [],
                        remoteProxySource: 'shared',
                        nodeNameRegex: '^HK',
                    },
                ],
                rules: [{ kind: 'final', policy: 'Manual A' }],
                outputs: { clash: {} },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });
        const generated = YAML.safeLoad(result.body);
        const groups = Object.fromEntries(
            generated['proxy-groups'].map((group) => [group.name, group]),
        );

        expect(Object.keys(generated['proxy-providers'])).to.have.length(2);
        expect(groups['Manual A'].use).to.deep.equal(groups['Manual B'].use);
        expect(groups.Filtered.use).to.not.deep.equal(groups['Manual A'].use);
        expect(
            generated['proxy-providers'][groups.Filtered.use[0]].filter,
        ).to.equal('^HK');
    });

    it('rejects a target-owned proxy source that is incompatible with Clash', async function () {
        let caught;
        try {
            await generateClashConfig({
                project: {
                    name: 'clash-incompatible-source',
                    remoteProxySources: [
                        {
                            name: 'surge-only',
                            source: {
                                kind: 'url',
                                url: 'https://example.com/surge.conf',
                                target: 'surge',
                            },
                        },
                    ],
                    groups: [
                        {
                            name: 'Proxy',
                            type: 'select',
                            members: [],
                            remoteProxySource: 'surge-only',
                        },
                    ],
                    rules: [{ kind: 'final', policy: 'Proxy' }],
                    outputs: { clash: {} },
                },
                ruleSets: [],
                produceBuiltinArtifact: async () => '',
            });
        } catch (error) {
            caught = error;
        }

        expect(caught).to.be.instanceOf(ConfigGeneratorValidationError);
        expect(caught.issues).to.deep.include({
            path: 'groups.Proxy.remoteProxySource',
            message:
                'references a remote proxy source that is not compatible with Clash',
        });
    });

    it('imports common Clash YAML and preserves inline proxies for round-trip generation', async function () {
        const nativeSource = {
            name: 'native',
            source: {
                kind: 'sub-store',
                type: 'collection',
                name: 'all',
                publicBaseUrl: 'https://sub.example.com',
            },
        };
        const draft = importClashConfig(
            YAML.safeDump({
                port: 7890,
                proxies: [
                    {
                        name: 'Node A',
                        type: 'ss',
                        server: 'a.example.com',
                        port: 443,
                        cipher: 'aes-128-gcm',
                        password: 'a',
                    },
                    {
                        name: 'Node B',
                        type: 'ss',
                        server: 'b.example.com',
                        port: 443,
                        cipher: 'aes-128-gcm',
                        password: 'b',
                    },
                ],
                'proxy-providers': {
                    Remote: {
                        type: 'http',
                        url: 'https://sub.example.com/download/collection/all/Clash',
                        interval: 7200,
                        path: './providers/remote.yaml',
                        filter: 'HK|Hong Kong',
                    },
                },
                'proxy-groups': [
                    {
                        name: 'Proxy',
                        type: 'select',
                        proxies: ['Node A', 'DIRECT'],
                        use: ['Remote'],
                    },
                    {
                        name: 'Auto',
                        type: 'url-test',
                        proxies: ['Proxy', 'Node B'],
                        url: 'https://example.com/generate_204',
                        interval: 300,
                        tolerance: 50,
                    },
                    {
                        name: 'Round',
                        type: 'load-balance',
                        strategy: 'round-robin',
                        proxies: ['Proxy'],
                    },
                    {
                        name: 'Hash',
                        type: 'load-balance',
                        strategy: 'consistent-hashing',
                        proxies: ['Proxy'],
                    },
                ],
                'rule-providers': {
                    Ads: {
                        type: 'http',
                        behavior: 'classical',
                        url: 'https://rules.example.com/ads.yaml',
                        path: './rules/ads.yaml',
                        interval: 3600,
                    },
                },
                rules: [
                    'DOMAIN-SUFFIX,example.com,Proxy',
                    'RULE-SET,Ads,REJECT',
                    'MATCH,Auto',
                ],
            }),
            { remoteProxySources: [nativeSource] },
        );

        expect(draft.project.remoteProxySources[0]).to.deep.include({
            name: 'Remote',
            source: nativeSource.source,
            targetOptions: { clash: { updateInterval: 7200 } },
        });
        expect(draft.project.groups[0]).to.deep.include({
            name: 'Proxy',
            type: 'select',
            remoteProxySource: 'Remote',
            nodeNameRegex: 'HK|Hong Kong',
        });
        expect(draft.project.groups[0].members).to.deep.equal([
            { kind: 'proxy', value: 'Node A' },
            { kind: 'builtin', value: 'DIRECT' },
        ]);
        expect(draft.project.groups[1]).to.deep.include({
            name: 'Auto',
            type: 'url-test',
            testUrl: 'https://example.com/generate_204',
            interval: 300,
            tolerance: 50,
        });
        expect(draft.project.groups[1].members).to.deep.equal([
            { kind: 'group', value: 'Proxy' },
            { kind: 'proxy', value: 'Node B' },
        ]);
        expect(draft.project.groups[2].type).to.equal('round-robin');
        expect(draft.project.groups[3].type).to.equal('dest-hash');
        expect(draft.ruleSets[0]).to.deep.equal({
            name: 'Ads',
            source: {
                kind: 'url',
                url: 'https://rules.example.com/ads.yaml',
                target: 'clash',
            },
            updateInterval: 3600,
        });
        expect(draft.project.rules).to.deep.equal([
            {
                kind: 'inline',
                type: 'DOMAIN-SUFFIX',
                value: 'example.com',
                policy: 'Proxy',
            },
            {
                kind: 'remote',
                name: 'Ads',
                ruleSet: 'Ads',
                policy: 'REJECT',
            },
            { kind: 'final', policy: 'Auto' },
        ]);
        const independent = YAML.safeLoad(
            draft.project.outputs.clash.independentConfig,
        );
        expect(independent.port).to.equal(7890);
        expect(independent.proxies.map((proxy) => proxy.name)).to.deep.equal([
            'Node A',
            'Node B',
        ]);
        expect(independent).to.not.have.property('proxy-groups');

        draft.project.name = 'clash-round-trip';
        const generated = YAML.safeLoad(
            (
                await generateClashConfig({
                    project: draft.project,
                    ruleSets: draft.ruleSets,
                    produceBuiltinArtifact: async () => '',
                })
            ).body,
        );
        expect(generated.proxies.map((proxy) => proxy.name)).to.deep.equal([
            'Node A',
            'Node B',
        ]);
        expect(
            generated['proxy-groups'].find((group) => group.name === 'Proxy'),
        ).to.deep.include({
            proxies: ['Node A', 'DIRECT'],
            use: ['Remote-Proxy'],
        });
    });

    it('returns structured Clash import warnings for unsupported constructs', function () {
        const draft = importClashConfig(
            YAML.safeDump({
                proxies: [
                    {
                        name: 'Mihomo Node',
                        type: 'hysteria2',
                        server: 'example.com',
                        port: 443,
                    },
                ],
                'proxy-providers': {
                    Local: { type: 'file', path: './local.yaml' },
                },
                'proxy-groups': [
                    { name: 'Network', type: 'ssid', proxies: ['DIRECT'] },
                ],
                'rule-providers': {
                    Domains: {
                        type: 'http',
                        behavior: 'domain',
                        url: 'https://example.com/domains.yaml',
                    },
                },
                rules: ['RULE-SET,Domains,DIRECT', 'SCRIPT,example,DIRECT'],
            }),
        );

        expect(draft.project.groups).to.deep.equal([]);
        expect(draft.ruleSets).to.deep.equal([]);
        expect(draft.project.rules).to.deep.equal([]);
        expect(draft.warnings).to.have.length.greaterThan(3);
        expect(draft.warnings).to.deep.include({
            path: 'proxies[0].type',
            message:
                'The hysteria2 proxy type may require Mihomo and is not portable to classic Clash; the inline definition was preserved unchanged.',
        });
        draft.warnings.forEach((warning) => {
            expect(warning).to.have.all.keys('path', 'message');
        });
    });

    it('generates Loon remote proxies, filters, policy fallbacks, and remote rules', async function () {
        const result = await generateLoonConfig({
            project: {
                name: 'loon-profile',
                revision: 7,
                embeddedSource: {
                    type: 'subscription',
                    name: 'embedded-nodes',
                },
                remoteProxySources: [
                    {
                        name: 'Shared Nodes',
                        source: {
                            kind: 'sub-store',
                            type: 'collection',
                            name: 'all',
                            publicBaseUrl: 'https://sub.example.com',
                        },
                    },
                ],
                groups: [
                    {
                        name: 'Proxy',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                        remoteProxySource: 'Shared Nodes',
                        nodeNameRegex: 'HK|Hong Kong',
                    },
                    {
                        name: 'Auto',
                        type: 'smart',
                        members: [{ kind: 'group', value: 'Proxy' }],
                        interval: 600,
                        tolerance: 100,
                    },
                    {
                        name: 'Round',
                        type: 'round-robin',
                        members: [{ kind: 'proxy', value: 'HK 1' }],
                        timeout: 3,
                    },
                ],
                rules: [
                    {
                        kind: 'inline',
                        type: 'DOMAIN-SUFFIX',
                        value: 'example.com',
                        policy: 'Proxy',
                    },
                    {
                        kind: 'remote',
                        name: 'Advertising',
                        ruleSet: 'ads',
                        policy: 'REJECT',
                    },
                    { kind: 'final', policy: 'Proxy' },
                ],
                outputs: {
                    loon: {
                        independentConfig:
                            '[General]\nfoo=bar\n\n[Proxy Group]\nManual = select, DIRECT\n\n[Rule]\nDOMAIN, local.example, DIRECT\n',
                    },
                },
            },
            ruleSets: [
                {
                    name: 'ads',
                    source: {
                        kind: 'url',
                        url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list',
                        target: 'surge',
                    },
                },
            ],
            produceBuiltinArtifact: async ({ platform }) => {
                expect(platform).to.equal('Loon');
                return 'HK 1=shadowsocks,hk.example.com,443,aes-128-gcm,"password"\n';
            },
        });

        expect(result.sourceRevision).to.equal(7);
        expect(result.body).to.contain(
            '[Proxy]\nHK 1=shadowsocks,hk.example.com,443,aes-128-gcm,"password"',
        );
        expect(result.body).to.contain(
            '[Remote Proxy]\nShared Nodes = https://sub.example.com/download/collection/all/Loon',
        );
        expect(result.body).to.contain(
            '[Remote Filter]\nShared Nodes-Proxy = NameRegex, Shared Nodes, FilterKey = HK|Hong Kong',
        );
        expect(result.body).to.contain('Manual = select, DIRECT');
        expect(result.body).to.contain(
            'Proxy = select, DIRECT, Shared Nodes-Proxy',
        );
        expect(result.body).to.contain(
            'Auto = url-test, Proxy, url = http://www.gstatic.com/generate_204, interval = 600, tolerance = 100',
        );
        expect(result.body).to.contain(
            'Round = load-balance, HK 1, url = http://www.gstatic.com/generate_204, max-timeout = 3000, algorithm = Round-Robin',
        );
        expect(result.body).to.contain(
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list, policy=REJECT, enabled=true',
        );
        expect(result.body).to.contain(
            '# Advertising\nhttps://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list',
        );
        expect(result.body).to.contain('FINAL, Proxy');
        expect(
            result.warnings.some((warning) =>
                warning.message.includes(
                    'Surge smart was approximated as Loon url-test',
                ),
            ),
        ).to.equal(true);
    });

    it('approximates Loon fallback includeOtherGroups as a nested policy member', async function () {
        const result = await generateLoonConfig({
            project: {
                name: 'loon-nested-fallback-group',
                remoteProxySources: [],
                groups: [
                    {
                        name: 'Speedtest',
                        type: 'select',
                        members: [{ kind: 'builtin', value: 'DIRECT' }],
                    },
                    {
                        name: 'Hong Kong',
                        type: 'fallback',
                        members: [],
                        includeOtherGroups: ['Speedtest'],
                        nodeNameRegex: '港|HK|香港',
                    },
                ],
                rules: [{ kind: 'final', policy: 'Hong Kong' }],
                outputs: { loon: {} },
            },
            ruleSets: [],
            produceBuiltinArtifact: async () => '',
        });

        expect(result.body).to.contain(
            'Hong Kong = fallback, Speedtest, url = http://www.gstatic.com/generate_204',
        );
        expect(result.warnings).to.deep.include({
            path: 'groups.Hong Kong.includeOtherGroups',
            message:
                'Loon cannot flatten nodes from included policy groups; referenced group names were appended as nested policy members instead.',
        });
    });

    it('imports Loon proxy groups, SSID conditions, remote filters, and rules without losing local proxies', function () {
        const draft = importLoonConfig(
            '[General]\nfoo=bar\n' +
                '[Proxy]\nLocal=shadowsocks,local.example.com,443,aes-128-gcm,"password"\n' +
                '[Remote Proxy]\nSubs = https://example.com/nodes\n' +
                '[Remote Filter]\nHK = NameRegex, Subs, FilterKey = HK|Hong Kong\n' +
                '[Proxy Group]\n' +
                'Proxy = select, DIRECT, Local, HK\n' +
                'Auto = url-test, Proxy, url = http://bing.com/, interval = 600, tolerance = 50\n' +
                'SSID = ssid, default = Proxy, cellular = DIRECT, "Home WiFi" = Proxy\n' +
                '[Rule]\nDOMAIN-SUFFIX, example.com, Proxy\nFINAL, Proxy\n' +
                '[Remote Rule]\n# Advertising\nhttps://example.com/ads.list, policy=REJECT, enabled=false\n',
        );

        expect(draft.project.remoteProxySources).to.deep.include({
            name: 'Subs',
            source: {
                kind: 'url',
                url: 'https://example.com/nodes',
                mode: 'passthrough',
                target: 'loon',
            },
            enabled: true,
        });
        expect(draft.project.groups[0]).to.deep.include({
            name: 'Proxy',
            type: 'select',
            remoteProxySource: 'Subs',
            nodeNameRegex: 'HK|Hong Kong',
        });
        expect(draft.project.groups[0].members).to.deep.equal([
            { kind: 'builtin', value: 'DIRECT' },
            { kind: 'proxy', value: 'Local' },
        ]);
        expect(draft.project.groups[2].members).to.deep.equal([
            {
                kind: 'conditional',
                value: 'default:Proxy',
                policy: 'Proxy',
            },
            {
                kind: 'conditional',
                value: 'cellular:DIRECT',
                policy: 'DIRECT',
            },
            {
                kind: 'conditional',
                value: 'Home WiFi:Proxy',
                policy: 'Proxy',
            },
        ]);
        expect(draft.project.rules).to.deep.include({
            kind: 'remote',
            name: 'Advertising',
            ruleSet: 'Advertising',
            policy: 'REJECT',
            disabled: true,
        });
        expect(draft.ruleSets[0]).to.deep.equal({
            name: 'Advertising',
            source: {
                kind: 'url',
                url: 'https://example.com/ads.list',
                target: 'loon',
            },
        });
        expect(draft.project.outputs.loon.independentConfig).to.contain(
            '[Proxy]\nLocal=shadowsocks,local.example.com,443,aes-128-gcm,"password"',
        );
        expect(draft.project.outputs.loon.independentConfig).to.not.contain(
            '[Proxy Group]',
        );
    });

    it('resolves Blackmatrix7 rule sets to the Loon directory and preserves target diagnostics', function () {
        const result = resolveRuleSetUrl(
            {
                name: 'ads',
                source: {
                    kind: 'url',
                    url: 'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Surge/Advertising/Advertising.list',
                    target: 'surge',
                },
            },
            'loon',
        );

        expect(result.url).to.equal(
            'https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Loon/Advertising/Advertising.list',
        );
        expect(result.provider).to.equal('blackmatrix7-ios-rule-script');
        expect(normalizeTargetId('Loon')).to.equal('loon');
        expect(resolvePolicyGroupCapability('loon', 'smart')).to.deep.include({
            outputType: 'url-test',
            exact: false,
        });
    });

    it('registers preview, download, and import routes with builtin generation', async function () {
        const state = {
            [CONFIG_GENERATOR_KEY]: {
                version: 1,
                projects: [
                    {
                        name: 'main',
                        groups: [
                            {
                                name: 'Main',
                                type: 'select',
                                members: [{ kind: 'builtin', value: 'DIRECT' }],
                            },
                        ],
                        rules: [{ kind: 'final', policy: 'Main' }],
                        remoteProxySources: [],
                        outputs: {
                            surge: {},
                        },
                    },
                ],
                ruleSets: [],
            },
        };
        $.read = (key) => state[key] || [];
        $.write = (value, key) => {
            state[key] = value;
        };
        const { app, handlers } = createRouteApp();
        registerConfigGeneratorRoutes(app, {
            produceBuiltinArtifact: async () =>
                '[General]\nloglevel = notify\n',
        });
        expect(configGeneratorArtifactSource.platforms).to.deep.equal([
            'Surge',
            'QX',
            'Clash',
            'Loon',
        ]);
        expect(
            configGeneratorArtifactSource.platforms.map(normalizeTargetId),
        ).to.deep.equal(getTargetIds());

        const preview = createResponse(
            '/api/extensions/config-generator/preview/surge',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/preview/surge',
        )({ body: { name: 'main' } }, preview);
        expect(preview.body).to.deep.include({ status: 'success' });
        expect(preview.body.data.body).to.contain('[Proxy Group]');

        const download = createResponse('/download/config-project/:name');
        await handlers.get('GET /download/config-project/:name')(
            { params: { name: 'main' } },
            download,
        );
        expect(download.body).to.contain('[Proxy Group]');
        expect(download.body).to.contain('FINAL, Main');

        const qxDownload = createResponse('/download/config-project/:name');
        await handlers.get('GET /download/config-project/:name')(
            { params: { name: 'main' }, query: { target: 'QX' } },
            qxDownload,
        );
        expect(qxDownload.body).to.contain('[policy]');
        expect(qxDownload.body).to.contain('static=Main, DIRECT');

        const clashPreview = createResponse(
            '/api/extensions/config-generator/preview/clash',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/preview/clash',
        )({ body: { name: 'main' } }, clashPreview);
        expect(
            YAML.safeLoad(clashPreview.body.data.body)['proxy-groups'],
        ).to.deep.include({
            name: 'Main',
            type: 'select',
            proxies: ['DIRECT'],
        });

        const clashDownload = createResponse(
            '/download/config-project/:name/:target',
        );
        await handlers.get('GET /download/config-project/:name/:target')(
            { params: { name: 'main', target: 'Clash' }, query: {} },
            clashDownload,
        );
        expect(YAML.safeLoad(clashDownload.body).rules).to.deep.equal([
            'MATCH,Main',
        ]);

        const loonPreview = createResponse(
            '/api/extensions/config-generator/preview/loon',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/preview/loon',
        )({ body: { name: 'main' } }, loonPreview);
        expect(loonPreview.body.data.body).to.contain(
            '[Proxy Group]\nMain = select, DIRECT',
        );
        expect(loonPreview.body.data.body).to.contain('[Rule]\nFINAL, Main');

        const imported = createResponse(
            '/api/extensions/config-generator/import/surge',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/import/surge',
        )({ body: { content: '[Rule]\nFINAL, DIRECT\n' } }, imported);
        expect(imported.body.data.project.rules).to.deep.include({
            kind: 'final',
            policy: 'DIRECT',
            dnsFailed: false,
        });

        const qxImported = createResponse(
            '/api/extensions/config-generator/import/qx',
        );
        await handlers.get('POST /api/extensions/config-generator/import/qx')(
            { body: { content: '[policy]\nstatic=Main, DIRECT\n' } },
            qxImported,
        );
        expect(qxImported.body.data.project.groups).to.deep.include({
            name: 'Main',
            type: 'select',
            members: [{ kind: 'builtin', value: 'DIRECT' }],
        });

        const clashImported = createResponse(
            '/api/extensions/config-generator/import/clash',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/import/clash',
        )(
            {
                body: {
                    content:
                        'proxy-groups:\n  - name: Main\n    type: select\n    proxies:\n      - DIRECT\n',
                },
            },
            clashImported,
        );
        expect(clashImported.body.data.project.groups).to.deep.include({
            name: 'Main',
            type: 'select',
            members: [{ kind: 'builtin', value: 'DIRECT' }],
        });
        const loonImported = createResponse(
            '/api/extensions/config-generator/import/loon',
        );
        await handlers.get('POST /api/extensions/config-generator/import/loon')(
            {
                body: {
                    content:
                        '[Proxy Group]\nMain = select, DIRECT\n[Rule]\nFINAL, Main\n',
                },
            },
            loonImported,
        );
        expect(loonImported.body.data.project.groups).to.deep.include({
            name: 'Main',
            type: 'select',
            members: [{ kind: 'builtin', value: 'DIRECT' }],
        });
        [imported, qxImported, clashImported, loonImported].forEach(
            (response) => {
                expect(
                    Object.keys(response.body.data.project.outputs),
                ).to.deep.equal(['surge', 'qx', 'clash', 'loon']);
            },
        );
    });

    it('persists a cleared RULE-SET name across project update and reload', async function () {
        const state = {
            [CONFIG_GENERATOR_KEY]: {
                version: 1,
                projects: [
                    {
                        name: 'main',
                        revision: 1,
                        groups: [],
                        remoteProxySources: [],
                        rules: [
                            {
                                kind: 'remote',
                                name: 'Advertising',
                                ruleSet: 'ads',
                                policy: 'REJECT',
                            },
                        ],
                        outputs: { surge: {} },
                    },
                ],
                ruleSets: [
                    {
                        name: 'ads',
                        source: {
                            kind: 'url',
                            url: 'https://rules.example.com/ads.list',
                            target: 'surge',
                        },
                    },
                ],
            },
        };
        $.read = (key) => state[key] || [];
        $.write = (value, key) => {
            state[key] = value;
        };
        const { app, handlers } = createRouteApp();
        registerConfigGeneratorRoutes(app, {
            produceBuiltinArtifact: async () => '',
        });

        const update = createResponse(
            '/api/extensions/config-generator/project/:name',
        );
        await handlers.get(
            'PATCH /api/extensions/config-generator/project/:name',
        )(
            {
                params: { name: 'main' },
                body: {
                    rules: [
                        {
                            kind: 'remote',
                            ruleSet: 'ads',
                            policy: 'REJECT',
                        },
                    ],
                },
            },
            update,
        );

        expect(update.statusCode).to.equal(200);
        expect(update.body.data.rules[0]).to.not.have.property('name');

        const reload = createResponse(
            '/api/extensions/config-generator/project/:name',
        );
        await handlers.get(
            'GET /api/extensions/config-generator/project/:name',
        )({ params: { name: 'main' } }, reload);

        expect(reload.statusCode).to.equal(200);
        expect(reload.body.data.rules[0]).to.deep.equal({
            kind: 'remote',
            ruleSet: 'ads',
            policy: 'REJECT',
        });
    });

    it('converts an automatic URL source through the builtin subscription pipeline', async function () {
        const state = {
            [CONFIG_GENERATOR_KEY]: {
                version: 1,
                projects: [
                    {
                        name: 'automatic-source',
                        remoteProxySources: [
                            {
                                name: 'Shared % Nodes',
                                source: {
                                    kind: 'url',
                                    mode: 'auto',
                                    url: 'https://origin.example.com/subscription',
                                    publicBaseUrl: 'https://sub.example.com',
                                },
                            },
                        ],
                        groups: [],
                        rules: [],
                        outputs: { qx: {} },
                    },
                ],
                ruleSets: [],
            },
        };
        $.read = (key) => state[key] || [];
        $.write = (value, key) => {
            state[key] = value;
        };
        let producerInput;
        const { app, handlers } = createRouteApp();
        registerConfigGeneratorRoutes(app, {
            produceBuiltinArtifact: async (input) => {
                producerInput = input;
                return 'converted proxy output';
            },
        });

        const response = createResponse(
            '/download/config-project/:name/proxy-source/:source/:target',
        );
        await handlers.get(
            'GET /download/config-project/:name/proxy-source/:source/:target',
        )(
            {
                params: {
                    name: 'automatic-source',
                    source: 'Shared % Nodes',
                    target: 'QX',
                },
            },
            response,
        );

        expect(response.statusCode).to.equal(200);
        expect(response.body).to.equal('converted proxy output');
        expect(producerInput).to.deep.include({
            type: 'subscription',
            url: 'https://origin.example.com/subscription',
            platform: 'QX',
            noFlow: true,
        });
        expect(producerInput.subscription).to.deep.include({
            name: 'config-project:automatic-source:Shared % Nodes',
            displayName: 'Shared % Nodes',
            source: 'remote',
            url: 'https://origin.example.com/subscription',
        });
    });

    it('previews legacy URL sources through automatic conversion for Clash and Loon', async function () {
        const state = {
            [CONFIG_GENERATOR_KEY]: {
                version: 1,
                projects: [
                    {
                        name: 'legacy-url-source',
                        remoteProxySources: [
                            {
                                name: 'Shared Nodes',
                                source: {
                                    kind: 'url',
                                    url: 'https://origin.example.com/subscription',
                                    target: 'surge',
                                    publicBaseUrl: 'https://sub.example.com',
                                },
                            },
                        ],
                        groups: [
                            {
                                name: 'Auto',
                                type: 'smart',
                                members: [],
                                remoteProxySource: 'Shared Nodes',
                            },
                        ],
                        rules: [{ kind: 'final', policy: 'Auto' }],
                        outputs: { surge: {}, clash: {}, loon: {} },
                    },
                ],
                ruleSets: [],
            },
        };
        $.read = (key) => state[key] || [];
        $.write = (value, key) => {
            state[key] = value;
        };
        const { app, handlers } = createRouteApp();
        registerConfigGeneratorRoutes(app, {
            produceBuiltinArtifact: async () => 'converted proxy output',
        });

        const clashPreview = createResponse(
            '/api/extensions/config-generator/preview/clash',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/preview/clash',
        )({ body: { name: 'legacy-url-source' } }, clashPreview);
        expect(clashPreview.statusCode).to.equal(200);
        expect(clashPreview.body.status).to.equal('success');
        expect(clashPreview.body.data.body).to.contain(
            '/download/config-project/legacy-url-source/proxy-source/Shared%20Nodes/Clash',
        );

        const loonPreview = createResponse(
            '/api/extensions/config-generator/preview/loon',
        );
        await handlers.get(
            'POST /api/extensions/config-generator/preview/loon',
        )({ body: { name: 'legacy-url-source' } }, loonPreview);
        expect(loonPreview.statusCode).to.equal(200);
        expect(loonPreview.body.status).to.equal('success');
        expect(loonPreview.body.data.body).to.contain(
            '/download/config-project/legacy-url-source/proxy-source/Shared%20Nodes/Loon',
        );

        const convertedSource = createResponse(
            '/download/config-project/:name/proxy-source/:source/:target',
        );
        await handlers.get(
            'GET /download/config-project/:name/proxy-source/:source/:target',
        )(
            {
                params: {
                    name: 'legacy-url-source',
                    source: 'Shared Nodes',
                    target: 'Clash',
                },
            },
            convertedSource,
        );
        expect(convertedSource.statusCode).to.equal(200);
        expect(convertedSource.body).to.equal('converted proxy output');
    });

    it('uses the same Response Transformer for QX preview, download, and artifact output', async function () {
        const state = {
            [CONFIG_GENERATOR_KEY]: {
                version: 1,
                projects: [
                    {
                        name: 'scripted',
                        groups: [
                            {
                                name: 'Main',
                                type: 'select',
                                members: [{ kind: 'builtin', value: 'DIRECT' }],
                            },
                        ],
                        rules: [{ kind: 'final', policy: 'Main' }],
                        remoteProxySources: [],
                        process: [
                            {
                                id: 'append-marker',
                                type: 'Response Transformer',
                                args: {
                                    mode: 'script',
                                    content:
                                        'function transformFunction(res) { res.body += "# transformed\\n"; return res; }',
                                },
                            },
                            {
                                id: 'disabled-marker',
                                type: 'Response Transformer',
                                disabled: true,
                                args: {
                                    mode: 'script',
                                    content:
                                        'function transformFunction(res) { res.body += "# disabled\\n"; return res; }',
                                },
                            },
                        ],
                        outputs: { qx: {} },
                    },
                ],
                ruleSets: [],
            },
        };
        $.read = (key) => state[key] || [];
        $.write = (value, key) => {
            state[key] = value;
        };
        const { app, handlers } = createRouteApp();
        registerConfigGeneratorRoutes(app, {
            produceBuiltinArtifact: async () => '',
        });

        const preview = createResponse(
            '/api/extensions/config-generator/preview/qx',
        );
        await handlers.get('POST /api/extensions/config-generator/preview/qx')(
            { body: { name: 'scripted' } },
            preview,
        );
        expect(preview.body.data.body).to.contain('[policy]');
        expect(preview.body.data.body).to.contain('# transformed');
        expect(preview.body.data.body).to.not.contain('# disabled');

        const download = createResponse(
            '/download/config-project/:name/:target',
        );
        await handlers.get('GET /download/config-project/:name/:target')(
            { params: { name: 'scripted', target: 'QX' }, query: {} },
            download,
        );
        expect(download.body).to.contain('# transformed');
        expect(download.body).to.not.contain('# disabled');

        const output = await produceArtifact({
            type: 'config-project',
            name: 'scripted',
            platform: 'QX',
        });
        expect(output).to.contain('# transformed');
        expect(output).to.not.contain('# disabled');

        const clashOutput = await produceArtifact({
            type: 'config-project',
            name: 'scripted',
            platform: 'Clash',
        });
        expect(clashOutput).to.contain('# transformed');
        expect(clashOutput).to.not.contain('# disabled');
        expect(YAML.safeLoad(clashOutput)['proxy-groups']).to.deep.include({
            name: 'Main',
            type: 'select',
            proxies: ['DIRECT'],
        });
    });
});

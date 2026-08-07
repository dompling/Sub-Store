import { success, failed } from '@/restful/response';
import { RequestInvalidError, ResourceNotFoundError } from '@/restful/errors';
import { findByName, deleteByName, updateByName } from '@/utils/database';
import {
    initializeConfigGeneratorStore,
    readConfigGeneratorStore,
    writeConfigGeneratorStore,
} from './store';
import { validateProject, validateRuleSet } from './validation';
import { generateSurgeConfig } from './targets/surge/generator';
import { importSurgeConfig } from './targets/surge/importer';
import { generateQXConfig } from './targets/qx/generator';
import { importQXConfig } from './targets/qx/importer';
import { generateClashConfig } from './targets/clash/generator';
import { importClashConfig } from './targets/clash/importer';
import { generateLoonConfig } from './targets/loon/generator';
import { importLoonConfig } from './targets/loon/importer';
import {
    getTargetIds,
    getTargetPlatform,
    normalizeTargetId,
} from './core/target-capabilities';
import { isAutomaticRemoteProxySource } from './core/remote-proxy-source';
import { registerExtension } from '@/extensions/registry';
import { ARTIFACTS_KEY } from '@/constants';
import { ProxyUtils } from '@/core/proxy-utils';
import resourceCache from '@/utils/resource-cache';
import { runBackendRequestTask } from '@/utils/request-concurrency';
import { hex_md5 } from '@/vendor/md5';
import $ from '@/core/app';

const CONFIG_GENERATOR_RULE_SET_CACHE_PREFIX =
    'config-generator:remote-rule-set:';

const TARGET_HANDLERS = {
    surge: {
        route: 'surge',
        platform: getTargetPlatform('surge'),
        generate: generateSurgeConfig,
        importConfig: importSurgeConfig,
    },
    qx: {
        route: 'qx',
        platform: getTargetPlatform('qx'),
        generate: generateQXConfig,
        importConfig: importQXConfig,
    },
    clash: {
        route: 'clash',
        platform: getTargetPlatform('clash'),
        generate: generateClashConfig,
        importConfig: importClashConfig,
    },
    loon: {
        route: 'loon',
        platform: getTargetPlatform('loon'),
        generate: generateLoonConfig,
        importConfig: importLoonConfig,
    },
};
const TARGET_HANDLER_LIST = Object.values(TARGET_HANDLERS);

function assertTargetHandlerCoverage() {
    const capabilityTargets = getTargetIds();
    const handlerTargets = Object.keys(TARGET_HANDLERS);
    const missingHandlers = capabilityTargets.filter(
        (target) => !TARGET_HANDLERS[target],
    );
    const unknownHandlers = handlerTargets.filter(
        (target) => !capabilityTargets.includes(target),
    );
    if (!missingHandlers.length && !unknownHandlers.length) return;
    throw new Error(
        `Config generator target handler registry mismatch: missing handlers [${missingHandlers.join(
            ', ',
        )}], unknown handlers [${unknownHandlers.join(', ')}]`,
    );
}

assertTargetHandlerCoverage();

function errorFrom(error) {
    return error?.code
        ? error
        : new RequestInvalidError(
              'CONFIG_GENERATOR_INVALID_REQUEST',
              error.message || `${error}`,
          );
}

function projectItems() {
    return readConfigGeneratorStore().projects.map((project) => ({
        name: project.name,
        displayName: project.displayName || project.name,
    }));
}

function parseName(req) {
    return decodeURIComponent(req.params.name);
}

function resolveTargetHandler(target) {
    const handler = TARGET_HANDLERS[normalizeTargetId(target || 'surge')];
    if (handler) return handler;
    throw new RequestInvalidError(
        'UNSUPPORTED_EXTENSION_PLATFORM',
        `Config generator does not support ${target}`,
    );
}

async function downloadCachedRuleSet(url) {
    const cacheKey = `${CONFIG_GENERATOR_RULE_SET_CACHE_PREFIX}${hex_md5(url)}`;
    const cached = resourceCache.get(cacheKey);
    if (cached !== null && cached !== undefined) return cached;

    const response = await runBackendRequestTask(
        () => $.http.get({ url }),
        'config-generator-rule-set',
    );
    const statusCode = Number(response?.statusCode || 0);
    if (statusCode && (statusCode < 200 || statusCode >= 400)) {
        throw new Error(`HTTP ${statusCode}`);
    }
    const body = `${response?.body ?? ''}`;
    if (!body.trim()) throw new Error('Remote rule-set content is empty');
    resourceCache.set(cacheKey, body);
    return body;
}

async function generateProject({
    project,
    ruleSets,
    produceBuiltinArtifact,
    target,
}) {
    const handler = resolveTargetHandler(target);
    const result = await handler.generate({
        project,
        ruleSets,
        produceBuiltinArtifact,
        downloadRuleSet: downloadCachedRuleSet,
    });
    const transformed = await ProxyUtils.processResponse(
        { status: 200, headers: {}, body: result.body },
        project.process || [],
        handler.platform,
        { type: 'config-project', name: project.name },
    );
    return { ...result, body: transformed.body };
}

function importConfig(req, res, handler) {
    try {
        success(
            res,
            handler.importConfig(
                req.body?.content || '',
                req.body?.sourceContext || req.body?.remoteProxySources,
            ),
        );
    } catch (error) {
        failed(res, errorFrom(error), 400);
    }
}

function createProject(req, res) {
    try {
        const store = readConfigGeneratorStore();
        validateProject(req.body, store.ruleSets);
        if (findByName(store.projects, req.body.name))
            throw new RequestInvalidError(
                'CONFIG_GENERATOR_PROJECT_EXISTS',
                `项目 ${req.body.name} 已存在`,
            );
        const project = { ...req.body, revision: 1, updated: Date.now() };
        store.projects.push(project);
        writeConfigGeneratorStore(store);
        success(res, project, 201);
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof RequestInvalidError ? 400 : 400,
        );
    }
}

function updateProject(req, res) {
    try {
        const store = readConfigGeneratorStore();
        const name = parseName(req);
        const current = findByName(store.projects, name);
        if (!current)
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                `找不到项目 ${name}`,
            );
        const next = {
            ...current,
            ...req.body,
            name: current.name,
            revision: (current.revision || 0) + 1,
            updated: Date.now(),
        };
        validateProject(next, store.ruleSets);
        updateByName(store.projects, name, next);
        writeConfigGeneratorStore(store);
        success(res, next);
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError ? 404 : 400,
        );
    }
}

function deleteProject(req, res) {
    try {
        const store = readConfigGeneratorStore();
        const name = parseName(req);
        if (!findByName(store.projects, name))
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                `找不到项目 ${name}`,
            );
        const references = ($.read(ARTIFACTS_KEY) || [])
            .filter(
                (artifact) =>
                    artifact.type === 'config-project' &&
                    artifact.source === name,
            )
            .map((artifact) => artifact.name);
        if (references.length) {
            throw new RequestInvalidError(
                'CONFIG_GENERATOR_PROJECT_IN_USE',
                `项目 ${name} 正被远程配置引用`,
                { references },
            );
        }
        deleteByName(store.projects, name);
        writeConfigGeneratorStore(store);
        success(res, { name });
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError ? 404 : 400,
        );
    }
}

function createRuleSet(req, res) {
    try {
        const store = readConfigGeneratorStore();
        validateRuleSet(req.body);
        if (findByName(store.ruleSets, req.body.name))
            throw new RequestInvalidError(
                'CONFIG_GENERATOR_RULE_SET_EXISTS',
                `规则集 ${req.body.name} 已存在`,
            );
        store.ruleSets.push({ ...req.body });
        writeConfigGeneratorStore(store);
        success(res, req.body, 201);
    } catch (error) {
        failed(res, errorFrom(error), 400);
    }
}

function updateRuleSet(req, res) {
    try {
        const store = readConfigGeneratorStore();
        const name = parseName(req);
        const current = findByName(store.ruleSets, name);
        if (!current)
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_RULE_SET_NOT_FOUND',
                `找不到规则集 ${name}`,
            );
        const next = { ...current, ...req.body, name: current.name };
        validateRuleSet(next);
        updateByName(store.ruleSets, name, next);
        writeConfigGeneratorStore(store);
        success(res, next);
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError ? 404 : 400,
        );
    }
}

function deleteRuleSet(req, res) {
    try {
        const store = readConfigGeneratorStore();
        const name = parseName(req);
        const references = store.projects
            .filter((project) =>
                (project.rules || []).some(
                    (rule) => rule.kind === 'remote' && rule.ruleSet === name,
                ),
            )
            .map((project) => project.name);
        if (references.length)
            throw new RequestInvalidError(
                'CONFIG_GENERATOR_RULE_SET_IN_USE',
                `规则集 ${name} 正被项目引用`,
                { references },
            );
        if (!findByName(store.ruleSets, name))
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_RULE_SET_NOT_FOUND',
                `找不到规则集 ${name}`,
            );
        deleteByName(store.ruleSets, name);
        writeConfigGeneratorStore(store);
        success(res, { name });
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError ? 404 : 409,
        );
    }
}

async function preview(req, res, produceBuiltinArtifact, target) {
    try {
        const body = req.body || {};
        const store = readConfigGeneratorStore();
        const project = body.project || findByName(store.projects, body.name);
        if (!project)
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                '找不到配置项目',
            );
        const result = await generateProject({
            project,
            ruleSets: body.ruleSets || store.ruleSets,
            produceBuiltinArtifact,
            target,
        });
        success(res, result);
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError ? 404 : 400,
        );
    }
}

async function downloadProject(req, res, produceBuiltinArtifact, target) {
    try {
        const store = readConfigGeneratorStore();
        const project = findByName(store.projects, parseName(req));
        if (!project)
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                '找不到配置项目',
            );
        const result = await generateProject({
            project,
            ruleSets: store.ruleSets,
            produceBuiltinArtifact,
            target: target || req.params.target || req.query?.target,
        });
        res.type('text/plain').send(result.body);
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError ? 404 : 400,
        );
    }
}

async function downloadRemoteProxySource(req, res, produceBuiltinArtifact) {
    try {
        const store = readConfigGeneratorStore();
        const projectName = parseName(req);
        const project = findByName(store.projects, projectName);
        if (!project) {
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                `找不到配置项目 ${projectName}`,
            );
        }

        const sourceName = req.params.source;
        const source = findByName(project.remoteProxySources || [], sourceName);
        if (!source) {
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_REMOTE_PROXY_SOURCE_NOT_FOUND',
                `找不到远程订阅来源 ${sourceName}`,
            );
        }
        if (source.enabled === false) {
            throw new RequestInvalidError(
                'REMOTE_PROXY_SOURCE_DISABLED',
                `远程订阅来源 ${sourceName} 已停用`,
            );
        }
        if (
            source.source?.kind !== 'url' ||
            !isAutomaticRemoteProxySource(source)
        ) {
            throw new RequestInvalidError(
                'REMOTE_PROXY_SOURCE_NOT_AUTOMATIC',
                `远程订阅来源 ${sourceName} 未启用 Sub-Store 自动转换`,
            );
        }

        const targetId = normalizeTargetId(req.params.target);
        const handler = resolveTargetHandler(targetId);
        const output = await produceBuiltinArtifact({
            type: 'subscription',
            url: source.source.url,
            platform: handler.platform,
            subscription: {
                name: `config-project:${project.name}:${source.name}`,
                displayName: source.name,
                source: 'remote',
                url: source.source.url,
                process: [],
                noFlow: true,
            },
            produceOpts:
                targetId === 'surge'
                    ? {
                          'include-unsupported-proxy':
                              project.outputs?.surge?.includeUnsupportedProxy,
                      }
                    : {},
            noFlow: true,
        });
        if (
            output === undefined ||
            output === null ||
            (typeof output === 'string' && !output.trim()) ||
            (Array.isArray(output) && !output.length)
        ) {
            const error = new Error(
                `远程订阅来源 ${sourceName} 未生成可用于 ${handler.platform} 的节点`,
            );
            error.code = 'REMOTE_PROXY_SOURCE_TARGET_EMPTY';
            throw error;
        }
        res.type('text/plain').send(output);
    } catch (error) {
        failed(
            res,
            errorFrom(error),
            error instanceof ResourceNotFoundError
                ? 404
                : error instanceof RequestInvalidError
                ? 400
                : 502,
        );
    }
}

export function registerConfigGeneratorRoutes(
    $app,
    { produceBuiltinArtifact },
) {
    initializeConfigGeneratorStore();
    $app.get('/api/extensions/config-generator/projects', (req, res) =>
        success(res, readConfigGeneratorStore().projects),
    );
    $app.post('/api/extensions/config-generator/projects', createProject);
    $app.get('/api/extensions/config-generator/project/:name', (req, res) => {
        const project = findByName(
            readConfigGeneratorStore().projects,
            parseName(req),
        );
        project
            ? success(res, project)
            : failed(
                  res,
                  new ResourceNotFoundError(
                      'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                      '找不到配置项目',
                  ),
                  404,
              );
    });
    $app.patch('/api/extensions/config-generator/project/:name', updateProject);
    $app.delete(
        '/api/extensions/config-generator/project/:name',
        deleteProject,
    );
    $app.get('/api/extensions/config-generator/rule-sets', (req, res) =>
        success(res, readConfigGeneratorStore().ruleSets),
    );
    $app.post('/api/extensions/config-generator/rule-sets', createRuleSet);
    $app.patch(
        '/api/extensions/config-generator/rule-set/:name',
        updateRuleSet,
    );
    $app.delete(
        '/api/extensions/config-generator/rule-set/:name',
        deleteRuleSet,
    );
    TARGET_HANDLER_LIST.forEach((handler) => {
        $app.post(
            `/api/extensions/config-generator/preview/${handler.route}`,
            (req, res) =>
                preview(req, res, produceBuiltinArtifact, handler.platform),
        );
    });
    TARGET_HANDLER_LIST.forEach((handler) => {
        $app.post(
            `/api/extensions/config-generator/import/${handler.route}`,
            (req, res) => importConfig(req, res, handler),
        );
    });
    $app.get(
        '/download/config-project/:name/proxy-source/:source/:target',
        (req, res) =>
            downloadRemoteProxySource(req, res, produceBuiltinArtifact),
    );
    $app.get('/download/config-project/:name/:target', (req, res) =>
        downloadProject(req, res, produceBuiltinArtifact),
    );
    $app.get('/download/config-project/:name', (req, res) =>
        downloadProject(req, res, produceBuiltinArtifact),
    );
}

export const configGeneratorArtifactSource = {
    type: 'config-project',
    labelKey: 'configGenerator.artifactSource',
    platforms: TARGET_HANDLER_LIST.map((handler) => handler.platform),
    list: projectItems,
    get: (name) => findByName(readConfigGeneratorStore().projects, name),
    findSourceConfig: (name) =>
        findByName(readConfigGeneratorStore().projects, name),
    collectDependencies: (name) => {
        const project = findByName(readConfigGeneratorStore().projects, name);
        return project?.embeddedSource ? [project.embeddedSource] : [];
    },
    async produce({ name, platform, produceBuiltinArtifact }) {
        const project = findByName(readConfigGeneratorStore().projects, name);
        if (!project)
            throw new ResourceNotFoundError(
                'CONFIG_GENERATOR_PROJECT_NOT_FOUND',
                `找不到配置项目 ${name}`,
            );
        const result = await generateProject({
            project,
            ruleSets: readConfigGeneratorStore().ruleSets,
            produceBuiltinArtifact,
            target: platform,
        });
        return result.body;
    },
    async produceForSync(input) {
        const result = await this.produce(input);
        const project = findByName(
            readConfigGeneratorStore().projects,
            input.name,
        );
        return {
            body: result,
            sourceRevision: project?.revision,
            assertFresh() {},
        };
    },
};

registerExtension({
    id: 'config-generator',
    feature: 'configGenerator',
    registerRoutes: registerConfigGeneratorRoutes,
    artifactSources: [configGeneratorArtifactSource],
});

export default registerConfigGeneratorRoutes;

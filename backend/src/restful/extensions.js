import { failed, success } from './response';
import { getExtensionManager } from '@/extensions/manager';

function envValue(name) {
    try {
        return eval(`process.env.${name}`);
    } catch (e) {
        return undefined;
    }
}

function nodeCrypto() {
    try {
        if (eval('typeof process === "undefined"')) return null;
        return eval('require("crypto")');
    } catch (e) {
        return null;
    }
}

function constantTimeEqual(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string') return false;
    const crypto = nodeCrypto();
    if (!crypto) return left === right;
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sha256(value) {
    const crypto = nodeCrypto();
    return crypto
        ? crypto.createHash('sha256').update(`${value}`).digest('hex')
        : null;
}

/**
 * Lifecycle mutations are deliberately behind a separate admin boundary.
 * In a default development/runtime build no token is configured, so the
 * control plane is read-only rather than silently trusting loopback/CORS.
 * Tests and internal migration callers can pass `req.extensionAdmin === true`
 * without exposing that bypass to HTTP clients.
 */
function assertAdmin(req) {
    if (req?.extensionAdmin === true) return;
    const configuredToken = envValue('SUB_STORE_EXTENSION_ADMIN_TOKEN');
    const configuredHash = envValue('SUB_STORE_EXTENSION_ADMIN_TOKEN_HASH');
    const authorization = req?.headers?.authorization || '';
    const match = authorization.match(/^Bearer\s+(.+)$/i);
    const provided = match?.[1];
    if (!provided || (!configuredToken && !configuredHash)) {
        const error = new Error(
            'Extension administrator authentication is required',
        );
        error.code = 'EXTENSION_ADMIN_AUTH_REQUIRED';
        error.statusCode = 401;
        throw error;
    }
    if (
        (configuredToken && constantTimeEqual(provided, configuredToken)) ||
        (configuredHash &&
            sha256(provided) &&
            constantTimeEqual(sha256(provided), configuredHash))
    ) {
        return;
    }
    const error = new Error('Extension administrator authentication failed');
    error.code = 'EXTENSION_ADMIN_UNAUTHORIZED';
    error.statusCode = 403;
    throw error;
}

function requestPayload(req) {
    return req?.body && typeof req.body === 'object' ? req.body : {};
}

function lifecycleInput(req) {
    const body = requestPayload(req);
    return {
        // Package bytes are selected from the verified local catalog. The
        // HTTP control plane never accepts an arbitrary package object.
        runtime: body.runtime,
        version: body.version,
        variant: body.variant,
        expectedRevision:
            body.expectedRevision ??
            req.headers?.['x-sub-store-extension-revision'],
        idempotencyKey:
            body.idempotencyKey ?? req.headers?.['x-idempotency-key'],
    };
}

function handle(res, action, successStatus = 200) {
    return Promise.resolve()
        .then(action)
        .then((data) => success(res, data, successStatus))
        .catch((error) =>
            failed(
                res,
                error,
                error.statusCode ||
                    (error.code?.includes('NOT_FOUND') ? 404 : 409),
            ),
        );
}

function setEtag(res, value) {
    const etag = `W/"extensions-${value}"`;
    if (typeof res.set === 'function') res.set('ETag', etag);
    else if (typeof res.header === 'function') res.header('ETag', etag);
    return etag;
}

function notModified(req, res, etag) {
    const incoming = req?.headers?.['if-none-match'];
    if (incoming && incoming === etag) {
        res.status(304).end();
        return true;
    }
    return false;
}

export function registerExtensionControlRoutes(
    $app,
    manager = getExtensionManager(),
) {
    $app.get('/api/extensions/runtime', (req, res) => {
        const manifest = manager.getRuntimeManifest();
        const etag = setEtag(
            res,
            `${manifest.storageIdentity}-${manifest.revision}`,
        );
        if (notModified(req, res, etag)) return;
        success(res, manifest);
    });

    $app.get('/api/extensions/catalog', (req, res) => {
        const catalog = manager.getCatalog();
        const etag = setEtag(res, catalog.sequence);
        if (notModified(req, res, etag)) return;
        success(res, catalog);
    });

    $app.get('/api/extensions/installed', (req, res) =>
        success(res, {
            revision: manager.getRuntimeManifest().revision,
            items: manager.getInstalled(),
        }),
    );

    $app.get('/api/extensions/tasks/:taskId', (req, res) => {
        const task = manager.getTask(req.params.taskId);
        if (!task) {
            const error = new Error(
                `Extension task ${req.params.taskId} was not found`,
            );
            error.code = 'EXTENSION_TASK_NOT_FOUND';
            error.statusCode = 404;
            failed(res, error, 404);
            return;
        }
        success(res, task);
    });

    $app.get('/api/extensions/:id/health', (req, res) => {
        const id = decodeURIComponent(req.params.id);
        const manifest = manager.getManifest(id);
        if (!manifest) {
            const error = new Error(`Extension ${id} was not found`);
            error.code = 'EXTENSION_NOT_FOUND';
            error.statusCode = 404;
            failed(res, error, 404);
            return;
        }
        const health = manager.getHealth(id);
        success(res, {
            ...health,
            checks: {
                manifest: 'ok',
                implementation:
                    health.status === 'healthy' ? 'ok' : 'not-active',
            },
        });
    });

    $app.get('/api/extensions/:id/references', (req, res) => {
        const id = decodeURIComponent(req.params.id);
        if (!manager.getManifest(id)) {
            const error = new Error(`Extension ${id} was not found`);
            error.code = 'EXTENSION_NOT_FOUND';
            error.statusCode = 404;
            failed(res, error, 404);
            return;
        }
        // ReferenceGraph is introduced in a later phase. Returning an empty,
        // explicit projection keeps the API shape stable without claiming
        // that legacy artifact references have already migrated.
        success(res, {
            extensionId: manager.resolveId(id),
            status: manager.getAvailability(id).status,
            edges: [],
            complete: false,
        });
    });

    $app.get('/api/extensions/:id', (req, res, next) => {
        const id = decodeURIComponent(req.params.id);
        if (id === 'artifact-sources') {
            if (typeof next === 'function') return next();
            return;
        }
        const manifest = manager.getManifest(id);
        if (!manifest) {
            const error = new Error(`Extension ${id} was not found`);
            error.code = 'EXTENSION_NOT_FOUND';
            error.statusCode = 404;
            failed(res, error, 404);
            return;
        }
        success(res, {
            id: manager.resolveId(id),
            manifest,
            availability: manager.getAvailability(id),
            record: manager.getRecord(id),
        });
    });

    $app.post('/api/admin/extensions/:id/install', (req, res) =>
        handle(
            res,
            () => {
                assertAdmin(req);
                return manager.install(req.params.id, lifecycleInput(req));
            },
            201,
        ),
    );

    $app.post('/api/admin/extensions/:id/enable', (req, res) =>
        handle(res, () => {
            assertAdmin(req);
            return manager.enable(req.params.id, lifecycleInput(req));
        }),
    );

    $app.post('/api/admin/extensions/:id/disable', (req, res) =>
        handle(res, () => {
            assertAdmin(req);
            return manager.disable(req.params.id, lifecycleInput(req));
        }),
    );

    $app.post('/api/admin/extensions/:id/update', (req, res) =>
        handle(res, () => {
            assertAdmin(req);
            return manager.update(req.params.id, lifecycleInput(req));
        }),
    );

    $app.post('/api/admin/extensions/:id/rollback', (req, res) =>
        handle(res, () => {
            assertAdmin(req);
            return manager.rollback(req.params.id, lifecycleInput(req));
        }),
    );

    $app.delete('/api/admin/extensions/:id/data', (req, res) =>
        handle(res, () => {
            assertAdmin(req);
            return manager.purgeData(req.params.id, lifecycleInput(req));
        }),
    );

    $app.delete('/api/admin/extensions/:id', (req, res) =>
        handle(res, () => {
            assertAdmin(req);
            return manager.uninstall(req.params.id, {
                purgeData: requestPayload(req).purgeData === true,
                expectedRevision: lifecycleInput(req).expectedRevision,
                idempotencyKey: lifecycleInput(req).idempotencyKey,
            });
        }),
    );
}

export { assertAdmin as assertExtensionAdmin };

export default registerExtensionControlRoutes;

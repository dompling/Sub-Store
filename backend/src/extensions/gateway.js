import { failed } from '@/restful/response';
import { getExtensionManager } from './manager';

function requestRevision(req) {
    return (
        req?.headers?.['x-sub-store-extension-revision'] ??
        req?.headers?.['x-extension-revision'] ??
        req?.query?.extensionRevision ??
        req?.body?.extensionRevision
    );
}

function requestExtensionAbi(req) {
    return (
        req?.headers?.['x-sub-store-extension-abi'] ??
        req?.headers?.['x-extension-abi'] ??
        req?.query?.extensionAbi ??
        req?.body?.extensionAbi
    );
}

function staleAbiError(manager, extensionId, suppliedAbi) {
    const manifest = manager.getManifest(extensionId);
    const required = manifest?.host?.implementationAbi;
    if (suppliedAbi && required && suppliedAbi !== required) {
        const error = new Error('Extension implementation ABI is stale');
        error.code = 'EXTENSION_ABI_MISMATCH';
        error.statusCode = 409;
        error.details = {
            extensionId: manager.resolveId(extensionId),
            requiredFrontendImplementationAbi: required,
            suppliedAbi,
        };
        throw error;
    }
}

export function createExtensionGateway(manager = getExtensionManager()) {
    return {
        availability(extensionId) {
            return manager.getAvailability(extensionId);
        },
        guard(extensionId, req, options = {}) {
            staleAbiError(manager, extensionId, requestExtensionAbi(req));
            return manager.guard(extensionId, {
                ...options,
                expectedRevision:
                    options.expectedRevision !== undefined
                        ? options.expectedRevision
                        : requestRevision(req),
            });
        },
        async invoke(extensionId, req, handler, options = {}) {
            const gate = this.guard(extensionId, req, options);
            if (typeof handler !== 'function') return gate;
            return handler(gate.adapter, gate, req);
        },
        route(extensionId, handler, options = {}) {
            return async (req, res, next) => {
                try {
                    const value = await this.invoke(
                        extensionId,
                        req,
                        handler,
                        options,
                    );
                    if (value !== undefined && !res.headersSent) {
                        res.json({ status: 'success', data: value });
                    }
                } catch (error) {
                    if (typeof next === 'function' && options.passThrough) {
                        next(error);
                        return;
                    }
                    failed(
                        res,
                        error,
                        error.statusCode ||
                            (error.code === 'EXTENSION_NOT_FOUND' ? 404 : 409),
                    );
                }
            };
        },
    };
}

export function assertExtensionRequest(
    manager,
    extensionId,
    req,
    options = {},
) {
    return createExtensionGateway(manager).guard(extensionId, req, options);
}

export function withExtensionGateway(
    manager,
    extensionId,
    handler,
    { passThrough = false, allowDisabled = false } = {},
) {
    const gateway = createExtensionGateway(manager);
    return gateway.route(extensionId, handler, { passThrough, allowDisabled });
}

/**
 * Wrap a legacy Express-like registrar without changing its public route
 * shape. The registrar is used by the Host for legacy aliases that still live
 * in core modules (artifacts/sync/sort). Availability is checked per request,
 * so disabling a contribution does not require mutating Express' route stack.
 */
export function createExtensionRouteApp(
    app,
    manager,
    extensionId,
    { shouldGuard = () => true, mapPath = (method, path) => path } = {},
) {
    const proxy = Object.create(app);
    const wrap = (method, sourcePath, targetPath, handler) => {
        if (!shouldGuard(method, sourcePath, targetPath)) return handler;
        return async (req, res, next) => {
            try {
                manager.guard(extensionId);
                return await handler(req, res, next);
            } catch (error) {
                failed(res, error, error.statusCode || 409);
                return undefined;
            }
        };
    };
    const register = (method, path, handlers) => {
        const targetPath = mapPath(method, path);
        if (!targetPath) return proxy;
        const wrapped = handlers.map((handler) =>
            typeof handler === 'function'
                ? wrap(method, path, targetPath, handler)
                : handler,
        );
        app[method](targetPath, ...wrapped);
        return proxy;
    };

    for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
        if (typeof app[method] !== 'function') continue;
        proxy[method] = (path, ...handlers) => register(method, path, handlers);
    }
    if (typeof app.route === 'function') {
        proxy.route = (path) => {
            const routeProxy = {};
            for (const method of ['get', 'post', 'put', 'patch', 'delete']) {
                routeProxy[method] = (...handlers) => {
                    const targetPath = mapPath(method, path);
                    if (!targetPath) return routeProxy;
                    const route = app.route(targetPath);
                    if (typeof route[method] !== 'function') return routeProxy;
                    const wrapped = handlers.map((handler) =>
                        typeof handler === 'function'
                            ? wrap(method, path, targetPath, handler)
                            : handler,
                    );
                    route[method](...wrapped);
                    return routeProxy;
                };
            }
            return routeProxy;
        };
    }
    return proxy;
}

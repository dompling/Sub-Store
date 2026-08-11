import manifest from './manifest.json';
import { createExtensionRouteApp } from '../gateway';

export const CONFIG_HOSTING_EXTENSION_ID = manifest.id;

const CONFIG_HOSTING_ROUTE_PREFIX = `/api/extensions/${CONFIG_HOSTING_EXTENSION_ID}/runtime`;

const LEGACY_SIMPLE_ROUTE_MAP = Object.freeze({
    '/api/artifacts/restore': `${CONFIG_HOSTING_ROUTE_PREFIX}/artifacts/restore`,
    '/api/artifacts': `${CONFIG_HOSTING_ROUTE_PREFIX}/artifacts`,
    '/api/artifact/:name': `${CONFIG_HOSTING_ROUTE_PREFIX}/artifacts/:name`,
    '/api/sort/artifacts': `${CONFIG_HOSTING_ROUTE_PREFIX}/sort`,
});

const LEGACY_PARSER_ROUTE_MAP = Object.freeze({
    '/api/sync/artifacts': `${CONFIG_HOSTING_ROUTE_PREFIX}/sync`,
    '/api/sync/artifact/:name': `${CONFIG_HOSTING_ROUTE_PREFIX}/sync/:name`,
});

function routeMapForLane(lane) {
    if (lane === 'simple') return LEGACY_SIMPLE_ROUTE_MAP;
    if (lane === 'parser') return LEGACY_PARSER_ROUTE_MAP;
    return {};
}

/**
 * Return two permanent gateway surfaces for the same implementation:
 *
 * - `legacy` preserves the established Artifact/Sync API used by existing
 *   frontends and hosted links.
 * - `canonical` exposes the namespaced plugin route contract.
 *
 * Both surfaces resolve availability for every request, so disabling or
 * uninstalling the package takes effect without mutating the router stack.
 */
export function createConfigHostingRouteApps(app, manager, lane) {
    const routeMap = routeMapForLane(lane);
    return {
        legacy: createExtensionRouteApp(
            app,
            manager,
            CONFIG_HOSTING_EXTENSION_ID,
            {
                mapPath(method, path) {
                    return Object.prototype.hasOwnProperty.call(routeMap, path)
                        ? path
                        : null;
                },
            },
        ),
        canonical: createExtensionRouteApp(
            app,
            manager,
            CONFIG_HOSTING_EXTENSION_ID,
            {
                mapPath(method, path) {
                    return routeMap[path] || null;
                },
            },
        ),
    };
}

export function createConfigHostingAdapter({
    startScheduledJobs,
    stopScheduledJobs,
} = {}) {
    let active = false;
    return {
        extensionId: CONFIG_HOSTING_EXTENSION_ID,
        manifest,
        activate() {
            if (active) return this.health();
            active = true;
            try {
                startScheduledJobs?.({ isActive: () => active });
            } catch (error) {
                active = false;
                try {
                    stopScheduledJobs?.();
                } catch (cleanupError) {
                    error.cleanupError = cleanupError;
                }
                throw error;
            }
            return {
                active,
                implementationAbi: manifest.host.implementationAbi,
            };
        },
        deactivate() {
            if (!active) return this.health();
            // Close the adapter gate before touching scheduler resources. A
            // failing stop hook must not leave the extension logically active.
            active = false;
            stopScheduledJobs?.();
            return { active };
        },
        health() {
            return {
                active,
                implementationAbi: manifest.host.implementationAbi,
            };
        },
    };
}

export default createConfigHostingAdapter;

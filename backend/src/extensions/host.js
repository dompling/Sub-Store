import { getExtensionManager } from './manager';
import { listRegisteredExtensions } from './registry';
import { createExtensionGateway } from './gateway';
import configGeneratorManifest from './config-generator/manifest.json';
import configHostingManifest from './config-hosting/manifest.json';
import { createConfigHostingAdapter } from './config-hosting';

/**
 * Initialize the data-only Host layer. Business extensions can continue to
 * use the legacy registry during Phase 1; this function gives them a stable
 * manifest/manager/gateway boundary for incremental migration.
 */
export function initializeExtensionHost(options = {}) {
    const manager = getExtensionManager(options);
    // Register manifests even when a product slice did not import a concrete
    // extension implementation. This makes runtime/catalog state explicit.
    manager.registerManifest(configGeneratorManifest, null, {
        defaultEnabled: true,
    });
    manager.registerManifest(configHostingManifest, null, { kind: 'official' });
    const configHostingAdapter =
        options.configHostingAdapter ||
        createConfigHostingAdapter(options.configHosting || {});
    manager.registerAdapter(configHostingManifest.id, configHostingAdapter);
    if (options.adoptLegacy !== false) {
        manager.adoptLegacyConfigHostingIfNeeded();
    }
    if (options.restoreEnabled !== false) {
        manager.restoreEnabledExtensions();
    }
    return {
        manager,
        gateway: createExtensionGateway(manager),
        registered: listRegisteredExtensions(),
        configHostingAdapter,
    };
}

export { getExtensionManager } from './manager';
export { createExtensionGateway } from './gateway';
export { registerExtension } from './registry';

export default initializeExtensionHost;

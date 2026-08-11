import { getExtensionManager } from './manager';
import { listRegisteredExtensions } from './registry';
import { createExtensionGateway } from './gateway';
import configHostingManifest from './config-hosting/manifest.json';
import { createConfigHostingAdapter } from './config-hosting';
import { createBackendExtensionSdkV1 } from './backend-sdk-v1';
import { registerExtension, unregisterExtension } from './registry';

/**
 * Initialize the data-only Host layer. Business extensions can continue to
 * use the legacy registry during Phase 1; this function gives them a stable
 * manifest/manager/gateway boundary for incremental migration.
 */
export function initializeExtensionHost(options = {}) {
    const manager = getExtensionManager(options);
    manager.setHostBindings({
        createServices: ({ extensionId, manifest, store }) =>
            createBackendExtensionSdkV1({ extensionId, manifest, store }),
        registerContribution: registerExtension,
        unregisterContribution: unregisterExtension,
    });
    // Register manifests even when a product slice did not import a concrete
    // extension implementation. This makes runtime/catalog state explicit.
    manager.registerManifest(configHostingManifest, null, { kind: 'official' });
    const configHostingAdapter =
        options.configHostingAdapter ||
        createConfigHostingAdapter(options.configHosting || {});
    manager.registerAdapter(configHostingManifest.id, configHostingAdapter);
    options.registerEmbeddedExtensions?.(manager);
    if (options.adoptLegacy !== false) {
        manager.adoptLegacyConfigGeneratorIfNeeded();
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

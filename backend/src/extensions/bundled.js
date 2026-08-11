// Static bundled entrypoint catalog. Lifecycle adapters and contribution
// descriptors are registered explicitly by the Host; importing this module
// must not activate an extension as a side effect.
import { bundledExtensionCatalog } from './catalog.generated';
import { getExtensionManager } from './manager';
import { listRegisteredExtensions } from './registry';

let loaded = false;

export function loadBundledExtensions(manager = getExtensionManager()) {
    if (!loaded) {
        for (const entry of bundledExtensionCatalog) {
            manager.registerManifest(entry.manifest, null, {
                defaultEnabled: entry.defaultEnabled,
            });
        }
        loaded = true;
    }
    return listRegisteredExtensions();
}

export function resetBundledExtensionsForTests() {
    loaded = false;
}

export default loadBundledExtensions;

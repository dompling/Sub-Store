// Static bundled entrypoint catalog. Importing this module preserves the
// current config-generator activation side effect while giving the Host one
// explicit place to load bundled implementations.
import './config-generator';
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

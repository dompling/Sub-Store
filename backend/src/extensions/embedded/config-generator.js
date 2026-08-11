import { createBackendExtensionSdkV1 } from '../backend-sdk-v1';
import {
    registerExtension,
    unregisterExtension,
} from '../registry';
import {
    extensionId,
    implementationAbi,
    registerEmbeddedRuntime,
} from './org.substore.config-generator.generated';
import embeddedMetadata from './org.substore.config-generator.generated.json';

export * from './org.substore.config-generator.generated';

/** Register the generated implementation used by non-Node script runtimes. */
export function registerEmbeddedConfigGenerator(manager) {
    const manifest = manager.getManifest(extensionId);
    if (
        !manifest ||
        manifest.version !== embeddedMetadata.version ||
        manifest.host?.implementationAbi !== implementationAbi ||
        embeddedMetadata.extensionId !== extensionId ||
        embeddedMetadata.implementationAbi !== implementationAbi
    ) {
        const error = new Error(
            'Config generator embedded artifact does not match Host authorization metadata',
        );
        error.code = 'EXTENSION_EMBEDDED_ARTIFACT_MISMATCH';
        throw error;
    }
    return registerEmbeddedRuntime({
        apiVersion: '1.0.0',
        extensionId,
        services: createBackendExtensionSdkV1({
            extensionId,
            manifest,
            store: manager.store,
        }),
        registerAdapter: (adapter) =>
            manager.registerAdapter(extensionId, adapter),
        unregisterAdapter: (adapter) =>
            manager.unregisterAdapter(extensionId, adapter),
        registerContribution: (contribution) =>
            registerExtension(contribution),
        unregisterContribution: () => unregisterExtension(extensionId),
    });
}

export default registerEmbeddedConfigGenerator;

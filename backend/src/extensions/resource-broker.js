import { COLLECTIONS_KEY, SUBS_KEY } from '@/constants';
import {
    normalizeProviderResourceDescriptor,
    normalizeResourceOutput,
    normalizeResourceRef,
    resourceError,
} from './resource-contracts';
import { listResourceProviders, resolveResourceProvider } from './registry';

export const CORE_RESOURCE_PROVIDER_ID = 'org.substore.core';
export const CORE_RESOURCE_REPRESENTATION = 'substore-nodes-json';

let defaultResourceBroker = null;

function storedItems(store, key) {
    const value = store.read(key);
    if (Array.isArray(value)) return value;
    if (value && typeof value === 'object') return Object.values(value);
    return [];
}

function findStoredItem(store, key, id) {
    return storedItems(store, key).find((item) => item?.name === id) || null;
}

function coreSource({ id, type, contract, storageKey, store }) {
    return {
        providerId: CORE_RESOURCE_PROVIDER_ID,
        providerContributionId: id,
        source: {
            id,
            type,
            contract,
            representations: [CORE_RESOURCE_REPRESENTATION],
            list() {
                return storedItems(store, storageKey).map((item) => ({
                    id: item.name,
                    name: item.name,
                    displayName: item.displayName || item.name,
                    revision: item.revision,
                    updatedAt: item.updated,
                    lifecycle: { state: 'active' },
                }));
            },
            get(resourceId) {
                const item = findStoredItem(store, storageKey, resourceId);
                if (!item) return null;
                return {
                    id: item.name,
                    name: item.name,
                    displayName: item.displayName || item.name,
                    revision: item.revision,
                    updatedAt: item.updated,
                    lifecycle: { state: 'active' },
                };
            },
            produce({ id: resourceId, produceBuiltinArtifact }) {
                return produceBuiltinArtifact({
                    type,
                    name: resourceId,
                    platform: 'JSON',
                    produceType: 'internal',
                    noFlow: true,
                });
            },
        },
        core: true,
    };
}

export function createCoreResourceProviders({ store }) {
    return [
        coreSource({
            id: 'org.substore.core.subscriptions',
            type: 'subscription',
            contract: 'substore.subscription@1',
            storageKey: SUBS_KEY,
            store,
        }),
        coreSource({
            id: 'org.substore.core.collections',
            type: 'collection',
            contract: 'substore.collection@1',
            storageKey: COLLECTIONS_KEY,
            store,
        }),
    ];
}

function providerLifecycleError(manager, providerId) {
    const availability = manager?.getAvailability?.(providerId) || {
        status: 'missing',
        extensionId: providerId,
    };
    if (availability.status === 'enabled') return null;
    if (['installing', 'updating', 'restoring'].includes(availability.status)) {
        return resourceError(
            'RESOURCE_PROVIDER_UPDATING',
            `Resource provider ${providerId} is updating`,
            { providerId, status: availability.status },
            409,
        );
    }
    if (availability.status === 'disabled') {
        return resourceError(
            'RESOURCE_PROVIDER_DISABLED',
            `Resource provider ${providerId} is disabled`,
            { providerId, status: availability.status },
            409,
        );
    }
    return resourceError(
        'RESOURCE_PROVIDER_NOT_INSTALLED',
        `Resource provider ${providerId} is not installed`,
        { providerId, status: availability.status },
        409,
    );
}

function descriptorFrom(provider, item) {
    return normalizeProviderResourceDescriptor(
        {
            providerId: provider.providerId,
            providerContributionId: provider.providerContributionId,
            type: provider.source.type,
            contract: provider.source.contract,
            representations: provider.source.representations,
        },
        item,
    );
}

function assertProviderContract(provider, ref) {
    if (provider.source.contract === ref.contract) return;
    throw resourceError(
        'RESOURCE_CONTRACT_INCOMPATIBLE',
        `Resource provider ${ref.providerId} does not support ${ref.contract}`,
        {
            providerId: ref.providerId,
            providerContributionId: ref.providerContributionId,
            requestedContract: ref.contract,
            supportedContracts: [provider.source.contract],
        },
        409,
    );
}

function assertRepresentation(provider, representation) {
    if (
        typeof representation === 'string' &&
        provider.source.representations.includes(representation)
    ) {
        return;
    }
    throw resourceError(
        'RESOURCE_REPRESENTATION_UNSUPPORTED',
        `Resource provider ${provider.providerId} does not support ${
            representation || 'the requested representation'
        }`,
        {
            providerId: provider.providerId,
            providerContributionId: provider.providerContributionId,
            requestedRepresentation: representation || null,
            supportedRepresentations: [...provider.source.representations],
        },
    );
}

export function createResourceBroker({
    manager,
    store,
    produceBuiltinArtifact,
    listProviders = listResourceProviders,
    resolveProvider = resolveResourceProvider,
}) {
    if (typeof produceBuiltinArtifact !== 'function') {
        throw new TypeError('Resource Broker requires the builtin producer');
    }
    const coreProviders = createCoreResourceProviders({ store });

    const allProviders = () => [...coreProviders, ...listProviders()];

    const resolve = (input) => {
        const ref = normalizeResourceRef(input);
        const coreProvider = coreProviders.find(
            (provider) =>
                provider.providerId === ref.providerId &&
                provider.providerContributionId ===
                    ref.providerContributionId &&
                provider.source.type === ref.type,
        );
        const provider = coreProvider || resolveProvider(ref);
        if (!provider) {
            const lifecycleError =
                ref.providerId === CORE_RESOURCE_PROVIDER_ID
                    ? null
                    : providerLifecycleError(manager, ref.providerId);
            if (lifecycleError) throw lifecycleError;
            throw resourceError(
                'RESOURCE_PROVIDER_NOT_INSTALLED',
                `Resource provider ${ref.providerId} is unavailable`,
                {
                    providerId: ref.providerId,
                    providerContributionId: ref.providerContributionId,
                    type: ref.type,
                },
                409,
            );
        }
        if (!provider.core) {
            const lifecycleError = providerLifecycleError(
                manager,
                provider.providerId,
            );
            if (lifecycleError) throw lifecycleError;
        }
        assertProviderContract(provider, ref);
        return { provider, ref };
    };

    const getDescriptor = async (input) => {
        const { provider, ref } = resolve(input);
        const item = await provider.source.get(ref.id);
        if (!item) {
            throw resourceError(
                'RESOURCE_NOT_FOUND',
                `Resource ${ref.id} does not exist`,
                {
                    providerId: ref.providerId,
                    providerContributionId: ref.providerContributionId,
                    type: ref.type,
                    id: ref.id,
                },
                404,
            );
        }
        return normalizeProviderResourceDescriptor(
            {
                providerId: provider.providerId,
                providerContributionId: provider.providerContributionId,
                type: provider.source.type,
                contract: provider.source.contract,
                representations: provider.source.representations,
            },
            item,
            { expectedRef: ref },
        );
    };

    return Object.freeze({
        async list({ types, contracts, providerIds } = {}) {
            const typeFilter = Array.isArray(types) ? new Set(types) : null;
            const contractFilter = Array.isArray(contracts)
                ? new Set(contracts)
                : null;
            const providerFilter = Array.isArray(providerIds)
                ? new Set(providerIds)
                : null;
            const descriptors = [];
            for (const provider of allProviders()) {
                if (typeFilter && !typeFilter.has(provider.source.type)) {
                    continue;
                }
                if (
                    contractFilter &&
                    !contractFilter.has(provider.source.contract)
                ) {
                    continue;
                }
                if (
                    providerFilter &&
                    !providerFilter.has(provider.providerId)
                ) {
                    continue;
                }
                if (!provider.core) {
                    const lifecycleError = providerLifecycleError(
                        manager,
                        provider.providerId,
                    );
                    if (lifecycleError) continue;
                }
                const items = await provider.source.list();
                if (!Array.isArray(items)) {
                    throw resourceError(
                        'RESOURCE_DESCRIPTOR_INVALID',
                        'Resource provider list result must be an array',
                        {
                            providerId: provider.providerId,
                            providerContributionId:
                                provider.providerContributionId,
                        },
                    );
                }
                items.forEach((item) => {
                    const descriptor = descriptorFrom(provider, item);
                    if (descriptor.lifecycle.state === 'active') {
                        descriptors.push(descriptor);
                    }
                });
            }
            return descriptors;
        },

        get: getDescriptor,

        async produce(input, options = {}) {
            const { provider, ref } = resolve(input);
            assertRepresentation(provider, options.representation);
            const descriptor = await getDescriptor(ref);
            const representationIndex = provider.source.representations.indexOf(
                options.representation,
            );
            const platform =
                options.target ||
                provider.source.platforms?.[representationIndex] ||
                options.representation;
            const result = await provider.source.produce({
                id: ref.id,
                name: ref.id,
                ref,
                descriptor,
                representation: options.representation,
                target: options.target,
                platform,
                freshnessPolicy: options.freshnessPolicy,
                produceBuiltinArtifact,
            });
            return normalizeResourceOutput(result, {
                ref,
                representation: options.representation,
                legacy: typeof result === 'string' || Array.isArray(result),
            });
        },
    });
}

export function setDefaultResourceBroker(resourceBroker) {
    defaultResourceBroker = resourceBroker || null;
    return defaultResourceBroker;
}

export function getDefaultResourceBroker() {
    return defaultResourceBroker;
}

export default createResourceBroker;

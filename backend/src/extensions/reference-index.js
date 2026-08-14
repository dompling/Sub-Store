import { EXTENSION_REFERENCE_INDEX_KEY } from '@/constants';
import {
    normalizeResourceRef,
    resourceError,
    resourceRefKey,
} from './resource-contracts';

const REFERENCE_INDEX_SCHEMA_VERSION = 1;

function emptyIndex() {
    return {
        schemaVersion: REFERENCE_INDEX_SCHEMA_VERSION,
        edges: [],
    };
}

function parseStoredIndex(value) {
    if (value == null || value === '') return emptyIndex();
    let parsed = value;
    if (typeof value === 'string') {
        try {
            parsed = JSON.parse(value);
        } catch (error) {
            throw resourceError(
                'REFERENCE_INDEX_CORRUPT',
                'The extension reference index contains invalid JSON',
                {},
                409,
            );
        }
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw resourceError(
            'REFERENCE_INDEX_CORRUPT',
            'The extension reference index is invalid',
            {},
            409,
        );
    }
    if (parsed.schemaVersion !== REFERENCE_INDEX_SCHEMA_VERSION) {
        throw resourceError(
            'REFERENCE_INDEX_SCHEMA_UNSUPPORTED',
            `Unsupported extension reference index schema: ${
                parsed.schemaVersion ?? 'missing'
            }`,
            { schemaVersion: parsed.schemaVersion ?? null },
            409,
        );
    }
    if (!Array.isArray(parsed.edges)) {
        throw resourceError(
            'REFERENCE_INDEX_CORRUPT',
            'The extension reference index edges are invalid',
            {},
            409,
        );
    }
    return {
        schemaVersion: REFERENCE_INDEX_SCHEMA_VERSION,
        edges: parsed.edges.map((edge) => {
            if (!edge || typeof edge !== 'object' || Array.isArray(edge)) {
                throw resourceError(
                    'REFERENCE_INDEX_CORRUPT',
                    'The extension reference index contains an invalid edge',
                    {},
                    409,
                );
            }
            return {
                owner: normalizeResourceRef(edge.owner),
                target: normalizeResourceRef(edge.target),
            };
        }),
    };
}

export function createExtensionReferenceIndex({ store }) {
    if (
        !store ||
        typeof store.read !== 'function' ||
        typeof store.write !== 'function'
    ) {
        throw new TypeError('Extension reference index requires a Host store');
    }

    const read = () =>
        parseStoredIndex(store.read(EXTENSION_REFERENCE_INDEX_KEY));

    return Object.freeze({
        replaceOwn({ owner, targets = [] } = {}) {
            const normalizedOwner = normalizeResourceRef(owner);
            if (!Array.isArray(targets)) {
                throw resourceError(
                    'RESOURCE_REF_INVALID',
                    'Reference targets must be an array',
                    { field: 'targets' },
                );
            }
            const current = read();
            const ownerKey = resourceRefKey(normalizedOwner);
            const uniqueTargets = new Map();
            targets.forEach((target) => {
                const normalized = normalizeResourceRef(target);
                uniqueTargets.set(resourceRefKey(normalized), normalized);
            });
            const edges = current.edges.filter(
                (edge) => resourceRefKey(edge.owner) !== ownerKey,
            );
            uniqueTargets.forEach((target) => {
                edges.push({ owner: normalizedOwner, target });
            });
            const next = {
                schemaVersion: REFERENCE_INDEX_SCHEMA_VERSION,
                edges,
            };
            store.write(JSON.stringify(next), EXTENSION_REFERENCE_INDEX_KEY);
            return {
                owner: normalizedOwner,
                targets: [...uniqueTargets.values()],
                updatedAt: Date.now(),
            };
        },

        listIncoming(ref) {
            const targetKey = resourceRefKey(ref);
            const incoming = new Map();
            read().edges.forEach((edge) => {
                if (resourceRefKey(edge.target) !== targetKey) return;
                incoming.set(resourceRefKey(edge.owner), edge);
            });
            return {
                available: true,
                items: [...incoming.values()],
            };
        },
    });
}

export default createExtensionReferenceIndex;

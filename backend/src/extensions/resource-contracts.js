export const RESOURCE_REF_SCHEMA = 'substore.resource-ref@1';
export const RESOURCE_DESCRIPTOR_SCHEMA = 'substore.resource-descriptor@1';
export const RESOURCE_OUTPUT_SCHEMA = 'substore.resource-output@1';
export const RESOURCE_DIAGNOSTIC_SCHEMA = 'substore.diagnostic@1';

const MAX_IDENTITY_FIELD_LENGTH = 512;
// eslint-disable-next-line no-control-regex
const CONTROL_CHARACTER_RE = /[\u0000-\u001f\u007f]/;
const CONTRACT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*@[1-9][0-9]*$/;

function clone(value) {
    if (value === undefined) return undefined;
    return JSON.parse(JSON.stringify(value));
}

export function resourceError(code, message, details = {}, statusCode = 400) {
    const error = new Error(message || code);
    error.code = code;
    error.details = details;
    error.statusCode = statusCode;
    return error;
}

function assertResourceString(value, field, { contract = false } = {}) {
    if (
        typeof value !== 'string' ||
        !value.trim() ||
        value.length > MAX_IDENTITY_FIELD_LENGTH ||
        CONTROL_CHARACTER_RE.test(value) ||
        (contract && !CONTRACT_RE.test(value))
    ) {
        throw resourceError(
            'RESOURCE_REF_INVALID',
            `Resource reference ${field} is invalid`,
            { field },
        );
    }
    return value;
}

export function normalizeResourceRef(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw resourceError(
            'RESOURCE_REF_INVALID',
            'Resource reference must be an object',
        );
    }
    if (input.schema !== RESOURCE_REF_SCHEMA) {
        throw resourceError(
            'RESOURCE_REF_INVALID',
            `Unsupported resource reference schema: ${
                input.schema || 'missing'
            }`,
            { field: 'schema' },
        );
    }
    return Object.freeze({
        schema: RESOURCE_REF_SCHEMA,
        providerId: assertResourceString(input.providerId, 'providerId'),
        providerContributionId: assertResourceString(
            input.providerContributionId,
            'providerContributionId',
        ),
        type: assertResourceString(input.type, 'type'),
        id: assertResourceString(input.id, 'id'),
        contract: assertResourceString(input.contract, 'contract', {
            contract: true,
        }),
    });
}

export function resourceRefKey(input) {
    const ref = normalizeResourceRef(input);
    return [
        ref.providerId,
        ref.providerContributionId,
        ref.type,
        ref.id,
        ref.contract,
    ].join('\u0000');
}

export function normalizeResourceDiagnostic(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource diagnostic must be an object',
        );
    }
    if (!['info', 'warning', 'error'].includes(input.severity)) {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource diagnostic severity is invalid',
        );
    }
    if (typeof input.code !== 'string' || !input.code.trim()) {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource diagnostic code is invalid',
        );
    }
    if (typeof input.message !== 'string' || !input.message.trim()) {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource diagnostic message is invalid',
        );
    }
    return {
        ...clone(input),
        schema: RESOURCE_DIAGNOSTIC_SCHEMA,
    };
}

export function normalizeResourceDescriptor(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
        throw resourceError(
            'RESOURCE_DESCRIPTOR_INVALID',
            'Resource descriptor must be an object',
        );
    }
    const ref = normalizeResourceRef(input.ref);
    const name =
        typeof input.name === 'string' && input.name.trim()
            ? input.name
            : ref.id;
    const contracts = Array.isArray(input.contracts)
        ? input.contracts
        : [ref.contract];
    const representations = Array.isArray(input.representations)
        ? input.representations
        : [];
    if (!contracts.includes(ref.contract)) {
        throw resourceError(
            'RESOURCE_DESCRIPTOR_INVALID',
            'Resource descriptor does not declare its reference contract',
            { contract: ref.contract },
        );
    }
    if (
        representations.length === 0 ||
        representations.some(
            (representation) =>
                typeof representation !== 'string' || !representation.trim(),
        )
    ) {
        throw resourceError(
            'RESOURCE_DESCRIPTOR_INVALID',
            'Resource descriptor representations are invalid',
        );
    }
    const lifecycleState = input.lifecycle?.state || 'active';
    if (!['active', 'archived'].includes(lifecycleState)) {
        throw resourceError(
            'RESOURCE_DESCRIPTOR_INVALID',
            'Resource descriptor lifecycle is invalid',
        );
    }
    const availabilityStatus = input.availability?.status || 'available';
    if (
        ![
            'available',
            'disabled',
            'missing',
            'incompatible',
            'updating',
        ].includes(availabilityStatus)
    ) {
        throw resourceError(
            'RESOURCE_DESCRIPTOR_INVALID',
            'Resource descriptor availability is invalid',
        );
    }
    return {
        ...clone(input),
        schema: RESOURCE_DESCRIPTOR_SCHEMA,
        ref,
        name,
        contracts: [...contracts],
        representations: [...representations],
        lifecycle: {
            ...clone(input.lifecycle || {}),
            state: lifecycleState,
        },
        availability: {
            ...clone(input.availability || {}),
            status: availabilityStatus,
        },
    };
}

export function normalizeResourceOutput(
    input,
    { ref, representation, legacy = false } = {},
) {
    const normalizedRef = normalizeResourceRef(ref || input?.ref);
    if (typeof representation !== 'string' || !representation.trim()) {
        throw resourceError(
            'RESOURCE_REPRESENTATION_UNSUPPORTED',
            'A concrete resource representation is required',
        );
    }
    if (typeof input === 'string' || Array.isArray(input)) {
        const body = typeof input === 'string' ? input : JSON.stringify(input);
        return {
            schema: RESOURCE_OUTPUT_SCHEMA,
            ref: normalizedRef,
            representation,
            body,
            mediaType:
                representation === 'substore-nodes-json'
                    ? 'application/json'
                    : 'text/plain',
            freshness: { state: 'fresh' },
            diagnostics: legacy ? [] : [],
        };
    }
    if (!input || typeof input !== 'object') {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource output must be a string or output envelope',
        );
    }
    const outputRepresentation = input.representation;
    if (
        typeof outputRepresentation !== 'string' ||
        !outputRepresentation.trim() ||
        outputRepresentation !== representation
    ) {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource output representation does not match the request',
            { requested: representation },
        );
    }
    if (typeof input.body !== 'string') {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource output body must be a string',
        );
    }
    const freshnessState = input.freshness?.state || 'fresh';
    if (!['fresh', 'stale'].includes(freshnessState)) {
        throw resourceError(
            'RESOURCE_OUTPUT_INVALID',
            'Resource output freshness state is invalid',
        );
    }
    return {
        ...clone(input),
        schema: RESOURCE_OUTPUT_SCHEMA,
        ref: normalizedRef,
        representation,
        mediaType:
            typeof input.mediaType === 'string' && input.mediaType.trim()
                ? input.mediaType
                : 'text/plain',
        freshness: {
            ...clone(input.freshness || {}),
            state: freshnessState,
        },
        diagnostics: (input.diagnostics || []).map(normalizeResourceDiagnostic),
    };
}

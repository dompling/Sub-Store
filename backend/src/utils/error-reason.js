const MAX_ERROR_REASON_LENGTH = 2000;
const SENSITIVE_DETAIL_KEY =
    /authorization|cookie|credential|password|private[-_]?key|public[-_]?key|secret|token/i;

function truncate(value) {
    const text = `${value || ''}`;
    return text.length > MAX_ERROR_REASON_LENGTH
        ? `${text.slice(0, MAX_ERROR_REASON_LENGTH)}…`
        : text;
}

function findErrorMessage(value, depth = 0, seen = new Set()) {
    if (typeof value === 'string') return value;
    if (!value || typeof value !== 'object' || depth > 3 || seen.has(value)) {
        return '';
    }
    seen.add(value);

    for (const key of ['message', 'reason']) {
        if (typeof value[key] === 'string' && value[key].trim()) {
            return value[key].trim();
        }
    }
    return findErrorMessage(value.error, depth + 1, seen);
}

function serializeErrorDetails(value) {
    if (value == null || value === '') return '';
    if (typeof value === 'string') return value;

    const seen = new WeakSet();
    try {
        return JSON.stringify(value, (key, current) => {
            if (key && SENSITIVE_DETAIL_KEY.test(key)) return '[REDACTED]';
            if (typeof current === 'bigint') return `${current}`;
            if (current && typeof current === 'object') {
                if (seen.has(current)) return '[Circular]';
                seen.add(current);
                if (current instanceof Error) {
                    return {
                        name: current.name,
                        code: current.code,
                        message: current.message,
                        details: current.details,
                    };
                }
            }
            return current;
        });
    } catch (error) {
        return '';
    }
}

export function formatErrorReason(error) {
    if (error == null) return 'Unknown error';
    if (typeof error === 'string') return truncate(error);

    const code =
        typeof error?.code === 'string' && error.code.trim()
            ? error.code.trim()
            : '';
    const message = findErrorMessage(error);
    const details = serializeErrorDetails(error?.details);
    const primary = [code, message].filter(Boolean).join(': ');
    const result = details
        ? `${primary || 'Structured error'}; Details: ${details}`
        : primary || serializeErrorDetails(error) || `${error}`;

    return truncate(result);
}

export default formatErrorReason;

export function resolveRuleBindingName(rule, ruleSet) {
    return `${rule?.name || ruleSet?.name || ''}`.trim();
}

export function inferRuleBindingName(source, fallback = '') {
    const text = `${source || ''}`.trim();
    if (!text) return `${fallback || ''}`.trim();
    if (!/^https?:\/\//i.test(text)) return text;

    try {
        const pathname = new URL(text).pathname;
        const filename = decodeURIComponent(pathname.split('/').pop() || '');
        const name = filename.replace(
            /\.(?:conf|ini|json|list|txt|ya?ml)$/i,
            '',
        );
        return name.trim() || `${fallback || ''}`.trim();
    } catch (_) {
        return `${fallback || ''}`.trim();
    }
}

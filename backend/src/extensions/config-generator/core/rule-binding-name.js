export function getExplicitRuleBindingName(rule) {
    return typeof rule?.name === 'string' ? rule.name.trim() : '';
}

export function resolveRuleBindingResourceName(rule, ruleSet) {
    return getExplicitRuleBindingName(rule) || `${ruleSet?.name || ''}`.trim();
}

// Preserve the original export for external extensions while keeping its
// resource-allocation semantics explicit inside the built-in generators.
export function resolveRuleBindingName(rule, ruleSet) {
    return resolveRuleBindingResourceName(rule, ruleSet);
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

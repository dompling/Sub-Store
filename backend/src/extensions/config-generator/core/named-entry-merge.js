export function mergeNamedEntries(
    existing = [],
    generated = [],
    getName,
    { replace = (_, next) => next, duplicate = () => undefined } = {},
) {
    const generatedByName = new Map();
    const generatedOrder = [];
    generated.forEach((entry) => {
        const name = getName(entry);
        if (name == null || generatedByName.has(name)) return;
        generatedByName.set(name, entry);
        generatedOrder.push(name);
    });

    const consumed = new Set();
    const merged = [];
    existing.forEach((entry) => {
        const name = getName(entry);
        if (name == null || !generatedByName.has(name)) {
            merged.push(entry);
            return;
        }
        if (consumed.has(name)) {
            const kept = duplicate(entry, name);
            if (kept !== undefined) merged.push(kept);
            return;
        }
        merged.push(replace(entry, generatedByName.get(name), name));
        consumed.add(name);
    });

    generatedOrder.forEach((name) => {
        if (consumed.has(name)) return;
        merged.push(generatedByName.get(name));
        consumed.add(name);
    });
    return merged;
}

function splitNamedLines(lines, getName) {
    const entries = [];
    let prefix = [];
    lines.forEach((line) => {
        const name = getName(line);
        if (name == null) {
            prefix.push(line);
            return;
        }
        entries.push({ name, lines: [...prefix, line] });
        prefix = [];
    });
    if (prefix.length) entries.push({ name: undefined, lines: prefix });
    return entries;
}

function defaultComment(line) {
    return /^\s*#/.test(line);
}

export function mergeNamedLines(
    existing = [],
    generated = [],
    getName,
    { isComment = defaultComment } = {},
) {
    const existingEntries = splitNamedLines(existing, getName);
    const generatedEntries = splitNamedLines(generated, getName);
    const existingNames = new Set(
        existingEntries
            .map((entry) => entry.name)
            .filter((name) => name != null),
    );
    const merged = mergeNamedEntries(
        existingEntries,
        generatedEntries,
        (entry) => entry.name,
        {
            replace(existingEntry, generatedEntry) {
                const existingPrefix = existingEntry.lines.slice(0, -1);
                const generatedComments = generatedEntry.lines
                    .slice(0, -1)
                    .filter(isComment)
                    .filter(
                        (line) =>
                            !existingPrefix.some(
                                (existingLine) => existingLine === line,
                            ),
                    );
                return {
                    name: generatedEntry.name,
                    lines: [
                        ...existingPrefix,
                        ...generatedComments,
                        generatedEntry.lines[generatedEntry.lines.length - 1],
                    ],
                };
            },
            duplicate: (existingEntry) => ({
                name: undefined,
                lines: existingEntry.lines.slice(0, -1),
            }),
        },
    );

    const lines = [];
    let appendedGenerated = false;
    merged.forEach((entry) => {
        const isNew = entry.name != null && !existingNames.has(entry.name);
        const firstLine = entry.lines[0];
        const lastLine = lines[lines.length - 1];
        if (
            isNew &&
            !appendedGenerated &&
            lastLine?.trim() &&
            firstLine?.trim()
        ) {
            lines.push('');
        }
        lines.push(...entry.lines);
        if (isNew) appendedGenerated = true;
    });
    return lines;
}

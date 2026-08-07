export function parseProfileSections(input = '') {
    const bom = input.startsWith('\uFEFF');
    const source = bom ? input.slice(1) : input;
    const newline = source.match(/\r\n|\n/)?.[0] || '\n';
    const lines = source.replace(/\r\n/g, '\n').split('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    const ast = { bom, newline, preamble: [], sections: [] };
    let current = null;
    lines.forEach((line, index) => {
        const match = line.match(/^\s*\[([^\]]+)\]\s*$/);
        if (match) {
            const normalizedName = match[1].trim().toLowerCase();
            if (
                ast.sections.some((section) => section.name === normalizedName)
            ) {
                const error = new Error(
                    `Duplicate section [${match[1].trim()}] at line ${
                        index + 1
                    }`,
                );
                error.code = 'DUPLICATE_SURGE_SECTION';
                throw error;
            }
            current = { title: line, name: normalizedName, body: [] };
            ast.sections.push(current);
        } else if (current) current.body.push(line);
        else ast.preamble.push(line);
    });
    return ast;
}

const ORDER = ['proxy', 'proxy group', 'rule'];

export function replaceManagedSections(ast, replacements) {
    const next = {
        ...ast,
        preamble: [...ast.preamble],
        sections: ast.sections.map((s) => ({ ...s, body: [...s.body] })),
    };
    const managed = Object.keys(replacements).map((name) => name.toLowerCase());
    const existingOrder = next.sections
        .filter((s) => managed.includes(s.name))
        .map((s) => ORDER.indexOf(s.name));
    if (
        existingOrder.some(
            (value, index) => index && value < existingOrder[index - 1],
        )
    ) {
        const error = new Error(
            'Managed Surge sections are out of canonical order',
        );
        error.code = 'INVALID_SURGE_SECTION_ORDER';
        throw error;
    }
    for (const canonical of ORDER) {
        if (!managed.includes(canonical)) continue;
        const body =
            replacements[canonical] ||
            replacements[
                Object.keys(replacements).find(
                    (key) => key.toLowerCase() === canonical,
                )
            ] ||
            [];
        const existing = next.sections.find(
            (section) => section.name === canonical,
        );
        if (existing) {
            existing.title = `[${canonical
                .split(' ')
                .map((part) => part[0].toUpperCase() + part.slice(1))
                .join(' ')}]`;
            existing.body = body;
            continue;
        }
        const order = ORDER.indexOf(canonical);
        let at = next.sections.findIndex(
            (section) =>
                managed.includes(section.name) &&
                ORDER.indexOf(section.name) > order,
        );
        if (at < 0) {
            let lastEarlier = -1;
            next.sections.forEach((section, index) => {
                if (
                    managed.includes(section.name) &&
                    ORDER.indexOf(section.name) < order
                )
                    lastEarlier = index;
            });
            at = lastEarlier >= 0 ? lastEarlier + 1 : next.sections.length;
        }
        next.sections.splice(at, 0, {
            title: `[${canonical
                .split(' ')
                .map((part) => part[0].toUpperCase() + part.slice(1))
                .join(' ')}]`,
            name: canonical,
            body,
        });
    }
    return next;
}

export function serializeProfileSections(ast) {
    const lines = [...ast.preamble];
    ast.sections.forEach((section) => {
        lines.push(section.title, ...section.body);
    });
    return `${ast.bom ? '\uFEFF' : ''}${lines
        .join(ast.newline)
        .replace(/(?:\r?\n)*$/, '')}${ast.newline}`;
}

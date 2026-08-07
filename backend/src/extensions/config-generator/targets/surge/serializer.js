export function parseSurgeCsv(line) {
    const values = [];
    let value = '';
    let quoted = false;
    for (let index = 0; index < line.length; index++) {
        const char = line[index];
        if (char === '"') {
            if (quoted && line[index + 1] === '"') {
                value += '"';
                index++;
            } else quoted = !quoted;
        } else if (char === ',' && !quoted) {
            values.push(value.trim());
            value = '';
        } else value += char;
    }
    if (quoted) throw new Error('Unterminated quoted Surge CSV value');
    values.push(value.trim());
    return values;
}

export function serializeSurgeCsvValue(value) {
    const text = `${value ?? ''}`;
    return /[,"\r\n]|^\s|\s$/.test(text)
        ? `"${text.replace(/"/g, '""')}"`
        : text;
}

export function serializeSurgeCsv(values) {
    return values.map(serializeSurgeCsvValue).join(', ');
}

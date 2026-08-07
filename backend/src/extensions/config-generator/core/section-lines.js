export function separateSectionBlocks(blocks = []) {
    const lines = [];
    blocks.forEach((block) => {
        const next = (Array.isArray(block) ? block : [block]).filter(
            (line) => line !== undefined && line !== null,
        );
        if (!next.length) return;
        if (lines.length && lines[lines.length - 1] !== '') lines.push('');
        lines.push(...next);
    });
    return lines;
}

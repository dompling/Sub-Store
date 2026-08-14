export function getUserAgentFromHeaders(headers) {
    const keys = Object.keys(headers);
    let UA = '';
    let ua = '';
    let accept = '';
    for (let k of keys) {
        const lower = k.toLowerCase();
        if (lower === 'user-agent') {
            UA = headers[k];
            ua = UA.toLowerCase();
        } else if (lower === 'accept') {
            accept = headers[k];
        }
    }
    return { UA, ua, accept };
}

export function resolvePlatformFromUserAgent({ ua, UA, accept }) {
    if (UA.indexOf('Quantumult%20X') !== -1) {
        return { value: 'QX', source: 'user-agent' };
    } else if (ua.indexOf('egern') !== -1) {
        return { value: 'Egern', source: 'user-agent' };
    } else if (UA.indexOf('Surfboard') !== -1) {
        return { value: 'Surfboard', source: 'user-agent' };
    } else if (UA.indexOf('Surge Mac') !== -1) {
        return { value: 'SurgeMac', source: 'user-agent' };
    } else if (UA.indexOf('Surge') !== -1) {
        return { value: 'Surge', source: 'user-agent' };
    } else if (UA.indexOf('Decar') !== -1 || UA.indexOf('Loon') !== -1) {
        return { value: 'Loon', source: 'user-agent' };
    } else if (UA.indexOf('Shadowrocket') !== -1) {
        return { value: 'Shadowrocket', source: 'user-agent' };
    } else if (UA.indexOf('Stash') !== -1) {
        return { value: 'Stash', source: 'user-agent' };
    } else if (
        ua === 'meta' ||
        (ua.indexOf('clash') !== -1 && ua.indexOf('meta') !== -1) ||
        ua.indexOf('clash-verge') !== -1 ||
        ua.indexOf('flclash') !== -1
    ) {
        return { value: 'ClashMeta', source: 'user-agent' };
    } else if (ua.indexOf('clash') !== -1) {
        return { value: 'Clash', source: 'user-agent' };
    } else if (ua.indexOf('v2ray') !== -1) {
        return { value: 'V2Ray', source: 'user-agent' };
    } else if (ua.indexOf('sing-box') !== -1 || ua.indexOf('singbox') !== -1) {
        return { value: 'sing-box', source: 'user-agent' };
    } else if (accept.indexOf('application/json') === 0) {
        return { value: 'JSON', source: 'accept' };
    } else {
        return { value: 'V2Ray', source: 'default' };
    }
}

export function getPlatformFromUserAgent(input) {
    return resolvePlatformFromUserAgent(input).value;
}

export function getPlatformFromHeaders(headers) {
    const { UA, ua, accept } = getUserAgentFromHeaders(headers);
    return getPlatformFromUserAgent({ ua, UA, accept });
}

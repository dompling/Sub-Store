import $ from '@/core/app';
import { CONFIG_GENERATOR_KEY } from '@/constants';
import { findByName } from '@/utils/database';

export function readConfigGeneratorStore() {
    const value = $.read(CONFIG_GENERATOR_KEY);
    return {
        version: 1,
        projects: Array.isArray(value?.projects) ? value.projects : [],
        ruleSets: Array.isArray(value?.ruleSets) ? value.ruleSets : [],
    };
}

export function writeConfigGeneratorStore(store) {
    const normalized = {
        version: 1,
        projects: store.projects || [],
        ruleSets: store.ruleSets || [],
    };
    $.write(normalized, CONFIG_GENERATOR_KEY);
    return normalized;
}

export function initializeConfigGeneratorStore() {
    if (!$.read(CONFIG_GENERATOR_KEY)) {
        writeConfigGeneratorStore({ projects: [], ruleSets: [] });
    }
}

export function getProject(name) {
    return findByName(readConfigGeneratorStore().projects, name);
}

export function getRuleSet(name) {
    return findByName(readConfigGeneratorStore().ruleSets, name);
}

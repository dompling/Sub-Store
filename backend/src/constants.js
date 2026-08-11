export const SCHEMA_VERSION_KEY = 'schemaVersion';
export const SETTINGS_KEY = 'settings';
export const SUBS_KEY = 'subs';
export const COLLECTIONS_KEY = 'collections';
export const FILES_KEY = 'files';
export const MODULES_KEY = 'modules';
export const ARTIFACTS_KEY = 'artifacts';
export const CONFIG_GENERATOR_KEY = 'configGenerator';
// Extension Host state lives in the root/global store so that Node and
// script-product invocations share lifecycle revisions and receipts. Global
// metadata is indexed separately from extension-owned lifecycle records so a
// single plugin update does not rewrite every installed plugin.
export const LEGACY_EXTENSIONS_KEY = '#sub-store-extensions';
export const EXTENSION_STATE_INDEX_KEY = '#sub-store-extension-index';
export const EXTENSION_RECORD_KEY_PREFIX = '#sub-store-extension:';
// Retain the historical import name for callers that only need the current
// lifecycle state identity. The legacy aggregate key is explicitly named
// above and is read only by the migration path.
export const EXTENSIONS_KEY = EXTENSION_STATE_INDEX_KEY;
export const EXTENSION_CATALOG_KEY = '#sub-store-extension-catalog';
export const EXTENSION_TASKS_KEY = '#sub-store-extension-tasks';
export const RULES_KEY = 'rules';
export const TOKENS_KEY = 'tokens';
export const ARCHIVES_KEY = 'archives';
export const GIST_BACKUP_KEY = 'Auto Generated Sub-Store Backup';
export const GIST_BACKUP_FILE_NAME = 'Sub-Store';
export const GIST_DOWNLOAD_TOKEN_STRATEGIES = ['ask', 'overwrite', 'keep'];
export const ARTIFACT_REPOSITORY_KEY = 'Sub-Store Artifacts Repository';
export const RESOURCE_CACHE_KEY = '#sub-store-cached-resource';
export const HEADERS_RESOURCE_CACHE_KEY = '#sub-store-cached-headers-resource';
export const SCRIPT_RESOURCE_CACHE_KEY = '#sub-store-cached-script-resource';
export const LOGS_KEY = '#sub-store-logs';
export const DEFAULT_CACHE_TTL = 60 * 60 * 1000; // 1 hour
export const DEFAULT_HEADERS_CACHE_TTL = 60 * 1000; // 1 min
export const DEFAULT_SCRIPT_CACHE_TTL = 48 * 3600 * 1000; // 48 hours
export const DEFAULT_LOGS_MAX_COUNT = 0;

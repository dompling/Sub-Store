/**
 * 路由拆分 - 本文件只包含不涉及到解析器的 RESTFul API
 */

import { version } from '../../package.json';
console.log(
    `
┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅
     Sub-Store -- v${version}
┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅
`,
);

import migrate from '@/utils/migration';
import express from '@/vendor/express';
import $ from '@/core/app';
import registerCollectionRoutes from '@/restful/collections';
import registerSubscriptionRoutes from '@/restful/subscriptions';
import registerArtifactRoutes from '@/restful/artifacts';
import registerSettingRoutes from '@/restful/settings';
import registerMiscRoutes from '@/restful/miscs';
import registerSortRoutes from '@/restful/sort';
import registerFileRoutes from '@/restful/file';
import registerTokenRoutes from '@/restful/token';
import registerArchiveRoutes from '@/restful/archives';
import registerModuleRoutes from '@/restful/module';
import registerLogRoutes from '@/restful/logs';
import registerAgeRoutes from '@/restful/age';
import registerExtensionControlRoutes from '@/restful/extensions';
import { registerExtensionRoutes } from '@/extensions/registry';
import { initializeExtensionHost } from '@/extensions/host';
import { registerEmbeddedConfigGenerator } from '@/extensions/embedded/config-generator';
import { loadBundledExtensions } from '@/extensions/bundled';
import { createConfigHostingRouteApps } from '@/extensions/config-hosting';

migrate();
serve();

function serve() {
    const $app = express({ substore: $ });
    const { manager: extensionManager } = initializeExtensionHost({
        registerEmbeddedExtensions: registerEmbeddedConfigGenerator,
    });
    loadBundledExtensions(extensionManager);

    // register routes
    registerExtensionRoutes($app, {
        extensionManager,
        executionLane: 'simple',
    });
    registerExtensionControlRoutes($app, extensionManager);
    const configHostingApps = createConfigHostingRouteApps(
        $app,
        extensionManager,
        'simple',
    );
    registerCollectionRoutes($app);
    registerSubscriptionRoutes($app);
    registerTokenRoutes($app);
    registerFileRoutes($app);
    registerModuleRoutes($app);
    registerArtifactRoutes(configHostingApps.legacy);
    registerArtifactRoutes(configHostingApps.canonical);
    registerSettingRoutes($app);
    registerSortRoutes(configHostingApps.legacy);
    registerSortRoutes(configHostingApps.canonical);
    registerArchiveRoutes($app);
    registerMiscRoutes($app);
    registerLogRoutes($app);
    registerAgeRoutes($app);

    $app.start();
}

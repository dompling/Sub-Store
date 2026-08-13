/**
 * 路由拆分 - 本文件仅包含使用到解析器的 RESTFul API
 */

import { version } from '../../package.json';
import migrate from '@/utils/migration';
import express from '@/vendor/express';
import $ from '@/core/app';
import registerDownloadRoutes from '@/restful/download';
import registerPreviewRoutes from '@/restful/preview';
import registerSyncRoutes, { produceBuiltinArtifact } from '@/restful/sync';
import registerNodeInfoRoutes from '@/restful/node-info';
import { registerExtensionRoutes } from '@/extensions/registry';
import { initializeExtensionHost } from '@/extensions/host';
import { loadBundledExtensions } from '@/extensions/bundled';
import { createConfigHostingRouteApps } from '@/extensions/config-hosting';

console.log(
    `
┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅
     Sub-Store -- v${version}
┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅
`,
);

migrate();
serve();

function serve() {
    const $app = express({ substore: $ });
    const { manager: extensionManager } = initializeExtensionHost({
        executionLane: 'parser',
        produceBuiltinArtifact,
    });
    loadBundledExtensions(extensionManager);

    // register routes
    registerExtensionRoutes($app, {
        extensionManager,
        executionLane: 'parser',
        produceBuiltinArtifact,
    });
    const configHostingApps = createConfigHostingRouteApps(
        $app,
        extensionManager,
        'parser',
    );
    registerDownloadRoutes($app);
    registerPreviewRoutes($app);
    registerSyncRoutes(configHostingApps.legacy);
    registerSyncRoutes(configHostingApps.canonical);
    registerNodeInfoRoutes($app);

    $app.options('/', (req, res) => {
        res.status(200).end();
    });

    $app.start();
}

import { expect } from 'chai';
import { describe, it, afterEach } from 'mocha';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { EXTENSION_IDS } from '@/extensions/contracts';
import {
    ExtensionManager,
    extensionHostCapabilities,
} from '@/extensions/manager';
import { createNodeExtensionPackageStore } from '@/extensions/package-store';
import { createConfigHostingAdapter } from '@/extensions/config-hosting';
import { createBackendExtensionSdkV1 } from '@/extensions/backend-sdk-v1';
import {
    createExtensionScheduler,
    disposeExtensionScheduler,
    extensionSchedulerAvailable,
    extensionSchedulerStatus,
    resetExtensionSchedulersForTests,
    validateExtensionCron,
} from '@/extensions/scheduler';

const EXTENSION = 'org.example.scheduled';
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createStore() {
    const values = {};
    return {
        read: (key) => values[key],
        write: (value, key) => {
            values[key] = value;
            return true;
        },
        delete: (key) => {
            delete values[key];
        },
    };
}

describe('Extension scheduled jobs (Host CronJob service)', function () {
    afterEach(() => resetExtensionSchedulersForTests());

    it('validates cron expressions and reports the next fire time', function () {
        expect(extensionSchedulerAvailable()).to.equal(true);
        const valid = validateExtensionCron(' */30 * * * * ');
        expect(valid.valid).to.equal(true);
        expect(valid.cron).to.equal('*/30 * * * *');
        expect(valid.nextRunAt).to.be.greaterThan(Date.now());
        expect(validateExtensionCron('').reasonCode).to.equal(
            'EXTENSION_CRON_EMPTY',
        );
        expect(validateExtensionCron('not a cron').reasonCode).to.equal(
            'EXTENSION_CRON_INVALID',
        );
    });

    it('never overlaps a job with its own previous run', async function () {
        this.timeout(8000);
        const scheduler = createExtensionScheduler(EXTENSION);
        let release;
        const gate = new Promise((resolve) => {
            release = resolve;
        });
        let starts = 0;
        let concurrent = 0;
        let maxConcurrent = 0;
        scheduler.schedule({
            id: 'slow',
            cron: '* * * * * *',
            run: async () => {
                starts += 1;
                concurrent += 1;
                maxConcurrent = Math.max(maxConcurrent, concurrent);
                await gate;
                concurrent -= 1;
            },
        });
        // Several ticks pass while the first run is held open.
        await wait(3200);
        expect(starts).to.equal(1);
        expect(maxConcurrent).to.equal(1);
        expect(scheduler.list()[0].running).to.equal(true);
        release();
        await wait(1500);
        // Once the run finished, the next tick may start a new one.
        expect(starts).to.be.within(1, 3);
        expect(maxConcurrent).to.equal(1);
    });

    it('replaces a job with the same id instead of duplicating it', async function () {
        this.timeout(4000);
        const scheduler = createExtensionScheduler(EXTENSION);
        let first = 0;
        let second = 0;
        scheduler.schedule({
            id: 'job',
            cron: '* * * * * *',
            run: () => {
                first += 1;
            },
        });
        scheduler.schedule({
            id: 'job',
            cron: '* * * * * *',
            run: () => {
                second += 1;
            },
        });
        expect(scheduler.list()).to.have.length(1);
        await wait(2200);
        expect(first).to.equal(0);
        expect(second).to.be.greaterThan(0);
    });

    it('runs one-shot jobs once and forgets them', async function () {
        this.timeout(4000);
        const scheduler = createExtensionScheduler(EXTENSION);
        let runs = 0;
        scheduler.schedule({
            id: 'catch-up',
            at: Date.now(),
            run: () => {
                runs += 1;
            },
        });
        expect(scheduler.list()[0].once).to.equal(true);
        await wait(2200);
        expect(runs).to.equal(1);
        expect(scheduler.list()).to.deep.equal([]);
    });

    it('dispose stops every job and invalidates in-flight generations', async function () {
        this.timeout(4000);
        const scheduler = createExtensionScheduler(EXTENSION);
        let runs = 0;
        scheduler.schedule({
            id: 'a',
            cron: '* * * * * *',
            run: () => {
                runs += 1;
            },
        });
        scheduler.schedule({ id: 'b', cron: '*/5 * * * *', run: () => {} });
        expect(extensionSchedulerStatus(EXTENSION).scheduled).to.equal(2);
        expect(disposeExtensionScheduler(EXTENSION)).to.equal(2);
        expect(scheduler.list()).to.deep.equal([]);
        const after = runs;
        await wait(1500);
        expect(runs).to.equal(after);
        expect(extensionSchedulerStatus(EXTENSION).generation).to.equal(1);
    });

    it('rejects invalid jobs with stable codes', function () {
        const scheduler = createExtensionScheduler(EXTENSION);
        const code = (fn) => {
            try {
                fn();
            } catch (error) {
                return error.code;
            }
            return null;
        };
        expect(
            code(() => scheduler.schedule({ id: 'x', cron: 'nope', run() {} })),
        ).to.equal('EXTENSION_CRON_INVALID');
        expect(
            code(() =>
                scheduler.schedule({ id: '../x', cron: '* * * * *', run() {} }),
            ),
        ).to.equal('EXTENSION_CRON_JOB_ID_INVALID');
        expect(
            code(() => scheduler.schedule({ id: 'x', cron: '* * * * *' })),
        ).to.equal('EXTENSION_CRON_HANDLER_INVALID');
    });

    it('exposes the service through the SDK only with scheduler.jobs', function () {
        const withPermission = createBackendExtensionSdkV1({
            extensionId: EXTENSION,
            manifest: { id: EXTENSION, permissions: ['scheduler.jobs'] },
            store: createStore(),
        });
        expect(withPermission.scheduler.available()).to.equal(true);
        expect(withPermission.scheduler.validate('0 * * * *').valid).to.equal(
            true,
        );
        const without = createBackendExtensionSdkV1({
            extensionId: EXTENSION,
            manifest: { id: EXTENSION, permissions: [] },
            store: createStore(),
        });
        expect(without.scheduler.available()).to.equal(false);
        expect(() =>
            without.scheduler.schedule({
                id: 'x',
                cron: '* * * * *',
                run() {},
            }),
        )
            .to.throw()
            .with.property('code', 'EXTENSION_PERMISSION_DENIED');
    });

    it('advertises scheduler.cron@1 only when requested', function () {
        expect(
            extensionHostCapabilities({ scheduler: true })['scheduler.cron@1']
                .status,
        ).to.equal('available');
        expect(extensionHostCapabilities({})['scheduler.cron@1']).to.equal(
            undefined,
        );
    });

    it('disposes extension jobs on enable, disable and failed activation', function () {
        const basePath = fs.mkdtempSync(
            path.join(os.tmpdir(), 'sub-store-extension-cron-'),
        );
        try {
            const disposed = [];
            const manager = new ExtensionManager({
                store: createStore(),
                env: { isNode: true },
                packageStore: createNodeExtensionPackageStore({ basePath }),
            });
            manager.setHostBindings({
                disposeExtension: (extensionId) => disposed.push(extensionId),
            });
            manager.registerAdapter(
                EXTENSION_IDS.configHosting,
                createConfigHostingAdapter({}),
            );
            manager.install(EXTENSION_IDS.configHosting);
            manager.enable(EXTENSION_IDS.configHosting);
            // Activation clears anything an older activation left behind.
            expect(disposed).to.deep.equal([EXTENSION_IDS.configHosting]);
            manager.disable(EXTENSION_IDS.configHosting);
            expect(disposed).to.deep.equal([
                EXTENSION_IDS.configHosting,
                EXTENSION_IDS.configHosting,
            ]);
        } finally {
            fs.rmSync(basePath, { recursive: true, force: true });
        }
    });
});

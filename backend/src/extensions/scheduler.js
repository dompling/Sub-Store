import $ from '@/core/app';

/**
 * Host-owned scheduled jobs for executable extensions.
 *
 * Modeled on `utils/artifact-cron.js`: every job is a `cron` CronJob, a job
 * never overlaps with its own previous invocation, and each extension owns a
 * generation counter so a job created by an older activation (or an older
 * package version) can never fire after the extension was deactivated,
 * disabled or upgraded. Extensions never create timers themselves; the Host
 * stops every job of an extension when it deactivates, even if the package
 * forgot to.
 *
 * Only the Node runtime has CronJob. Script runtimes (Surge, Loon, QX, Stash,
 * Shadowrocket, Egern) schedule through their own cron configuration instead,
 * so there the service reports itself as unavailable.
 */

const MAX_JOBS_PER_EXTENSION = 64;
const JOB_ID_RE = /^[A-Za-z0-9_.:-]{1,128}$/;

const registries = new Map();

function cronModule() {
    if (!$.env.isNode) return null;
    try {
        return eval(`require("cron")`);
    } catch (e) {
        return null;
    }
}

function schedulerError(code, message, statusCode = 400) {
    const error = new Error(message);
    error.code = code;
    error.statusCode = statusCode;
    return error;
}

export function extensionSchedulerAvailable() {
    return Boolean(cronModule()?.CronJob);
}

function toMillis(value) {
    if (!value) return null;
    if (typeof value.toMillis === 'function') return value.toMillis();
    if (value instanceof Date) return value.getTime();
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
}

/**
 * Validate a cron expression without scheduling anything. Returns the next
 * fire time so a UI can show when the job would run.
 */
export function validateExtensionCron(cron) {
    const expression = `${cron ?? ''}`.trim();
    if (!expression) {
        return { valid: false, reasonCode: 'EXTENSION_CRON_EMPTY' };
    }
    const module = cronModule();
    if (!module?.CronTime) {
        return { valid: false, reasonCode: 'EXTENSION_SCHEDULER_UNAVAILABLE' };
    }
    try {
        const time = new module.CronTime(expression);
        const upcoming = [].concat(time.sendAt(2)).map(toMillis);
        return {
            valid: true,
            cron: expression,
            nextRunAt: upcoming[0] ?? null,
            // Distance between the next two fires; callers use it as the
            // nominal period (e.g. to size cache lifetimes).
            periodMs:
                upcoming.length > 1 && upcoming[1] > upcoming[0]
                    ? upcoming[1] - upcoming[0]
                    : null,
        };
    } catch (e) {
        return {
            valid: false,
            reasonCode: 'EXTENSION_CRON_INVALID',
            message: `${e?.message ?? e}`.slice(0, 200),
        };
    }
}

function registryFor(extensionId) {
    let registry = registries.get(extensionId);
    if (!registry) {
        registry = { generation: 0, jobs: new Map(), running: new Set() };
        registries.set(extensionId, registry);
    }
    return registry;
}

function stopJob(entry) {
    try {
        entry.job.stop();
    } catch (error) {
        $.error(
            `[EXTENSION CRON] ${entry.extensionId} ${entry.id} stop error: ${
                error?.message ?? error
            }`,
        );
    }
}

async function fire(extensionId, entry) {
    const registry = registries.get(extensionId);
    const label = `[EXTENSION CRON] ${extensionId} ${entry.id} ${entry.label}`;
    if (
        !registry ||
        registry.generation !== entry.generation ||
        registry.jobs.get(entry.id) !== entry
    ) {
        $.info(`${label} skipped: job is no longer active`);
        return;
    }
    if (registry.running.has(entry.id)) {
        $.info(`${label} skipped: previous run is still running`);
        return;
    }
    registry.running.add(entry.id);
    try {
        $.info(`${label} started`);
        await entry.run();
        $.info(`${label} finished`);
    } catch (error) {
        $.error(`${label} error: ${error?.message ?? error}`);
    } finally {
        registry.running.delete(entry.id);
        if (entry.once && registry.jobs.get(entry.id) === entry) {
            registry.jobs.delete(entry.id);
        }
    }
}

function schedule(extensionId, { id, cron, at, run } = {}) {
    const module = cronModule();
    if (!module?.CronJob) {
        throw schedulerError(
            'EXTENSION_SCHEDULER_UNAVAILABLE',
            'Scheduled jobs are only available on the Node runtime',
            409,
        );
    }
    const jobId = `${id ?? ''}`;
    if (!JOB_ID_RE.test(jobId)) {
        throw schedulerError(
            'EXTENSION_CRON_JOB_ID_INVALID',
            'Job id is invalid',
        );
    }
    if (typeof run !== 'function') {
        throw schedulerError(
            'EXTENSION_CRON_HANDLER_INVALID',
            'Job handler must be a function',
        );
    }
    const once = at !== undefined && at !== null;
    let cronTime;
    let label;
    if (once) {
        const when = Number(at);
        if (!Number.isFinite(when)) {
            throw schedulerError(
                'EXTENSION_CRON_INVALID',
                'Job time is invalid',
            );
        }
        // A one-shot job in the past fires as soon as possible.
        cronTime = new Date(Math.max(Date.now() + 1000, when));
        label = `once@${cronTime.toISOString()}`;
    } else {
        const validation = validateExtensionCron(cron);
        if (!validation.valid) {
            throw schedulerError(
                validation.reasonCode,
                validation.message || 'Cron expression is invalid',
            );
        }
        cronTime = validation.cron;
        label = validation.cron;
    }
    const registry = registryFor(extensionId);
    const previous = registry.jobs.get(jobId);
    if (!previous && registry.jobs.size >= MAX_JOBS_PER_EXTENSION) {
        throw schedulerError(
            'EXTENSION_CRON_JOB_LIMIT',
            `An extension can own at most ${MAX_JOBS_PER_EXTENSION} jobs`,
            409,
        );
    }
    if (previous) stopJob(previous);
    const entry = {
        extensionId,
        id: jobId,
        label,
        once,
        run,
        generation: registry.generation,
        job: null,
    };
    entry.job = new module.CronJob(
        cronTime,
        () => fire(extensionId, entry),
        null,
        false,
    );
    registry.jobs.set(jobId, entry);
    entry.job.start();
    $.info(`[EXTENSION CRON] ${extensionId} ${jobId} ${label} scheduled`);
    return describe(entry);
}

function describe(entry) {
    let nextRunAt = null;
    try {
        nextRunAt = entry.job?.running ? toMillis(entry.job.nextDate()) : null;
    } catch (e) {
        nextRunAt = null;
    }
    const registry = registries.get(entry.extensionId);
    return {
        id: entry.id,
        cron: entry.once ? null : entry.label,
        once: entry.once,
        nextRunAt,
        running: Boolean(registry?.running.has(entry.id)),
    };
}

function unschedule(extensionId, id) {
    const registry = registries.get(extensionId);
    const entry = registry?.jobs.get(`${id ?? ''}`);
    if (!entry) return false;
    registry.jobs.delete(entry.id);
    stopJob(entry);
    return true;
}

function list(extensionId) {
    const registry = registries.get(extensionId);
    if (!registry) return [];
    return [...registry.jobs.values()].map(describe);
}

/**
 * Stop every job of an extension and invalidate anything still in flight.
 * Called by the Host on deactivate/disable/uninstall/upgrade and before a new
 * activation, so a package can never leave a job behind.
 */
export function disposeExtensionScheduler(extensionId) {
    const registry = registries.get(extensionId);
    if (!registry) return 0;
    registry.generation += 1;
    const stopped = registry.jobs.size;
    for (const entry of registry.jobs.values()) stopJob(entry);
    registry.jobs.clear();
    if (stopped) {
        $.info(`[EXTENSION CRON] ${extensionId} ${stopped} job(s) stopped`);
    }
    return stopped;
}

export function extensionSchedulerStatus(extensionId) {
    const registry = registries.get(extensionId);
    return {
        available: extensionSchedulerAvailable(),
        scheduled: registry?.jobs.size || 0,
        running: registry?.running.size || 0,
        generation: registry?.generation || 0,
    };
}

/**
 * Capability-scoped view handed to one extension through the backend SDK.
 */
export function createExtensionScheduler(extensionId) {
    return Object.freeze({
        available: () => extensionSchedulerAvailable(),
        validate: (cron) => validateExtensionCron(cron),
        schedule: (options) => schedule(extensionId, options),
        unschedule: (id) => unschedule(extensionId, id),
        list: () => list(extensionId),
        clear: () => disposeExtensionScheduler(extensionId),
        status: () => extensionSchedulerStatus(extensionId),
    });
}

export function resetExtensionSchedulersForTests() {
    for (const extensionId of [...registries.keys()]) {
        disposeExtensionScheduler(extensionId);
    }
    registries.clear();
}

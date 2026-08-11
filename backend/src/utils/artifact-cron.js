import $ from '@/core/app';
import { ARTIFACTS_KEY } from '@/constants';
import { RequestInvalidError } from '@/restful/errors';

const artifactCronJobs = new Map();
const runningArtifactCronNames = new Set();
let syncArtifactByName;
let artifactCronEnabled = false;
let artifactCronGeneration = 0;
let artifactCronActivationCheck = null;

function getArtifactCron(artifact) {
    const cron = artifact?.cron == null ? '' : `${artifact.cron}`.trim();
    return cron;
}

function hasArtifactCron(artifact) {
    return getArtifactCron(artifact).length > 0;
}

function getArtifactDisplayName(artifact) {
    const displayName = artifact?.displayName ?? artifact?.['display-name'];
    return displayName == null ? '' : `${displayName}`.trim();
}

function formatArtifactLogName(artifact) {
    if (!artifact || typeof artifact !== 'object') return `${artifact}`;

    const name = artifact.name == null ? '' : `${artifact.name}`;
    const displayName = getArtifactDisplayName(artifact);
    if (!displayName || displayName === name) return name;

    return `${name} (${displayName})`;
}

function shouldSyncArtifactInGlobalCron(artifact) {
    return !hasArtifactCron(artifact);
}

function validateArtifactCron(cron) {
    if (!cron || !$.env.isNode) return;

    try {
        const { CronTime } = eval(`require("cron")`);
        new CronTime(cron);
    } catch (e) {
        throw new RequestInvalidError(
            'INVALID_ARTIFACT_CRON',
            `Artifact cron ${cron} is invalid.`,
            `Reason: ${e.message ?? e}`,
        );
    }
}

function normalizeArtifactCron(artifact) {
    if (!artifact || typeof artifact !== 'object') return artifact;

    const cron = getArtifactCron(artifact);
    if (!cron) {
        delete artifact.cron;
        return artifact;
    }

    validateArtifactCron(cron);
    artifact.cron = cron;
    return artifact;
}

function stopScheduledArtifactCronInstances() {
    const errors = [];
    artifactCronJobs.forEach((job) => {
        try {
            job.stop();
        } catch (error) {
            errors.push(error);
        }
    });
    artifactCronJobs.clear();
    return errors;
}

function stopArtifactCronJobs() {
    artifactCronEnabled = false;
    artifactCronGeneration += 1;
    artifactCronActivationCheck = null;
    const errors = stopScheduledArtifactCronInstances();
    if (errors.length) {
        const error = new Error(
            'One or more artifact cron jobs failed to stop',
        );
        error.code = 'ARTIFACT_CRON_STOP_FAILED';
        error.causes = errors;
        throw error;
    }
}

async function runArtifactCron(name, logName, cron, gate = {}) {
    const activationCheck = gate.isActive || artifactCronActivationCheck;
    if (
        !artifactCronEnabled ||
        (gate.generation !== undefined &&
            gate.generation !== artifactCronGeneration) ||
        (activationCheck && activationCheck() !== true)
    ) {
        $.info(
            `[ARTIFACT CRON] ${logName} ${cron} skipped: extension is inactive`,
        );
        return;
    }
    if (runningArtifactCronNames.has(name)) {
        $.info(
            `[ARTIFACT CRON] ${logName} ${cron} skipped: previous run is still running`,
        );
        return;
    }

    runningArtifactCronNames.add(name);
    try {
        $.info(`[ARTIFACT CRON] ${logName} ${cron} started`);
        await syncArtifactByName(name);
        $.info(`[ARTIFACT CRON] ${logName} ${cron} finished`);
    } catch (e) {
        $.error(`[ARTIFACT CRON] ${logName} ${cron} error: ${e.message ?? e}`);
    } finally {
        runningArtifactCronNames.delete(name);
    }
}

function scheduleArtifactCron(artifact, gate) {
    const cron = getArtifactCron(artifact);
    const name = artifact.name;
    const logName = formatArtifactLogName(artifact);
    const { CronJob } = eval(`require("cron")`);

    try {
        const job = new CronJob(
            cron,
            async function () {
                await runArtifactCron(name, logName, cron, gate);
            },
            null,
            true,
        );
        artifactCronJobs.set(name, job);
        $.info(`[ARTIFACT CRON] ${logName} ${cron} scheduled`);
    } catch (e) {
        $.error(
            `[ARTIFACT CRON] ${logName} ${cron} schedule error: ${
                e.message ?? e
            }`,
        );
    }
}

function refreshArtifactCronJobs() {
    if (!$.env.isNode || !syncArtifactByName || !artifactCronEnabled) return;

    artifactCronGeneration += 1;
    const gate = {
        generation: artifactCronGeneration,
        isActive: artifactCronActivationCheck,
    };
    const stopErrors = stopScheduledArtifactCronInstances();
    stopErrors.forEach((error) => {
        $.error(
            `[ARTIFACT CRON] stale schedule stop error: ${
                error.message ?? error
            }`,
        );
    });

    const storedArtifacts = $.read(ARTIFACTS_KEY);
    const artifacts = Array.isArray(storedArtifacts) ? storedArtifacts : [];
    artifacts
        .filter((artifact) => artifact.sync && artifact.source)
        .filter(hasArtifactCron)
        .forEach((artifact) => scheduleArtifactCron(artifact, gate));
}

function startArtifactCronJobs(handler, { isActive } = {}) {
    if (!$.env.isNode) return;

    syncArtifactByName = handler;
    artifactCronActivationCheck =
        typeof isActive === 'function' ? isActive : null;
    artifactCronEnabled = true;
    refreshArtifactCronJobs();
}

function artifactCronStatus() {
    return {
        enabled: artifactCronEnabled,
        scheduled: artifactCronJobs.size,
        running: runningArtifactCronNames.size,
    };
}

export {
    formatArtifactLogName,
    getArtifactDisplayName,
    getArtifactCron,
    hasArtifactCron,
    normalizeArtifactCron,
    refreshArtifactCronJobs,
    runArtifactCron,
    shouldSyncArtifactInGlobalCron,
    startArtifactCronJobs,
    stopArtifactCronJobs,
    artifactCronStatus,
    validateArtifactCron,
};

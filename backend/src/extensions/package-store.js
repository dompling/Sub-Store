import { canonicalJson } from './contracts';
import {
    extensionPackageDigest,
    isSha256Digest,
    sha256Hex,
    verifyReceipt,
    verifySignedEnvelope,
} from './signature';
import { isCommunityContentPackage } from './sources';

const RESERVED_PACKAGE_FILES = new Set([
    'manifest.json',
    'receipt.json',
    'package.json',
    'active.json',
]);
export const MAX_PACKAGE_FILES = 128;
export const MAX_PACKAGE_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_PACKAGE_BYTES = 8 * 1024 * 1024;

function nodeModule(name) {
    try {
        if (eval('typeof process === "undefined"')) return null;
        return eval(`require("${name}")`);
    } catch (e) {
        return null;
    }
}

function nodeBasePath() {
    try {
        return eval('process.env.SUB_STORE_DATA_BASE_PATH') || '.';
    } catch (e) {
        return '.';
    }
}

function safeSegment(value, label) {
    const segment = `${value || ''}`;
    if (
        segment === '.' ||
        segment === '..' ||
        !/^[a-zA-Z0-9._@-]+$/.test(segment)
    ) {
        const error = new Error(`Invalid extension ${label}`);
        error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
        error.statusCode = 400;
        error.details = { label, value };
        throw error;
    }
    return segment;
}

function isContainedPath(path, root, candidate, { allowRoot = false } = {}) {
    const relative = path.relative(root, candidate);
    if (!relative) return allowRoot;
    return (
        relative !== '..' &&
        !relative.startsWith(`..${path.sep}`) &&
        !path.isAbsolute(relative)
    );
}

function listPackageFiles(fs, path, directory, current = directory) {
    const files = [];
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        const absolute = path.join(current, entry.name);
        const relative = path.relative(directory, absolute).replace(/\\/g, '/');
        if (entry.isSymbolicLink()) {
            const error = new Error(
                `Extension package contains a symbolic link: ${relative}`,
            );
            error.code = 'EXTENSION_PACKAGE_FILE_INVALID';
            error.statusCode = 409;
            throw error;
        }
        if (entry.isDirectory()) {
            files.push(...listPackageFiles(fs, path, directory, absolute));
        } else if (entry.isFile()) {
            files.push(relative);
        } else {
            const error = new Error(
                `Extension package contains a non-regular file: ${relative}`,
            );
            error.code = 'EXTENSION_PACKAGE_FILE_INVALID';
            error.statusCode = 409;
            throw error;
        }
    }
    return files.sort();
}

function safeRelativeFile(value) {
    const file = `${value || ''}`.replace(/\\/g, '/');
    if (
        !file ||
        file.startsWith('/') ||
        file.split('/').some((part) => !part || part === '.' || part === '..')
    ) {
        const error = new Error(`Invalid extension package file ${file}`);
        error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
        error.statusCode = 400;
        throw error;
    }
    return file;
}

function atomicWriteJson(fs, path, file, value) {
    const target = path.join(file.directory, file.name);
    const temporary = `${target}.tmp-${Date.now()}-${Math.random()
        .toString(36)
        .slice(2)}`;
    fs.writeFileSync(temporary, JSON.stringify(value, null, 2), 'utf8');
    fs.renameSync(temporary, target);
}

function packageEntrypoint(path, directory, receipt, payload) {
    const declared = receipt?.implementation?.entrypoint;
    if (!declared) return null;
    const relativeFile = safeRelativeFile(declared);
    if (
        !Object.prototype.hasOwnProperty.call(
            payload?.files || {},
            relativeFile,
        )
    ) {
        const error = new Error(
            'Extension package entrypoint is not part of the verified payload',
        );
        error.code = 'EXTENSION_ENTRYPOINT_UNVERIFIED';
        error.statusCode = 409;
        throw error;
    }
    return path.join(directory, relativeFile);
}

function implementationLaneProjection(manifest) {
    return Object.fromEntries(
        Object.entries(manifest?.scriptExecutionLanes || {}).map(
            ([laneId, lane]) => [
                laneId,
                {
                    product: lane.product,
                    implementationId: lane.implementationId,
                },
            ],
        ),
    );
}

export class NodeExtensionPackageStore {
    constructor({ basePath = nodeBasePath(), verificationOptions = {} } = {}) {
        this.fs = nodeModule('fs');
        this.path = nodeModule('path');
        this.basePath = basePath;
        this.verificationOptions = { ...verificationOptions };
        this.rootPath = this.path
            ? this.path.resolve(basePath, '.sub-store-extensions')
            : null;
    }

    get available() {
        return Boolean(this.fs && this.path && this.rootPath);
    }

    extensionRoot(extensionId) {
        return this.path.join(this.rootPath, safeSegment(extensionId, 'id'));
    }

    versionRoot(extensionId, version, packageDigest) {
        return this.path.join(
            this.extensionRoot(extensionId),
            'versions',
            safeSegment(version, 'version'),
            safeSegment(packageDigest, 'digest'),
        );
    }

    assertManagedExtensionRoot(extensionId) {
        const root = this.path.resolve(this.rootPath);
        const extensionRoot = this.path.resolve(
            this.extensionRoot(extensionId),
        );
        for (const directory of [root, extensionRoot]) {
            if (!this.fs.existsSync(directory)) {
                const error = new Error(
                    'Extension managed package root is unavailable',
                );
                error.code = 'EXTENSION_PACKAGE_MISSING';
                error.statusCode = 409;
                throw error;
            }
            const stat = this.fs.lstatSync(directory);
            if (!stat.isDirectory() || stat.isSymbolicLink()) {
                const error = new Error(
                    'Extension managed package root is not a regular directory',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
        }
        const realRoot = this.fs.realpathSync(root);
        const realExtensionRoot = this.fs.realpathSync(extensionRoot);
        if (!isContainedPath(this.path, realRoot, realExtensionRoot)) {
            const error = new Error(
                'Extension managed package root escaped its storage root',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        return { extensionRoot, realExtensionRoot };
    }

    assertNoSymlinkPath(root, candidate) {
        const relative = this.path.relative(root, candidate);
        if (!relative || !isContainedPath(this.path, root, candidate)) {
            const error = new Error(
                'Extension package path is outside its managed root',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        let current = root;
        for (const segment of relative.split(this.path.sep)) {
            current = this.path.join(current, segment);
            if (!this.fs.existsSync(current)) {
                const error = new Error(
                    'Extension package path is unavailable',
                );
                error.code = 'EXTENSION_PACKAGE_MISSING';
                error.statusCode = 409;
                throw error;
            }
            if (this.fs.lstatSync(current).isSymbolicLink()) {
                const error = new Error(
                    'Extension package path contains a symbolic link',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
        }
    }

    assertExistingOwnedDirectory(extensionId, directory) {
        const candidate = this.path.resolve(directory || '');
        if (!this.fs.existsSync(candidate)) {
            const error = new Error(
                'Extension package directory is unavailable',
            );
            error.code = 'EXTENSION_PACKAGE_MISSING';
            error.statusCode = 409;
            throw error;
        }
        const candidateStat = this.fs.lstatSync(candidate);
        if (!candidateStat.isDirectory() || candidateStat.isSymbolicLink()) {
            const error = new Error(
                'Extension package directory is not a regular directory',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        const { extensionRoot, realExtensionRoot } =
            this.assertManagedExtensionRoot(extensionId);
        const lexicalRoot = this.path.resolve(extensionRoot);
        const pathRoot = isContainedPath(this.path, lexicalRoot, candidate)
            ? lexicalRoot
            : isContainedPath(this.path, realExtensionRoot, candidate)
            ? realExtensionRoot
            : null;
        if (!pathRoot) {
            const error = new Error(
                'Extension package directory is outside its managed root',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        this.assertNoSymlinkPath(pathRoot, candidate);
        const realCandidate = this.fs.realpathSync(candidate);
        if (!isContainedPath(this.path, realExtensionRoot, realCandidate)) {
            const error = new Error(
                'Extension package directory escaped its managed root',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        return realCandidate;
    }

    setVerificationOptions(options = {}) {
        this.verificationOptions = { ...options };
    }

    validatePackageInput(
        packageInput,
        { allowCommunityContent = false, allowDigestOnly = false } = {},
    ) {
        const { manifest, receipt, payload, signature } = packageInput || {};
        const packageDigest = packageInput?.packageDigest;
        const selectedVariant = packageInput?.selectedVariant;
        const variant = manifest?.variants?.[selectedVariant];
        const expectedImplementation = variant
            ? {
                  id: variant.implementationId,
                  abi: variant.implementationAbi,
                  frontendAssetId: variant.frontendAssetId,
                  entrypoint: variant.entrypoint,
                  lanes: implementationLaneProjection(manifest),
                  containsExecutableCode:
                      variant.containsExecutableCode === true,
              }
            : null;
        const receiptVerification = verifyReceipt(receipt, manifest, {
            expectedVariant: selectedVariant,
            expectedPackageDigest: packageDigest,
            expectedImplementation,
        });
        if (
            !manifest ||
            !receipt ||
            !payload ||
            packageInput.schemaVersion !== 1 ||
            payload.schemaVersion !== packageInput.schemaVersion ||
            canonicalJson(payload.manifest || null) !==
                canonicalJson(manifest) ||
            payload.selectedVariant !== selectedVariant ||
            !variant ||
            canonicalJson(payload.variant || null) !== canonicalJson(variant) ||
            payload.containsExecutableCode !==
                (variant.containsExecutableCode === true) ||
            payload.containsInstallHook !== false ||
            !receiptVerification.valid ||
            !isSha256Digest(packageDigest) ||
            receipt.packageDigest !== packageDigest ||
            payload.packageDigest !== packageDigest ||
            extensionPackageDigest(payload) !== packageDigest ||
            canonicalJson(payload.receipt) !== canonicalJson(receipt)
        ) {
            const error = new Error(
                'Extension package digest/receipt closure is invalid',
            );
            error.code =
                receiptVerification.reasonCode ||
                'EXTENSION_PACKAGE_DIGEST_INVALID';
            error.statusCode = 409;
            throw error;
        }
        const files = payload.files || {};
        const fileDigests = payload.fileDigests || {};
        const fileNames = Object.keys(files).sort();
        const digestNames = Object.keys(fileDigests).sort();
        if (
            canonicalJson(fileNames) !== canonicalJson(digestNames) ||
            fileNames.length > MAX_PACKAGE_FILES
        ) {
            const error = new Error(
                'Extension package file digest map is incomplete',
            );
            error.code = 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH';
            error.statusCode = 409;
            throw error;
        }
        let totalBytes = 0;
        for (const relativeName of fileNames) {
            safeRelativeFile(relativeName);
            const content = files[relativeName];
            const byteLength =
                typeof content === 'string'
                    ? Buffer.byteLength(content, 'utf8')
                    : Number.POSITIVE_INFINITY;
            totalBytes += byteLength;
            if (
                typeof content !== 'string' ||
                byteLength > MAX_PACKAGE_FILE_BYTES ||
                totalBytes > MAX_PACKAGE_BYTES ||
                !isSha256Digest(fileDigests[relativeName]) ||
                sha256Hex(content) !== fileDigests[relativeName]
            ) {
                const error = new Error(
                    `Extension package file failed verification: ${relativeName}`,
                );
                error.code = 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH';
                error.statusCode = 409;
                throw error;
            }
        }
        const communityContent =
            allowCommunityContent && isCommunityContentPackage(packageInput);
        const envelopeResult = verifySignedEnvelope(
            { payload, signature },
            communityContent || allowDigestOnly
                ? { ...this.verificationOptions, allowDigestOnly: true }
                : this.verificationOptions,
        );
        if (!envelopeResult.valid) {
            const error = new Error(
                'Extension package signature verification failed',
            );
            error.code =
                envelopeResult.reasonCode ||
                'EXTENSION_PACKAGE_SIGNATURE_INVALID';
            error.statusCode = 409;
            error.details = envelopeResult;
            throw error;
        }
        return {
            packageDigest,
            payloadDigest: envelopeResult.digest,
            files,
            fileDigests,
        };
    }

    verifyDirectory(directory, packageInput, options = {}) {
        const { manifest, receipt, payload } = packageInput;
        const verifiedInput = this.validatePackageInput(packageInput, options);
        const ownedDirectory = this.assertExistingOwnedDirectory(
            manifest.id,
            directory,
        );
        const expectedFiles = Object.keys(payload?.files || {}).sort();
        const actualFiles = listPackageFiles(
            this.fs,
            this.path,
            ownedDirectory,
        );
        const expectedStoredFiles = [
            ...expectedFiles,
            'manifest.json',
            'package.json',
            'receipt.json',
        ].sort();
        if (canonicalJson(actualFiles) !== canonicalJson(expectedStoredFiles)) {
            const error = new Error(
                'Extension package contains unverified files',
            );
            error.code = 'EXTENSION_PACKAGE_UNEXPECTED_FILE';
            error.statusCode = 409;
            error.details = { expectedFiles: expectedStoredFiles, actualFiles };
            throw error;
        }
        for (const [relativeName, content] of Object.entries(
            payload?.files || {},
        )) {
            const relativeFile = safeRelativeFile(relativeName);
            const target = this.path.resolve(ownedDirectory, relativeFile);
            if (!isContainedPath(this.path, ownedDirectory, target)) {
                const error = new Error(
                    'Extension package file escaped its managed directory',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
            const stat = this.fs.lstatSync(target);
            if (!stat.isFile() || stat.isSymbolicLink()) {
                const error = new Error(
                    `Extension package file is not a regular file: ${relativeName}`,
                );
                error.code = 'EXTENSION_PACKAGE_FILE_INVALID';
                error.statusCode = 409;
                throw error;
            }
            const actualPath = this.fs.realpathSync(target);
            if (!isContainedPath(this.path, ownedDirectory, actualPath)) {
                const error = new Error(
                    'Extension package file escaped its managed directory',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
            const expectedDigest = payload?.fileDigests?.[relativeName];
            const actualContent = this.fs.readFileSync(actualPath, 'utf8');
            if (
                !expectedDigest ||
                sha256Hex(actualContent) !== expectedDigest ||
                sha256Hex(`${content}`) !== expectedDigest
            ) {
                const error = new Error(
                    `Extension package file digest mismatch: ${relativeName}`,
                );
                error.code = 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH';
                error.statusCode = 409;
                throw error;
            }
        }

        const storedManifest = JSON.parse(
            this.fs.readFileSync(
                this.path.join(ownedDirectory, 'manifest.json'),
                'utf8',
            ),
        );
        const storedReceipt = JSON.parse(
            this.fs.readFileSync(
                this.path.join(ownedDirectory, 'receipt.json'),
                'utf8',
            ),
        );
        const storedPackage = JSON.parse(
            this.fs.readFileSync(
                this.path.join(ownedDirectory, 'package.json'),
                'utf8',
            ),
        );
        if (
            canonicalJson(storedManifest) !== canonicalJson(manifest) ||
            canonicalJson(storedReceipt) !== canonicalJson(receipt) ||
            storedPackage.packageDigest !== verifiedInput.packageDigest ||
            storedPackage.payloadDigest !== verifiedInput.payloadDigest ||
            storedPackage.selectedVariant !== packageInput.selectedVariant ||
            canonicalJson(storedPackage.variant || {}) !==
                canonicalJson(payload?.variant || {}) ||
            storedPackage.containsExecutableCode !==
                (payload?.containsExecutableCode === true) ||
            storedPackage.containsInstallHook !==
                (payload?.containsInstallHook === true) ||
            canonicalJson(storedPackage.fileDigests || {}) !==
                canonicalJson(payload?.fileDigests || {}) ||
            canonicalJson(storedPackage.signature || {}) !==
                canonicalJson(packageInput.signature || {})
        ) {
            const error = new Error(
                'Stored extension package metadata failed verification',
            );
            error.code = 'EXTENSION_PACKAGE_METADATA_MISMATCH';
            error.statusCode = 409;
            throw error;
        }

        return {
            directory: ownedDirectory,
            entrypoint: packageEntrypoint(
                this.path,
                ownedDirectory,
                receipt,
                payload,
            ),
        };
    }

    stage(packageInput, options = {}) {
        if (!this.available) return null;
        const verifiedInput = this.validatePackageInput(packageInput, options);
        const { manifest, receipt, payload } = packageInput || {};
        const extensionId = manifest?.id;
        const version = manifest?.version;
        const packageDigest = verifiedInput.packageDigest;
        if (!extensionId || !version || !packageDigest) {
            const error = new Error('Extension package metadata is incomplete');
            error.code = 'EXTENSION_PACKAGE_INVALID';
            error.statusCode = 400;
            throw error;
        }

        const finalDirectory = this.versionRoot(
            extensionId,
            version,
            packageDigest,
        );
        if (this.fs.existsSync(finalDirectory)) {
            return this.verifyDirectory(finalDirectory, packageInput, options);
        }

        const parent = this.path.dirname(finalDirectory);
        this.fs.mkdirSync(parent, { recursive: true });
        const { extensionRoot } = this.assertManagedExtensionRoot(extensionId);
        this.assertNoSymlinkPath(extensionRoot, parent);
        const stagingDirectory = `${finalDirectory}.staging-${Date.now()}-${Math.random()
            .toString(36)
            .slice(2)}`;
        this.fs.mkdirSync(stagingDirectory, { recursive: true });

        try {
            const files = payload?.files || {};
            for (const [relativeName, content] of Object.entries(files)) {
                const relativeFile = safeRelativeFile(relativeName);
                if (RESERVED_PACKAGE_FILES.has(relativeFile.toLowerCase())) {
                    const error = new Error(
                        `Extension payload cannot replace Host metadata: ${relativeName}`,
                    );
                    error.code = 'EXTENSION_PACKAGE_FILE_RESERVED';
                    error.statusCode = 400;
                    throw error;
                }
                const target = this.path.resolve(
                    stagingDirectory,
                    relativeFile,
                );
                if (!isContainedPath(this.path, stagingDirectory, target)) {
                    const error = new Error(
                        'Extension package escaped staging directory',
                    );
                    error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                    throw error;
                }
                const expectedDigest = payload?.fileDigests?.[relativeName];
                const actualDigest = sha256Hex(`${content}`);
                if (!expectedDigest || actualDigest !== expectedDigest) {
                    const error = new Error(
                        `Extension package file digest mismatch: ${relativeName}`,
                    );
                    error.code = 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH';
                    error.statusCode = 409;
                    throw error;
                }
                this.fs.mkdirSync(this.path.dirname(target), {
                    recursive: true,
                });
                this.fs.writeFileSync(target, `${content}`, 'utf8');
            }

            this.fs.writeFileSync(
                this.path.join(stagingDirectory, 'manifest.json'),
                JSON.stringify(manifest, null, 2),
                'utf8',
            );
            this.fs.writeFileSync(
                this.path.join(stagingDirectory, 'receipt.json'),
                JSON.stringify(receipt, null, 2),
                'utf8',
            );
            this.fs.writeFileSync(
                this.path.join(stagingDirectory, 'package.json'),
                JSON.stringify(
                    {
                        schemaVersion: packageInput.schemaVersion,
                        source: packageInput.source,
                        packageDigest,
                        payloadDigest: verifiedInput.payloadDigest,
                        selectedVariant: packageInput.selectedVariant,
                        variant: payload?.variant || {},
                        containsExecutableCode:
                            payload?.containsExecutableCode === true,
                        containsInstallHook:
                            payload?.containsInstallHook === true,
                        fileDigests: payload?.fileDigests || {},
                        signature: packageInput.signature || null,
                    },
                    null,
                    2,
                ),
                'utf8',
            );
            this.fs.renameSync(stagingDirectory, finalDirectory);
        } catch (error) {
            this.fs.rmSync(stagingDirectory, { recursive: true, force: true });
            if (this.fs.existsSync(finalDirectory)) {
                return this.verifyDirectory(
                    finalDirectory,
                    packageInput,
                    options,
                );
            }
            throw error;
        }

        return this.verifyDirectory(finalDirectory, packageInput, options);
    }

    activate(record) {
        if (!this.available || !record?.packageDirectory) return null;
        const runtimeModule = this.load(record);
        this.commitActive(record);
        return runtimeModule;
    }

    commitActive(record) {
        if (!this.available || !record?.packageDirectory) return;
        const root = this.extensionRoot(record.extensionId);
        this.fs.mkdirSync(root, { recursive: true });
        this.assertManagedExtensionRoot(record.extensionId);
        atomicWriteJson(
            this.fs,
            this.path,
            {
                directory: root,
                name: 'active.json',
            },
            {
                extensionId: record.extensionId,
                version: record.version,
                packageDigest: record.packageDigest,
                packageDirectory: record.packageDirectory,
                entrypoint: record.entrypoint || null,
                activatedAt: Date.now(),
            },
        );
    }

    evictRequireCache(directory) {
        if (!this.available || !directory) return;
        const requireModule = eval('require');
        const root = this.fs.existsSync(directory)
            ? this.fs.realpathSync(directory)
            : this.path.resolve(directory);
        for (const cachedPath of Object.keys(requireModule.cache || {})) {
            const resolved = this.fs.existsSync(cachedPath)
                ? this.fs.realpathSync(cachedPath)
                : this.path.resolve(cachedPath);
            if (
                resolved === root ||
                isContainedPath(this.path, root, resolved)
            ) {
                delete requireModule.cache[cachedPath];
            }
        }
    }

    verifyInstalledRecord(record) {
        if (!record?.entrypoint || !this.available) return null;
        const allowDigestOnly =
            record.verificationMode === 'source-integrity' ||
            record.verificationMode === 'local-integrity';
        if (
            !isSha256Digest(record.packageDigest) ||
            !isSha256Digest(record.manifestDigest) ||
            !isSha256Digest(record.receiptDigest) ||
            !isSha256Digest(record.payloadDigest)
        ) {
            const error = new Error(
                'Installed extension state contains invalid digests',
            );
            error.code = 'EXTENSION_PACKAGE_STATE_MISMATCH';
            error.statusCode = 409;
            throw error;
        }
        const packageDirectory = this.assertExistingOwnedDirectory(
            record.extensionId,
            record.packageDirectory,
        );
        const expectedDirectory = this.versionRoot(
            record.extensionId,
            record.version,
            record.packageDigest,
        );
        if (
            !this.fs.existsSync(expectedDirectory) ||
            this.fs.realpathSync(expectedDirectory) !== packageDirectory
        ) {
            const error = new Error(
                'Installed extension package path does not match its receipt',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        const manifest = JSON.parse(
            this.fs.readFileSync(
                this.path.join(packageDirectory, 'manifest.json'),
                'utf8',
            ),
        );
        const receipt = JSON.parse(
            this.fs.readFileSync(
                this.path.join(packageDirectory, 'receipt.json'),
                'utf8',
            ),
        );
        const packageMetadata = JSON.parse(
            this.fs.readFileSync(
                this.path.join(packageDirectory, 'package.json'),
                'utf8',
            ),
        );
        const receiptVerification = verifyReceipt(receipt, manifest, {
            expectedVariant: record.selectedVariant,
            expectedPackageDigest: record.packageDigest,
            expectedImplementation: record.implementation || {},
        });
        if (
            !receiptVerification.valid ||
            receipt.manifestDigest !== record.manifestDigest ||
            receipt.packageDigest !== record.packageDigest ||
            receipt.receiptDigest !== record.receiptDigest ||
            packageMetadata.packageDigest !== record.packageDigest ||
            packageMetadata.payloadDigest !== record.payloadDigest ||
            packageMetadata.selectedVariant !== record.selectedVariant ||
            canonicalJson(packageMetadata.fileDigests || {}) !==
                canonicalJson(record.fileDigests || {})
        ) {
            const error = new Error(
                'Installed extension receipt no longer matches active state',
            );
            error.code =
                receiptVerification.reasonCode ||
                'EXTENSION_PACKAGE_STATE_MISMATCH';
            error.statusCode = 409;
            throw error;
        }
        const expectedPayloadFiles = Object.keys(
            packageMetadata.fileDigests || {},
        ).sort();
        const actualFiles = listPackageFiles(
            this.fs,
            this.path,
            packageDirectory,
        );
        const expectedStoredFiles = [
            ...expectedPayloadFiles,
            'manifest.json',
            'package.json',
            'receipt.json',
        ].sort();
        if (canonicalJson(actualFiles) !== canonicalJson(expectedStoredFiles)) {
            const error = new Error(
                'Installed extension package contains unverified files',
            );
            error.code = 'EXTENSION_PACKAGE_UNEXPECTED_FILE';
            error.statusCode = 409;
            throw error;
        }
        const files = {};
        for (const [relativeName, expectedDigest] of Object.entries(
            packageMetadata.fileDigests || {},
        )) {
            const relativeFile = safeRelativeFile(relativeName);
            const candidate = this.path.resolve(packageDirectory, relativeFile);
            if (!isContainedPath(this.path, packageDirectory, candidate)) {
                const error = new Error(
                    'Installed extension file escaped its package root',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
            const lexicalStat = this.fs.lstatSync(candidate);
            if (!lexicalStat.isFile() || lexicalStat.isSymbolicLink()) {
                const error = new Error(
                    `Installed extension file is not regular: ${relativeName}`,
                );
                error.code = 'EXTENSION_PACKAGE_FILE_INVALID';
                error.statusCode = 409;
                throw error;
            }
            const actualPath = this.fs.realpathSync(candidate);
            const stat = this.fs.lstatSync(actualPath);
            const content = this.fs.readFileSync(actualPath, 'utf8');
            if (
                !isContainedPath(this.path, packageDirectory, actualPath) ||
                !stat.isFile() ||
                stat.isSymbolicLink() ||
                !isSha256Digest(expectedDigest) ||
                sha256Hex(content) !== expectedDigest
            ) {
                const error = new Error(
                    `Installed extension file failed verification: ${relativeName}`,
                );
                error.code = 'EXTENSION_PACKAGE_FILE_DIGEST_MISMATCH';
                error.statusCode = 409;
                throw error;
            }
            files[relativeName] = content;
        }
        const reconstructedPayload = {
            schemaVersion: packageMetadata.schemaVersion,
            manifest,
            selectedVariant: packageMetadata.selectedVariant,
            variant: packageMetadata.variant || {},
            containsExecutableCode:
                packageMetadata.containsExecutableCode === true,
            containsInstallHook: packageMetadata.containsInstallHook === true,
            files,
            fileDigests: packageMetadata.fileDigests || {},
            packageDigest: packageMetadata.packageDigest,
            receipt,
        };
        const envelopeResult = verifySignedEnvelope(
            {
                payload: reconstructedPayload,
                signature: packageMetadata.signature,
            },
            allowDigestOnly
                ? { ...this.verificationOptions, allowDigestOnly: true }
                : this.verificationOptions,
        );
        if (
            !envelopeResult.valid ||
            envelopeResult.digest !== record.payloadDigest ||
            extensionPackageDigest(reconstructedPayload) !==
                record.packageDigest
        ) {
            const error = new Error(
                'Installed extension package authenticity verification failed',
            );
            error.code =
                envelopeResult.reasonCode ||
                'EXTENSION_PACKAGE_SIGNATURE_INVALID';
            error.statusCode = 409;
            throw error;
        }
        const declaredEntrypoint = receipt.implementation?.entrypoint;
        const relativeEntrypoint = safeRelativeFile(declaredEntrypoint);
        if (
            !Object.prototype.hasOwnProperty.call(
                packageMetadata.fileDigests || {},
                relativeEntrypoint,
            )
        ) {
            const error = new Error(
                'Extension package entrypoint is not digest-bound',
            );
            error.code = 'EXTENSION_ENTRYPOINT_UNVERIFIED';
            error.statusCode = 409;
            throw error;
        }
        const expectedEntrypoint = this.path.resolve(
            packageDirectory,
            relativeEntrypoint,
        );
        const resolvedEntrypoint = this.path.resolve(record.entrypoint);
        if (resolvedEntrypoint !== expectedEntrypoint) {
            const error = new Error(
                'Extension package entrypoint does not match its receipt',
            );
            error.code = 'EXTENSION_ENTRYPOINT_UNVERIFIED';
            error.statusCode = 409;
            throw error;
        }
        if (!this.fs.existsSync(resolvedEntrypoint)) {
            const error = new Error(
                'Extension package entrypoint is unavailable',
            );
            error.code = 'EXTENSION_ENTRYPOINT_MISSING';
            error.statusCode = 409;
            throw error;
        }
        const entrypoint = this.fs.realpathSync(resolvedEntrypoint);
        if (!isContainedPath(this.path, packageDirectory, entrypoint)) {
            const error = new Error(
                'Extension package entrypoint is unavailable',
            );
            error.code = 'EXTENSION_ENTRYPOINT_MISSING';
            error.statusCode = 409;
            throw error;
        }
        const lexicalEntrypointStat = this.fs.lstatSync(resolvedEntrypoint);
        const stat = this.fs.lstatSync(entrypoint);
        if (
            !lexicalEntrypointStat.isFile() ||
            lexicalEntrypointStat.isSymbolicLink() ||
            !stat.isFile() ||
            stat.isSymbolicLink()
        ) {
            const error = new Error(
                'Extension package entrypoint is not a regular file',
            );
            error.code = 'EXTENSION_ENTRYPOINT_INVALID';
            error.statusCode = 409;
            throw error;
        }
        return {
            packageDirectory,
            entrypoint,
            manifest,
            receipt,
            packageMetadata,
            files,
            reconstructedPayload,
        };
    }

    readVerifiedFile(record, relativeName) {
        const verified = this.verifyInstalledRecord(record);
        const relativeFile = safeRelativeFile(relativeName);
        if (
            !Object.prototype.hasOwnProperty.call(verified.files, relativeFile)
        ) {
            const error = new Error(
                `Extension package asset is unavailable: ${relativeFile}`,
            );
            error.code = 'EXTENSION_PACKAGE_ASSET_NOT_FOUND';
            error.statusCode = 404;
            throw error;
        }
        return {
            path: relativeFile,
            content: verified.files[relativeFile],
            digest: verified.packageMetadata.fileDigests[relativeFile],
            packageDigest: verified.packageMetadata.packageDigest,
        };
    }

    load(record) {
        const verified = this.verifyInstalledRecord(record);
        this.evictRequireCache(verified.packageDirectory);
        const requireModule = eval('require');
        return requireModule(verified.entrypoint);
    }

    deactivate(extensionId, record) {
        if (!this.available) return;
        const root = this.extensionRoot(extensionId);
        if (!this.fs.existsSync(root)) return;
        this.assertManagedExtensionRoot(extensionId);
        const activePath = this.path.join(root, 'active.json');
        if (this.fs.existsSync(activePath)) this.fs.unlinkSync(activePath);
        if (record?.packageDirectory) {
            this.evictRequireCache(record.packageDirectory);
        }
    }

    removeVersion(record) {
        if (
            !this.available ||
            !record?.extensionId ||
            !record?.version ||
            !record?.packageDigest ||
            !record?.packageDirectory
        ) {
            return;
        }
        const candidate = this.path.resolve(record.packageDirectory);
        if (!this.fs.existsSync(candidate)) return;
        const ownedDirectory = this.assertExistingOwnedDirectory(
            record.extensionId,
            candidate,
        );
        const expectedDirectory = this.versionRoot(
            record.extensionId,
            record.version,
            record.packageDigest,
        );
        if (
            !this.fs.existsSync(expectedDirectory) ||
            this.fs.realpathSync(expectedDirectory) !== ownedDirectory
        ) {
            const error = new Error(
                'Extension package path does not match the version selected for cleanup',
            );
            error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
            error.statusCode = 409;
            throw error;
        }
        this.evictRequireCache(ownedDirectory);
        this.fs.rmSync(ownedDirectory, { recursive: true, force: true });
    }

    remove(record) {
        if (!this.available || !record?.extensionId) return;
        this.deactivate(record.extensionId, record);
        if (!this.fs.existsSync(this.extensionRoot(record.extensionId))) return;
        const { extensionRoot, realExtensionRoot } =
            this.assertManagedExtensionRoot(record.extensionId);
        const versionsDirectory = this.path.join(extensionRoot, 'versions');
        if (this.fs.existsSync(versionsDirectory)) {
            this.assertNoSymlinkPath(extensionRoot, versionsDirectory);
            const stat = this.fs.lstatSync(versionsDirectory);
            if (!stat.isDirectory() || stat.isSymbolicLink()) {
                const error = new Error(
                    'Extension versions path is not a regular directory',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
            const realVersionsDirectory =
                this.fs.realpathSync(versionsDirectory);
            if (
                !isContainedPath(
                    this.path,
                    realExtensionRoot,
                    realVersionsDirectory,
                )
            ) {
                const error = new Error(
                    'Extension versions path escaped its managed root',
                );
                error.code = 'EXTENSION_PACKAGE_PATH_INVALID';
                error.statusCode = 409;
                throw error;
            }
            this.evictRequireCache(versionsDirectory);
            this.fs.rmSync(versionsDirectory, {
                recursive: true,
                force: true,
            });
        }
    }
}

export function createNodeExtensionPackageStore(options) {
    const store = new NodeExtensionPackageStore(options);
    return store.available ? store : null;
}

export default NodeExtensionPackageStore;

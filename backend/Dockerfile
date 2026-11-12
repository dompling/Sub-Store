# Keep the Node tag aligned with the repository-root .node-version.
FROM node:24.22.1-bookworm-slim AS build

WORKDIR /build

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches

RUN corepack install \
    && corepack pnpm install --frozen-lockfile

COPY . .

# The backend-only build context does not contain the repository-root file.
# Record the image runtime used to test the standalone bundle manifest.
RUN node -p 'process.versions.node' > ../.node-version \
    && corepack pnpm bundle:esbuild


FROM node:24.22.1-bookworm-slim AS runtime

ENV NODE_ENV=production \
    SUB_STORE_BACKEND_API_HOST=0.0.0.0 \
    SUB_STORE_BACKEND_API_PORT=3000 \
    SUB_STORE_DATA_BASE_PATH=/opt/app/data

WORKDIR /app

RUN mkdir -p /opt/app/data \
    && chown node:node /opt/app/data

COPY --from=build --chown=node:node /build/dist/sub-store.bundle.js ./sub-store.bundle.js
COPY --from=build --chown=node:node /build/dist/runtime-manifest.json ./runtime-manifest.json

USER node

VOLUME ["/opt/app/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["node", "-e", "const pathPrefix = process.env.SUB_STORE_BACKEND_PREFIX ? (process.env.SUB_STORE_FRONTEND_BACKEND_PATH || '').replace(/\\/$/, '') : ''; fetch('http://127.0.0.1:' + (process.env.SUB_STORE_BACKEND_API_PORT || '3000') + pathPrefix + '/api/utils/env').then((response) => { if (!response.ok) throw new Error('HTTP ' + response.status); }).catch((error) => { console.error(error); process.exit(1); })"]

CMD ["node", "/app/sub-store.bundle.js"]

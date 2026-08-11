# Keep the Node tag aligned with the repository-root .node-version.
FROM node:24.15.0-bookworm-slim AS build

WORKDIR /build

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches

RUN corepack install \
    && corepack pnpm install --frozen-lockfile

COPY . .

RUN corepack pnpm bundle:esbuild


FROM node:24.15.0-bookworm-slim AS runtime

ENV NODE_ENV=production \
    SUB_STORE_BACKEND_API_HOST=0.0.0.0 \
    SUB_STORE_BACKEND_API_PORT=3000 \
    SUB_STORE_DATA_BASE_PATH=/opt/app/data

WORKDIR /app

RUN mkdir -p /opt/app/data \
    && chown node:node /opt/app/data

COPY --from=build --chown=node:node /build/dist/sub-store.bundle.js ./sub-store.bundle.js

USER node

VOLUME ["/opt/app/data"]
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["node", "-e", "fetch('http://127.0.0.1:' + (process.env.SUB_STORE_BACKEND_API_PORT || '3000') + '/api/utils/env').then((response) => { if (!response.ok) throw new Error('HTTP ' + response.status); }).catch((error) => { console.error(error); process.exit(1); })"]

CMD ["node", "/app/sub-store.bundle.js"]

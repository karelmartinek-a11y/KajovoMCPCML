FROM node:22.16.0-alpine3.22 AS build
ARG HANDLER_DIR
WORKDIR /build/handler
RUN corepack enable && corepack prepare pnpm@9.15.4 --activate
COPY ${HANDLER_DIR}/package.json ${HANDLER_DIR}/pnpm-lock.yaml ${HANDLER_DIR}/tsconfig.json ./
RUN pnpm install --frozen-lockfile --ignore-scripts
COPY ${HANDLER_DIR}/src ./src
RUN pnpm exec tsc -p tsconfig.json && pnpm prune --prod --ignore-scripts

FROM node:22.16.0-alpine3.22
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /build/handler/dist /app/handler/dist
COPY --from=build --chown=node:node /build/handler/node_modules /app/handler/node_modules
COPY --chown=node:node deploy/handler-runtime/bootstrap.mjs /app/bootstrap.mjs
COPY --chown=node:node deploy/handler-runtime/handler-runner.mjs /app/handler-runner.mjs
USER node
ENTRYPOINT ["node", "/app/bootstrap.mjs"]

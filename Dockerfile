FROM node:24-bookworm-slim AS build
WORKDIR /app
RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json eslint.config.js ./
COPY scripts ./scripts
COPY apps ./apps
COPY packages ./packages
COPY docs ./docs
COPY Connect_in_Catalog_KajovoCML_v1.7.docx ./Connect_in_Catalog_KajovoCML_v1.7.docx
RUN pnpm install --frozen-lockfile
RUN pnpm --filter @kcml/admin-ui build
RUN pnpm --filter @kcml/server build
RUN pnpm --filter @kcml/server deploy --prod --legacy /runtime/server

FROM node:24-bookworm-slim
WORKDIR /app
ENV NODE_ENV=production
RUN groupadd --system kcml && useradd --system --gid kcml --home-dir /nonexistent --shell /usr/sbin/nologin kcml
COPY --from=build --chown=kcml:kcml /runtime/server/node_modules ./apps/server/node_modules
COPY --from=build --chown=kcml:kcml /app/apps/server/package.json ./apps/server/package.json
COPY --from=build --chown=kcml:kcml /app/apps/server/dist ./apps/server/dist
COPY --from=build --chown=kcml:kcml /app/apps/server/src/migrations ./apps/server/dist/migrations
COPY --from=build --chown=kcml:kcml /app/apps/admin-ui/dist ./apps/admin-ui/dist
COPY --from=build --chown=kcml:kcml /app/docs/onboarding-catalogs ./docs/onboarding-catalogs
COPY --from=build --chown=kcml:kcml /app/docs/onboarding-manifest-v1.5.example.json ./docs/onboarding-manifest-v1.5.example.json
COPY --from=build --chown=kcml:kcml /app/Connect_in_Catalog_KajovoCML_v1.7.docx ./Connect_in_Catalog_KajovoCML_v1.7.docx
USER kcml
EXPOSE 3000
CMD ["node", "apps/server/dist/index.js"]

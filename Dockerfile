FROM oven/bun:1.3.11-alpine AS build

WORKDIR /app

COPY package.json bun.lock tsconfig.json ./
COPY apps/server/package.json apps/server/package.json
COPY packages/identity/package.json packages/identity/package.json
COPY packages/server/package.json packages/server/package.json
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build

FROM oven/bun:1.3.11-alpine AS runtime

WORKDIR /app
ENV NODE_ENV=production

COPY --chown=bun:bun package.json bun.lock ./
COPY --chown=bun:bun apps/server/package.json apps/server/package.json
COPY --chown=bun:bun packages/identity/package.json packages/identity/package.json
COPY --chown=bun:bun packages/server/package.json packages/server/package.json
RUN bun install --frozen-lockfile --production --omit optional --omit peer

COPY --from=build --chown=bun:bun /app/apps/server/dist apps/server/dist
COPY --from=build --chown=bun:bun /app/apps/server/drizzle apps/server/drizzle
COPY --from=build --chown=bun:bun /app/packages/identity/dist packages/identity/dist
COPY --from=build --chown=bun:bun /app/packages/server/dist packages/server/dist

USER bun
EXPOSE 8790
CMD ["bun", "apps/server/dist/index.js"]

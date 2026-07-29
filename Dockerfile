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

COPY --from=build --chown=bun:bun /app /app

USER bun
EXPOSE 8790
CMD ["bun", "apps/server/dist/index.js"]

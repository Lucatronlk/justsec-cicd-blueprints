FROM node:20.19.2-alpine3.21 AS build
WORKDIR /app
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate
COPY package.json pnpm-lock.yaml tsconfig.json ./
RUN pnpm install --frozen-lockfile
COPY src ./src
COPY test ./test
RUN pnpm run test

FROM node:20.19.2-alpine3.21
ENV NODE_ENV=production HOST=0.0.0.0 PORT=3000
WORKDIR /app
COPY --from=build --chown=node:node /app/dist/src ./dist/src
USER node
EXPOSE 3000
CMD ["node", "dist/src/server.js"]

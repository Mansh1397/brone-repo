# --- Stage 1: Build & Prune ---
FROM node:18-alpine AS base
WORKDIR /app

# Copy all configuration files and full project source
COPY package.json package-lock.json ./
COPY apps/ ./apps/
COPY packages/ ./packages/

# Install ALL dependencies (including devDependencies needed for compilation)
RUN npm install

# Compile the backend and packages
RUN npm run build --workspace=@brone/types && npm run build --workspace=@brone/crypto-core && npm run build --workspace=@brone/backend

# Remove development dependencies to keep production image light
RUN npm prune --omit=dev

# --- Stage 2: Clean Production Runner ---
FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Copy root configs
COPY package.json package-lock.json ./

# Copy the pre-installed, pruned production node_modules from base stage
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/packages ./packages
COPY --from=base /app/apps/backend/package.json ./apps/backend/package.json
COPY --from=base /app/apps/backend/dist ./apps/backend/dist

EXPOSE 3000
CMD [ "node", "apps/backend/dist/index.js" ]
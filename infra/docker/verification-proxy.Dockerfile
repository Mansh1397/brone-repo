# Stage 1: Build the workspace typescript files
FROM node:22-alpine AS builder
WORKDIR /app

# Copy root configurations and workspace lockfiles
COPY package.json package-lock.json tsconfig.json ./
COPY packages/types/package.json ./packages/types/
COPY packages/crypto-core/package.json ./packages/crypto-core/
COPY apps/backend/package.json ./apps/backend/

# Install all dependencies (including devDependencies for compilation)
RUN npm ci

# Copy source code files
COPY packages/types ./packages/types
COPY packages/crypto-core ./packages/crypto-core
COPY apps/backend ./apps/backend

# Compile all workspace modules
RUN npx tsc --project packages/types/tsconfig.json || true
RUN npx tsc --project packages/crypto-core/tsconfig.json || true
RUN npx tsc --project apps/backend/tsconfig.json

# Stage 2: Production runtime image
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=2048"

# Run as non-root user
USER node

# Copy built artifacts and production dependencies from builder stage
COPY --from=builder /app/package.json /app/package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/apps/backend/package.json ./apps/backend/package.json
COPY --from=builder /app/apps/backend/src ./apps/backend/src

# Expose backend port
EXPOSE 3000

# Explicit, lightweight healthcheck running against /healthz using node
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD node -e "const http = require('http'); http.get('http://localhost:3000/healthz', (res) => { process.exit(res.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));"

# Launch command starting the compiled backend application
CMD ["node", "apps/backend/src/index.js"]

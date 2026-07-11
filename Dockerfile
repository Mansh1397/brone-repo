# FROM node:18-alpine

# WORKDIR /usr/src/app

# COPY package*.json ./
# RUN npm install && npm install -g typescript @types/node

# COPY . .

# RUN tsc

# EXPOSE 3000

# CMD [ "node", "dist/services/server.js" ]

FROM node:18-alpine AS base
WORKDIR /app

# 1. Copy everything necessary for workspace resolution
COPY package.json package-lock.json ./
COPY apps/ ./apps/
COPY packages/ ./packages/

# 2. Install all dependencies (npm will link @brone/types and @brone/crypto-core automatically)
RUN npm install

# 3. Build the backend workspace specifically
RUN npm run build --workspace=@brone/backend

# 4. Final production stage
FROM node:18-alpine
WORKDIR /app

# Copy the built backend
COPY --from=base /app/apps/backend/dist ./dist
# Copy the backend package.json for production dependencies
COPY --from=base /app/apps/backend/package.json ./package.json

# Install ONLY production deps (npm will link local workspaces again)
RUN npm install --omit=dev

EXPOSE 3000
CMD [ "node", "dist/index.js" ]
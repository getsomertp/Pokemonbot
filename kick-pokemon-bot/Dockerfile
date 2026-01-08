# Playwright image includes Chromium + system deps
# Note: v1.47.0 moved to Ubuntu 24.04 by default; the -jammy tag keeps Ubuntu 22.04. :contentReference[oaicite:1]{index=1}
FROM mcr.microsoft.com/playwright:v1.47.0-jammy

WORKDIR /app

# Install deps first (better caching)
COPY package.json package-lock.json* ./
RUN npm ci

# Prisma generate needs schema
COPY prisma ./prisma
RUN npx prisma generate

# App source
COPY src ./src

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "src/server.js"]

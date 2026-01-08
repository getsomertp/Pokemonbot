FROM mcr.microsoft.com/playwright:v1.47.0-jammy

WORKDIR /app

# 1) Install deps but do NOT run postinstall yet (prisma folder not copied yet)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --ignore-scripts

# 2) Now copy Prisma schema and generate client
COPY prisma ./prisma
RUN npx prisma generate

# 3) Copy app source
COPY src ./src

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "src/server.js"]

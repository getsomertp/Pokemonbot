FROM node:18-bullseye-slim

WORKDIR /app

COPY package.json ./
RUN npm install --omit=dev

COPY prisma ./prisma
RUN npx prisma generate

COPY src ./src

ENV NODE_ENV=production
EXPOSE 8080

CMD ["node", "src/server.js"]

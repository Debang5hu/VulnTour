FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

ENV NODE_ENV=production
ENV PORT=5000
ENV DB_FILE=/data/database.sqlite3

# persisting data
VOLUME ["/data"]

EXPOSE 5000

CMD ["node", "server.js"]

FROM node:22.11.0-alpine
ARG NPM_TOKEN
WORKDIR /app
COPY . .
RUN npm ci
USER node
CMD ["node", "server.js"]

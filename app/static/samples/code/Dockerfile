# Sample - intentionally risky Dockerfile (for scanner demos)
FROM node:latest
ENV DB_PASSWORD=SuperSecret123
ARG NPM_TOKEN=npm_abcdefghijklmnopqrstuvwxyz0123456789
ADD https://example.com/tool.tar.gz /opt/
RUN curl -sL https://deb.nodesource.com/setup.sh | bash -
WORKDIR /app
COPY . .
RUN npm ci
EXPOSE 3000
CMD ["node", "server.js"]

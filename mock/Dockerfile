# PLANTED DEFECTS — do not copy into real code.
# Unpinned base image, runs as root, secret passed as a build arg.
FROM node:latest

ARG NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz
WORKDIR /app
COPY . .
RUN npm install --omit=dev

USER root
EXPOSE 3000
CMD ["node", "app/server.js"]

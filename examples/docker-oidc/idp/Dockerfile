FROM node:24-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205
WORKDIR /idp
RUN npm init -y >/dev/null && npm install --no-audit --no-fund jose@6.2.11
COPY idp.mjs .
USER node
CMD ["node", "idp.mjs"]

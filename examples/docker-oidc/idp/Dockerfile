FROM node:25-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370
WORKDIR /idp
RUN npm init -y >/dev/null && npm install --no-audit --no-fund jose@6.2.11
COPY idp.mjs .
USER node
CMD ["node", "idp.mjs"]

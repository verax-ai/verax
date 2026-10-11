FROM node:24-slim@sha256:d6aa754f16b3197301076f047b5def2f02ea1dbbc2ca920407d46d7ec7f87b20
WORKDIR /idp
RUN npm init -y >/dev/null && npm install --no-audit --no-fund jose@6.2.11
COPY idp.mjs .
USER node
CMD ["node", "idp.mjs"]

# The Verax body as a container image, for trying it or for running it on a
# server behind a TLS-terminating proxy. It is not the isolated install: under
# `verax install` the boundary is a separate OS account the agent cannot read;
# here it is the container and whoever controls the Docker host.
#
# The image installs the published package, so VERAX_VERSION must already be
# on npm. Without VERAX_ISSUER, VERAX_JWKS_URL and VERAX_AUDIENCE the body
# refuses to start (exit 78): there is no default token.
FROM node:25-slim@sha256:81db02c4b671288a03915da9534dbd54f96d0e7c24d80ccc54f5b36b2e684370
ARG VERAX_VERSION=0.5.1
RUN npm install -g --no-audit --no-fund "@verax-ai/body@${VERAX_VERSION}" \
 && npm cache clean --force \
 && mkdir -p /var/lib/verax \
 && chown node:node /var/lib/verax \
 && chmod 700 /var/lib/verax
ENV VERAX_STATE_DIR=/var/lib/verax \
    VERAX_BIND=0.0.0.0:8787
USER node
VOLUME /var/lib/verax
EXPOSE 8787
ENTRYPOINT ["verax"]

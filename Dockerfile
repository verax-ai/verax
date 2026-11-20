# The Verax body as a container image, for trying it or for running it on a
# server behind a TLS-terminating proxy. It is not the isolated install: under
# `verax install` the boundary is a separate OS account the agent cannot read;
# here it is the container and whoever controls the Docker host.
#
# The image installs the published package, so VERAX_VERSION must already be
# on npm. Without VERAX_ISSUER, VERAX_JWKS_URL and VERAX_AUDIENCE the body
# refuses to start (exit 78): there is no default token.
#
# Alpine, not Debian slim: on 20 November 2026 an Amazon ECR basic scan of the
# 0.8.2 image on node:24-slim reported seven HIGH findings in Debian packages
# (six left after apt-get upgrade, no fixed version yet); the same body on
# node:24-alpine with apk upgrade reported none. The packages are pure
# JavaScript, so nothing is built against glibc.
FROM node:24-alpine@sha256:116b800c3754b440ee0aa3ed2f20f5bf3d99a554bfd9adeea09ea8017f6e85f5
ARG VERAX_VERSION=0.9.0
RUN apk upgrade --no-cache \
 && npm install -g --no-audit --no-fund "@verax-ai/body@${VERAX_VERSION}" \
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

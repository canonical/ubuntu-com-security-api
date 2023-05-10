# syntax=docker/dockerfile:experimental

# Build stage: Install python dependencies
# ===
FROM ubuntu:jammy AS python-dependencies
RUN apt-get update && apt-get install --no-install-recommends --yes python3-pip python3-setuptools python3-wheel build-essential
ADD requirements.txt /tmp/requirements.txt
RUN pip3 config set global.disable-pip-version-check true
RUN --mount=type=cache,target=/root/.cache/pip pip3 install --user --requirement /tmp/requirements.txt


# Build the production image
# ===
FROM ubuntu:jammy

# Install python and import python dependencies
RUN apt-get update && apt-get install --no-install-recommends --yes python3-setuptools python3-lib2to3 python3-pkg-resources ca-certificates libsodium-dev gpg
COPY --from=python-dependencies /root/.local/lib/python3.8/site-packages /root/.local/lib/python3.8/site-packages
COPY --from=python-dependencies /root/.local/bin /root/.local/bin
ENV PATH="/root/.local/bin:${PATH}"

# Set up environment
ENV LANG C.UTF-8
WORKDIR /srv

# Import code, build assets and mirror list
ADD . .
RUN rm -rf package.json

# Set revision ID
ARG BUILD_ID
ENV TALISKER_REVISION_ID "${BUILD_ID}"

# Setup commands to run server
ENTRYPOINT ["./entrypoint"]
CMD ["0.0.0.0:80"]

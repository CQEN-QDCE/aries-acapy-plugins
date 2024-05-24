# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.134.0/containers/python-3/.devcontainer/base.Dockerfile

ARG VARIANT="3.9-bullseye"

FROM mcr.microsoft.com/vscode/devcontainers/python:0-${VARIANT} AS clone
RUN git clone https://github.com/CQEN-QDCE/aries-acapy-plugins.git

FROM mcr.microsoft.com/vscode/devcontainers/python:0-${VARIANT} AS build

RUN mkdir -p /mso_mdoc
COPY --from=clone /aries-acapy-plugins/mso_mdoc /mso_mdoc

ARG POETRY_VERSION="1.7.1"
ENV POETRY_HOME="/opt/poetry" \
    POETRY_VERSION=${POETRY_VERSION}

RUN curl -sSL https://install.python-poetry.org | python3 - \
    && update-alternatives --install /usr/local/bin/poetry poetry /opt/poetry/bin/poetry 900 \
    # Enable tab completion for bash
    && poetry completions bash >> /home/vscode/.bash_completion \
    # Enable tab completion for Zsh
    && mkdir -p /home/vscode/.zfunc/ \
    && poetry completions zsh > /home/vscode/.zfunc/_poetry \
    && echo "fpath+=~/.zfunc\nautoload -Uz compinit && compinit" >> /home/vscode/.zshrc

COPY pyproject.toml poetry.lock ./oid4vci/
WORKDIR /oid4vci
RUN poetry config virtualenvs.create false \
    && poetry install --no-root --no-interaction --with integration --extras "mdoc aca-py" \
    && rm -rf /root/.cache/pypoetry
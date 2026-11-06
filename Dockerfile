FROM python:3.14-slim

WORKDIR /srv/cartography

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        gcc pkg-config libffi-dev libssl-dev libxml2-dev libxmlsec1-dev \
        curl make git openssl && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN python -m venv /venv
ENV PATH=/venv/bin:$PATH

# Create cartography user so that we can give it ownership of the directory later for unit&integ tests
RUN groupadd cartography && \
    useradd -s /bin/bash -d /home/cartography -m -g cartography cartography

# Installs python dependencies
COPY setup.py test-requirements.txt ./
RUN pip install -U pip setuptools && \
    pip install -e . && \
    pip install -r test-requirements.txt && \
    # Grant write access to the directory for unit and integration test coverage files
    chmod -R a+w /srv/cartography

# Install cartography, setting the owner so that tests work
COPY --chown=cartography:cartography . /srv/cartography

USER cartography

# Sets the directory as safe due to a mismatch in the user that cloned the repo
# and the user that is going to run the unit&integ tests.
RUN git config --global --add safe.directory /srv/cartography
RUN /usr/bin/git config --local user.name "cartography"

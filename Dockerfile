# use stable, low-resource base
FROM python:3.14-slim

# update and install bash-completion
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*

# add non-root user
RUN useradd -m appuser
USER appuser
WORKDIR /home/appuser/ksc-tools

# enforce unbuffered I/O mode: display output immediately
ENV PYTHONUNBUFFERED=1

# install packages used by KSC-Tools
COPY --chown=appuser:appuser scripts/requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

# copy the KSC-Tools scripts
COPY --chown=appuser:appuser scripts/*.py ./

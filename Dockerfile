# use an Alphine base image
FROM python:3.12-alpine

WORKDIR /usr/src/app

# copy the KSC-Tools scripts
COPY scripts/*.py ./

# install packages used by KSC-Tools
COPY scripts/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

#!/bin/bash
docker stop webhook-external-hostname
docker rm webhook-external-hostname
docker build -t webhook-external-hostname .
docker run -p 5000:5000 -tid \
    --volume $(pwd)/settings.yaml:/settings.yaml \
    --name webhook-external-hostname \
    --restart always \
    webhook-external-hostname

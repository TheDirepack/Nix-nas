ARG BASE_IMAGE
FROM ${BASE_IMAGE}
USER root
COPY zap-addons.py zap-addons.lock.json zap-cookie-probes.patch /nas-zap-build/
RUN python3 /nas-zap-build/zap-addons.py build
USER zap

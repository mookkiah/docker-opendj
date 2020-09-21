.DEFAULT_GOAL := build-dev

GLUU_VERSION=4.2.1
OPENDJ_IMAGE_NAME=gluufederation/opendj
WRENDS_IMAGE_NAME=gluufederation/wrends
UNSTABLE_VERSION=dev

build-dev:
	@echo "[I] Building Docker image ${OPENDJ_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}"
	@docker build --rm --force-rm -t ${OPENDJ_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} -f Dockerfile.opendj .

trivy-scan:
	@echo "[I] Scanning Docker image ${OPENDJ_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} using trivy"
	@trivy -d image ${OPENDJ_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}

dockle-scan:
	@echo "[I] Scanning Docker image ${OPEND_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} using dockle"
	@dockle -d ${OPENDJ_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}

build-dev-wrends:
	@echo "[I] Building Docker image ${WRENDS_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}"
	@docker build --rm --force-rm -t ${WRENDS_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} -f Dockerfile.wrends .

trivy-scan-wrends:
	@echo "[I] Scanning Docker image ${WRENDS_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} using trivy"
	@trivy -d image ${WRENDS_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}

dockle-scan-wrends:
	@echo "[I] Scanning Docker image ${WRENDS_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION} using dockle"
	@dockle -d ${WRENDS_IMAGE_NAME}:${GLUU_VERSION}_${UNSTABLE_VERSION}

docker build \
  --build-arg GIT_COMMIT=$(git rev-parse HEAD) \
  --build-arg GIT_VERSION=$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD) \
  -t mcleancraig/vuln-app:${GIT_VERSION} .

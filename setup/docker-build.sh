GIT_VERSION=$(git describe --tags --always --dirty 2>/dev/null || git rev-parse --short HEAD) \
GIT_COMMIT=$(git rev-parse HEAD) \

docker build \
  --build-arg GIT_COMMIT=${GIT_COMMIT} \
  --build-arg GIT_VERSION=${GIT_VERSION} \
  -t mcleancraig/node-vuln:${GIT_VERSION} .

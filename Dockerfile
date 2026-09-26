ARG BASE_IMAGE=registry.internal.stacktixs.com/gcr.io/distroless/base-debian12
FROM ${BASE_IMAGE}

ARG TARGETARCH

ARG APP_NAME=target-service
COPY ${APP_NAME}-${TARGETARCH} /app

EXPOSE 8080
CMD ["/app"]

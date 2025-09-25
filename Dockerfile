FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -o /workspace/bin/crowdsec-cilium-bouncer ./cmd

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/bin/crowdsec-cilium-bouncer /crowdsec-cilium-bouncer
USER 65532:65532
ENTRYPOINT ["/crowdsec-cilium-bouncer"]

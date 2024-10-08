ARG GOVERSION=1.22

FROM golang:${GOVERSION}-alpine AS build

WORKDIR /go/src/cs-cloudflare-bouncer

RUN apk add --update --no-cache make git
COPY . .

RUN make build DOCKER_BUILD=1

FROM alpine:latest
COPY --from=build /go/src/cs-cloudflare-bouncer/crowdsec-cloudflare-bouncer /usr/local/bin/crowdsec-cloudflare-bouncer
COPY --from=build /go/src/cs-cloudflare-bouncer/config/crowdsec-cloudflare-bouncer-docker.yaml /etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml

ENTRYPOINT ["/usr/local/bin/crowdsec-cloudflare-bouncer", "-c", "/etc/crowdsec/bouncers/crowdsec-cloudflare-bouncer.yaml"]

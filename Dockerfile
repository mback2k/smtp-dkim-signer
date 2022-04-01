FROM golang:alpine as build
RUN apk --no-cache --update upgrade && apk --no-cache add git build-base

ADD . /go/smtp-dkim-signer
WORKDIR /go/smtp-dkim-signer

RUN go get
RUN go build -ldflags="-s -w"
RUN chmod +x smtp-dkim-signer

FROM ghcr.io/mback2k/docker-alpine:latest
RUN apk --no-cache --update upgrade && apk --no-cache add ca-certificates

COPY --from=build /go/smtp-dkim-signer/smtp-dkim-signer /usr/local/bin/smtp-dkim-signer

RUN addgroup -g 587 -S serve
RUN adduser -u 587 -h /data -S -D -G serve serve

WORKDIR /data
USER serve

CMD [ "/usr/local/bin/smtp-dkim-signer" ]

FROM golang:1.19.1-alpine as builder

WORKDIR /go/src/proxy

COPY . .

RUN go build .

FROM alpine:3.16

COPY --from=builder /go/src/proxy/proxy .

CMD ./proxy
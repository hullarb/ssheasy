FROM golang:1.20.1-alpine as builder

WORKDIR /go/src/proxy

COPY . .

RUN go build .

FROM alpine:3.17

COPY --from=builder /go/src/proxy/proxy .

CMD ./proxy
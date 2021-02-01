FROM golang:1.15.7-alpine3.13 as builder

WORKDIR /go/src/proxy

COPY . .

RUN go build .

FROM alpine:3.10

COPY --from=builder /go/src/proxy/proxy .

CMD ./proxy
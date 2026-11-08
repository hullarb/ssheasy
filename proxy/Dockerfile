FROM golang:1.27.3-alpine as builder

WORKDIR /go/src/proxy

COPY . .

RUN go build .

FROM alpine:3.24

COPY --from=builder /go/src/proxy/proxy .

CMD ./proxy
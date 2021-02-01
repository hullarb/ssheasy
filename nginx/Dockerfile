FROM golang:1.15.7-alpine3.13 as builder

WORKDIR /go/src/web

COPY ./web .


RUN GOOS=js GOARCH=wasm go build -o main.wasm


FROM nginx:1.19.6
# Add the Nginx configuration file
ADD ./nginx/nginx.conf /etc/nginx/nginx.conf
# Copy over static assets from the client application
COPY ./web/html /usr/share/nginx/html
COPY --from=builder /go/src/web/main.wasm /usr/share/nginx/html/
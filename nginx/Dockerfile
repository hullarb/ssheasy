FROM golang:1.20.1-alpine as builder

WORKDIR /go/src/web

COPY ./web .


RUN GOOS=js GOARCH=wasm go build -o main.wasm


FROM nginx:1.23.3
COPY --from=builder /usr/local/go/misc/wasm/wasm_exec.js /usr/share/nginx/html/
# Add the Nginx configuration file
ADD ./nginx/nginx.conf /etc/nginx/nginx.conf
# Copy over static assets from the client application
COPY ./web/html /usr/share/nginx/html
COPY --from=builder /go/src/web/main.wasm /usr/share/nginx/html/
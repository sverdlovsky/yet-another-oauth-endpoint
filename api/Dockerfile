FROM golang:alpine AS build

WORKDIR /app

COPY go.sum .
COPY go.mod .

RUN go mod download

COPY cmd cmd

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o yaoae ./cmd/yaoae


FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /app/yaoae /yaoae

USER 10001:10001

EXPOSE 8080

ENTRYPOINT ["/yaoae"]


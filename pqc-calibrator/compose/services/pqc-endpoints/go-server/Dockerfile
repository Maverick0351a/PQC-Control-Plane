FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /pqc-go-server main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=build /pqc-go-server /app/pqc-go-server
EXPOSE 8443
ENTRYPOINT ["/app/pqc-go-server"]

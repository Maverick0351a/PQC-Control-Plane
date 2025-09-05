FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /evg server.go

FROM alpine:3.20
WORKDIR /app
COPY --from=build /evg /app/evg
EXPOSE 8088
ENTRYPOINT ["/app/evg"]

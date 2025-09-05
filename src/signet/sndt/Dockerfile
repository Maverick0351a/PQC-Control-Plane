FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /sndt main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=build /sndt /app/sndt
EXPOSE 8090
ENTRYPOINT ["/app/sndt"]

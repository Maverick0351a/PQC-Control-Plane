FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /pqc-go-client main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=build /pqc-go-client /app/pqc-go-client
ENTRYPOINT ["/app/pqc-go-client"]

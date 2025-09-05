FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /pqc-calibrate main.go

FROM alpine:3.20
WORKDIR /app
COPY --from=build /pqc-calibrate /usr/local/bin/pqc-calibrate
ENTRYPOINT ["/usr/local/bin/pqc-calibrate"]

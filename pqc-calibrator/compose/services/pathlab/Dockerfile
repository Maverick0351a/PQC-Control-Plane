FROM alpine:3.20
RUN apk add --no-cache socat bash iproute2
# MVP placeholder: TCP proxy on 15000 -> 8443, admin echo on 15001
CMD ["sh","-lc","socat -v TCP-LISTEN:15000,fork,reuseaddr TCP:pqc-go-server:8443 & while true; do { echo -e 'HTTP/1.1 200 OK\r\n\r\npathlab ok'; } | nc -l -p 15001 -s 0.0.0.0; done"]

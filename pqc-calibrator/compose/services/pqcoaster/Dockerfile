FROM alpine:3.20
RUN apk add --no-cache bash iptables ip6tables
# NOTE: host network + privileged required in compose for tc/iptables; placeholder entrypoint
CMD ["sh","-lc","echo 'pqcoaster placeholder'; sleep infinity"]

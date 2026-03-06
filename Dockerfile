FROM alpine:latest

RUN apk add --no-cache ca-certificates libc6-compat iptables

RUN mkdir -p /etc/godns

WORKDIR /etc/godns

COPY . .

RUN chmod +x ./godns

ENTRYPOINT ["./godns"]
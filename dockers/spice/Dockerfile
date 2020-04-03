FROM alpine:3.11.3 

RUN apk add --no-cache squid
ADD dockers/spice/squid.conf /etc/squid/squid.conf
EXPOSE 8080
CMD ["squid", "-N"]


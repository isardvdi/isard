FROM haproxy:alpine
RUN apk add openssl
ADD dockers/haproxy/auto-generate-certs.sh /
ADD dockers/haproxy/docker-entrypoint.sh /
RUN chmod 775 docker-entrypoint.sh
RUN chmod 775 auto-generate-certs.sh
ADD dockers/haproxy/haproxy.conf /usr/local/etc/haproxy/haproxy.cfg

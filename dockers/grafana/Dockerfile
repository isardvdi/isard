FROM alpine:3.8
# Based on https://github.com/SchweizerischeBundesbahnen/docker-graphite and https://github.com/orangesys/alpine-grafana

# Install basic stuff =)
RUN apk add --no-cache \
  bash \
  ca-certificates \
  nginx \
  openssl \
  py2-pip \
  supervisor \
  tini \
  && pip install \
  supervisor-stdout \
  gunicorn

# Install graphite
ENV GRAPHITE_ROOT /opt/graphite

RUN apk add --no-cache \
  alpine-sdk \
  fontconfig \
  libffi \
  libffi-dev \
  python-dev \
  py-cairo \
  && export PYTHONPATH="/opt/graphite/lib/:/opt/graphite/webapp/" \
  && pip install https://github.com/graphite-project/whisper/tarball/master \
  && pip install https://github.com/graphite-project/carbon/tarball/master \
  && pip install https://github.com/graphite-project/graphite-web/tarball/master \
  && apk del \
  alpine-sdk \
  python-dev \
  libffi-dev

# Grafana
ENV GRAFANA_VERSION=6.6.2

RUN set -ex \
 && addgroup -S grafana \
 && adduser -S -G grafana grafana \
 && apk add --no-cache libc6-compat ca-certificates su-exec \
 && mkdir /tmp/setup \
 && wget -P /tmp/setup https://dl.grafana.com/oss/release/grafana-$GRAFANA_VERSION.linux-amd64.tar.gz \
 && tar -xzf /tmp/setup/grafana-$GRAFANA_VERSION.linux-amd64.tar.gz -C /tmp/setup --strip-components=1 \
 && install -m 755 /tmp/setup/bin/grafana-server /usr/local/bin/ \
 && install -m 755 /tmp/setup/bin/grafana-cli /usr/local/bin/ \
 && mkdir -p /grafana/datasources /grafana/dashboards /grafana/data /grafana/logs /grafana/plugins /var/lib/grafana \
 && cp -r /tmp/setup/public /grafana/public \
 && chown -R grafana:grafana /grafana \
 && ln -s /grafana/plugins /var/lib/grafana/plugins \
 && grafana-cli plugins update-all \
 && rm -rf /tmp/setup

ADD dockers/grafana/grafana-defaults.ini /grafana/conf/defaults.ini

EXPOSE 8080
EXPOSE 3000
EXPOSE 2003
EXPOSE 2004
EXPOSE 7002

VOLUME ["/opt/graphite/conf", "/opt/graphite/storage"]

COPY dockers/grafana/run.sh /run.sh
COPY dockers/grafana/etc/ /etc/
COPY dockers/grafana/data/ /grafana/data_init/
COPY dockers/grafana/conf/ /opt/graphite/conf.example/

# Enable tiny init
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/bin/bash", "/run.sh"]

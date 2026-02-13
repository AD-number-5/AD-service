FROM debian:bookworm-slim AS build
ARG APT_MIRROR=mirror.yandex.ru

RUN set -eux; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do \
      [ -f "$f" ] || continue; \
      sed -i "s|deb.debian.org|${APT_MIRROR}|g" "$f"; \
      sed -i "s|security.debian.org|${APT_MIRROR}|g" "$f"; \
    done; \
    apt-get update; \
    apt-get install -y --no-install-recommends ffmpeg; \
    rm -rf /var/lib/apt/lists/*

RUN useradd -r -m -d /home/pixel -s /usr/sbin/nologin pixel \
    && mkdir -p /work \
    && chown -R pixel:pixel /work

WORKDIR /work

COPY --chmod=0755 pixelizer /usr/local/bin/pixelizer

USER pixel
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pixelizer"]
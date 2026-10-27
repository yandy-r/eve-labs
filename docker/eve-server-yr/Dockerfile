# eve-server-yr: headless, prod-like Linux server for EVE-NG labs.
# Build on the EVE host: docker build -t eve-server-yr:latest docker/eve-server-yr
FROM ubuntu:24.04

LABEL org.opencontainers.image.title="eve-server-yr" \
      org.opencontainers.image.description="Headless prod-like test server for EVE-NG labs"

ENV LANG=C.UTF-8 \
    TZ=UTC \
    PATH=/opt/netops/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    ANSIBLE_COLLECTIONS_PATH=/usr/share/ansible/collections

COPY install-tools.sh /tmp/install-tools.sh
RUN bash /tmp/install-tools.sh \
    && apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

COPY rootfs/ /
RUN chmod +x /usr/local/sbin/eve-server-init /usr/local/bin/svc \
    && echo 'root:eve' | chpasswd \
    && useradd -m -s /bin/bash -G sudo netops \
    && echo 'netops:eve' | chpasswd \
    && rm -f /etc/ssh/ssh_host_* /etc/nginx/sites-enabled/default \
    && ln -s /etc/nginx/sites-available/eve-server /etc/nginx/sites-enabled/eve-server \
    && mkdir -p /srv/www/files /srv/tftp /run/sshd

EXPOSE 22 80 443 5201 69/udp 161/udp

# EVE injects /eve-net-gate as the entrypoint and execs this CMD after links are up.
CMD ["/usr/bin/tini", "--", "/usr/local/sbin/eve-server-init"]

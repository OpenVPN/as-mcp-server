# Access Server 3.2.4 has no image on Docker Hub yet (checked 2026-11-13), only packages.
# Same build steps as the official image, with the newer package version.
# Replace with the official image once openvpn/openvpn-as:3.2.4-* is published.
ARG VERSION=3.2.4-f3c295a7-Ubuntu26
FROM ubuntu:26.04
ARG VERSION
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y curl systemctl \
    && bash -c 'bash <(curl -fsS https://packages.openvpn.net/as/install.sh) --yes --as-version=$VERSION --without-dco' \
    && apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /openvpn /ovpn/tmp /ovpn/sock \
    && sed -i 's#~/tmp#/ovpn/tmp#g;s#~/sock#/ovpn/sock#g' /usr/local/openvpn_as/etc/as_templ.conf \
    && rm -rf /usr/local/openvpn_as/etc/sock/* \
    && rm -rf /usr/local/openvpn_as/etc/pid/* \
    && mv /usr/local/openvpn_as/etc /usr/local/openvpn_as/etc.docker.bak \
    && ln -s /openvpn/etc /usr/local/openvpn_as/etc
COPY --from=openvpn/openvpn-as:3.2.3-8444f22d-Ubuntu26 /docker-entrypoint.sh /
EXPOSE 943/tcp
VOLUME ["/openvpn"]
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["/usr/local/openvpn_as/scripts/openvpnas", "--nodaemon", "--pidfile=/ovpn/tmp/openvpn.pid"]

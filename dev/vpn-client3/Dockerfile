# An OpenVPN 3 client (OpenVPN 3 Linux) for the dev stand. Its services talk over D-Bus,
# so run.sh starts a bus first. The container needs --privileged.
# The base image brings curl and CA certificates, so the packages come over https
# (plain http is blocked on some networks).
# The hostname1 service file is removed: without systemd nothing answers for that name,
# and the client waits for it until the session manager gives up on the client
# ("New tunnel did not respond").
FROM buildpack-deps:bookworm-curl
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
 && mkdir -p /etc/apt/keyrings \
 && curl -fsSL https://packages.openvpn.net/packages-repo.gpg \
      -o /etc/apt/keyrings/openvpn.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/openvpn.asc] https://packages.openvpn.net/openvpn3/debian bookworm main" \
      > /etc/apt/sources.list.d/openvpn3.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends dbus openvpn3 \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /usr/share/dbus-1/system-services/org.freedesktop.hostname1.service \
 && sed -i 's|openvpn3-service-backendstart.*|openvpn3-service-backendstart --client-log-level 4 --client-log-file /tmp/client.log|' \
      /usr/share/dbus-1/system-services/net.openvpn.v3.backends.service
COPY run.sh /run.sh
ENTRYPOINT ["/bin/sh", "/run.sh"]

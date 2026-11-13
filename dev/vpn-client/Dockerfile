# A plain OpenVPN client for the dev stand: connects a test user to an Access Server
# container so that session tools (disconnect, block) have a real session to act on.
FROM alpine:3.22
RUN apk add --no-cache openvpn
ENTRYPOINT ["openvpn", "--config", "/client.ovpn"]

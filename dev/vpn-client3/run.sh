# Connects with /client.ovpn (and /auth.txt: username and password on two lines, for a
# profile that asks for them), prints the client log, and exits when the session ends.
mkdir -p /run/dbus
touch /tmp/client.log
chown _openvpn /tmp/client.log
dbus-daemon --system --fork
tail -n +1 -F /tmp/client.log &

leave() {
    openvpn3 session-manage --config /client.ovpn --disconnect >/dev/null 2>&1
    exit 0
}
trap leave TERM INT

if [ -f /auth.txt ]; then
    openvpn3 session-start --config /client.ovpn </auth.txt || exit 1
else
    openvpn3 session-start --config /client.ovpn || exit 1
fi
while openvpn3 sessions-list | grep -q "Path:"; do
    sleep 1
done
sleep 1

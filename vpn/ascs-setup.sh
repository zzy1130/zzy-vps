#!/bin/bash
# ASCS IPv6-only node: Xray VLESS-WS (127.0.0.1) + Hysteria2 (UDP 443) + WARP IPv4 egress + cloudflared
# Secrets are generated locally on the server and never leave it except inside the subscription file.
set -e
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
export DEBIAN_FRONTEND=noninteractive
G=https://gh.llkk.cc/https://github.com
apt-get update -qq
apt-get install -y -qq unzip openssl python3 ca-certificates curl >/dev/null
cd /tmp
dl() { curl -fsSL --retry 3 -o "$1" "$2"; echo "$3  $1" | sha256sum -c --quiet; }
dl x.zip  $G/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip 23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae
dl hy     $G/apernet/hysteria/releases/download/app/v2.13.0/hysteria-linux-amd64 907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691
dl wgcf   $G/ViRb3/wgcf/releases/download/v2.3.1/wgcf_2.3.1_linux_amd64 4fb7a136aa470ece11d17949c7db07b040ec9c604742dc8680bcf1889f85d0c8
dl cfd    $G/cloudflare/cloudflared/releases/download/2026.10.0/cloudflared-linux-amd64 d33ff2d14475178d2012c2c56beba87389ac5ded27649519f198a7d3134a99db
unzip -o -q x.zip xray -d /usr/local/bin
install -m755 hy /usr/local/bin/hysteria
install -m755 wgcf /usr/local/bin/wgcf
install -m755 cfd /usr/local/bin/cloudflared
D=/etc/proxy; mkdir -p $D/warp /var/www/sub; chmod 700 $D
[ -f $D/env ] || cat > $D/env <<EOF
U=$(cat /proc/sys/kernel/random/uuid)
P=$(openssl rand -hex 12)
H=$(openssl rand -hex 16)
S=$(openssl rand -hex 20)
EOF
chmod 600 $D/env
IP6=$(ip -6 addr show scope global | awk '/inet6/{print $2}' | cut -d/ -f1 | head -1)
echo "IP6=$IP6" > $D/ip6
# WARP account (IPv4 egress for IPv4-only sites); optional
( cd $D/warp && { [ -f wgcf-account.toml ] || wgcf register --accept-tos >/dev/null 2>&1; } && wgcf generate >/dev/null 2>&1 ) && echo WARP_OK || echo WARP_FAIL
[ -f $D/hy.key ] || openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 3650 \
  -keyout $D/hy.key -out $D/hy.crt -subj "/CN=www.bing.com" 2>/dev/null
cat > $D/gen.py <<'PYEOF'
import json, re, os, base64, urllib.parse
D = "/etc/proxy"
env = dict(l.strip().split("=", 1) for l in open(D + "/env") if "=" in l)
ip6 = open(D + "/ip6").read().strip().split("=", 1)[1]
U, P, H, S = env["U"], env["P"], env["H"], env["S"]
direct = {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "ForceIPv6"}}
outs = [direct]
rules = [{"ip": ["::/0"], "outboundTag": "direct"}]
prof = D + "/warp/wgcf-profile.conf"
if os.path.exists(prof):
    t = open(prof).read()
    key = re.search(r"PrivateKey\s*=\s*(\S+)", t).group(1)
    addrs = [a.strip() for l in re.findall(r"Address\s*=\s*(.+)", t) for a in l.split(",")]
    pub = re.search(r"PublicKey\s*=\s*(\S+)", t).group(1)
    outs.append({"tag": "warp", "protocol": "wireguard", "settings": {
        "secretKey": key, "address": addrs, "mtu": 1280, "domainStrategy": "ForceIPv4",
        "peers": [{"publicKey": pub, "endpoint": "[2606:4700:d0::a29f:c001]:2408",
                   "allowedIPs": ["0.0.0.0/0", "::/0"]}]}})
    rules.append({"ip": ["0.0.0.0/0"], "outboundTag": "warp"})
cfg = {
  "log": {"loglevel": "warning"},
  "inbounds": [
    {"tag": "front", "listen": "127.0.0.1", "port": 10086, "protocol": "vless",
     "settings": {"clients": [], "decryption": "none",
                  "fallbacks": [{"path": "/" + P, "dest": 10085, "xver": 0}, {"dest": 10087}]},
     "streamSettings": {"network": "raw", "security": "none"}},
    {"tag": "ws", "listen": "127.0.0.1", "port": 10085, "protocol": "vless",
     "settings": {"clients": [{"id": U}], "decryption": "none"},
     "streamSettings": {"network": "ws", "wsSettings": {"path": "/" + P}},
     "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}},
    {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
     "settings": {"udp": True},
     "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}}],
  "outbounds": outs,
  "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules}}
json.dump(cfg, open(D + "/xray.json", "w"), indent=1)
open(D + "/hy.yaml", "w").write(f"""listen: :443
tls:
  cert: {D}/hy.crt
  key: {D}/hy.key
auth:
  type: password
  password: {H}
masquerade:
  type: proxy
  proxy:
    url: https://www.bing.com/
    rewriteHost: true
outbounds:
  - name: xr
    type: socks5
    socks5:
      addr: 127.0.0.1:10808
""")
host = open(D + "/host").read().strip() if os.path.exists(D + "/host") else ""
lines = []
if host:
    q = urllib.parse.urlencode({"encryption": "none", "security": "tls", "sni": host, "fp": "chrome",
                                "type": "ws", "host": host, "path": "/" + P})
    lines.append(f"vless://{U}@{host}:443?{q}#ASCS-VLESS-CF")
lines.append(f"hysteria2://{H}@[{ip6}]:443?sni=www.bing.com&insecure=1#ASCS-HY2")
os.makedirs("/var/www/sub/" + S, exist_ok=True)
open("/var/www/sub/index.html", "w").write("")
open(f"/var/www/sub/{S}/index.html", "w").write("")
open(f"/var/www/sub/{S}/sub", "w").write(base64.b64encode("\n".join(lines).encode()).decode())
print("SUB_PATH=/" + S + "/sub", "HOST=" + (host or "none"))
PYEOF
python3 $D/gen.py
/usr/local/bin/xray run -test -c $D/xray.json >/dev/null && echo XRAY_CONFIG_OK
cat > $D/qt.sh <<'EOF'
#!/bin/bash
# temporary Cloudflare quick tunnel until the user's own domain is ready
L=/var/log/cft.log; : > $L
/usr/local/bin/cloudflared tunnel --no-autoupdate --edge-ip-version 6 --url http://127.0.0.1:10086 --logfile $L &
PID=$!
for i in $(seq 1 60); do
  h=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' $L | head -1 | sed 's#https://##')
  [ -n "$h" ] && { echo "$h" > /etc/proxy/host; python3 /etc/proxy/gen.py; break; }
  sleep 2
done
wait $PID
EOF
chmod 755 $D/qt.sh
cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray
After=network-online.target
[Service]
ExecStart=/usr/local/bin/xray run -c $D/xray.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/hysteria.service <<EOF
[Unit]
Description=Hysteria2
After=network-online.target xray.service
[Service]
ExecStart=/usr/local/bin/hysteria server -c $D/hy.yaml
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/subweb.service <<EOF
[Unit]
Description=subscription file server (loopback only)
[Service]
ExecStart=/usr/bin/python3 -m http.server 10087 --bind 127.0.0.1 --directory /var/www/sub
User=nobody
Restart=always
[Install]
WantedBy=multi-user.target
EOF
cat > /etc/systemd/system/cfquick.service <<EOF
[Unit]
Description=Cloudflare quick tunnel (temporary)
After=network-online.target xray.service
[Service]
ExecStart=$D/qt.sh
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now xray hysteria subweb >/dev/null 2>&1
if systemctl is-enabled cfnamed >/dev/null 2>&1; then systemctl restart xray hysteria; else systemctl enable --now cfquick >/dev/null 2>&1; fi
sleep 25

for s in xray hysteria subweb cfquick cfnamed; do echo "$s: $(systemctl is-active $s)"; done
ss -lntup | grep -E '10085|10086|10087|10808|:443' | awk '{print $1, $5}'
# local self-test of Hysteria2 against the public IPv6
. $D/env; . $D/ip6
cat > /tmp/hyc.yaml <<EOF
server: "[$IP6]:443"
auth: $H
tls:
  sni: www.bing.com
  insecure: true
socks5:
  listen: 127.0.0.1:1081
EOF
/usr/local/bin/hysteria client -c /tmp/hyc.yaml >/tmp/hyc.log 2>&1 &
HP=$!; sleep 4
echo "HY2_TEST google: $(curl -s -m 15 -o /dev/null -w '%{http_code}' -x socks5h://127.0.0.1:1081 https://www.google.com/generate_204)"
echo "HY2_TEST ipv4-only github: $(curl -s -m 15 -o /dev/null -w '%{http_code}' -x socks5h://127.0.0.1:1081 https://github.com)"
kill $HP; rm -f /tmp/hyc.yaml
echo "VIA_XRAY ipv4-only github: $(curl -s -m 15 -o /dev/null -w '%{http_code}' -x socks5h://127.0.0.1:10808 https://github.com)"
echo "SUB_URL=https://$(cat $D/host 2>/dev/null)/$S/sub"
echo DONE

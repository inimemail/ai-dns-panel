#!/bin/bash

set -o pipefail

BASE_DIR="/etc/ai_unlock"
CUSTOM_DOMAIN_FILE="$BASE_DIR/custom_domains.conf"
NODE_WHITELIST_FILE="$BASE_DIR/node_whitelist.conf"
DNSMASQ_CONF="/etc/dnsmasq.d/ai_unlock.conf"
SNI_CONF="/etc/sniproxy.conf"
SNI_CONF_DIR="/etc/sniproxy/sniproxy.conf"
SNI_DEFAULT="/etc/default/sniproxy"
SNI_SYSTEMD_SERVICE="/etc/systemd/system/sniproxy.service"
RESOLV_BACKUP="$BASE_DIR/resolv.conf.bak"
FIREWALL_CHAIN="AI_UNLOCK_DNS"
SYNC_SCRIPT="$BASE_DIR/sync_firewall.sh"
SYSTEMD_SERVICE="/etc/systemd/system/ai-unlock-firewall.service"
PANEL_SERVICE="/etc/systemd/system/ai-unlock-panel.service"
PANEL_AUTH_FILE="$BASE_DIR/panel_auth.conf"
PANEL_SECRET_FILE="$BASE_DIR/panel_secret"
PANEL_TOKEN_FILE="$BASE_DIR/node_join_token"
PANEL_NODES_FILE="$BASE_DIR/nodes.json"
PANEL_PORT_FILE="$BASE_DIR/panel_port.conf"
PANEL_DEFAULT_PORT="8088"
PANEL_BIN="/usr/local/bin/ai-unlock-panel"
PANEL_WORK_DIR="/opt/ai_unlock_panel"

AI_CHECK_HOSTS=(
  "chatgpt.com"
  "claude.ai"
  "gemini.google.com"
  "copilot.microsoft.com"
  "perplexity.ai"
  "grok.com"
  "midjourney.com"
  "deepseek.com"
  "mistral.ai"
  "openrouter.ai"
  "character.ai"
  "poe.com"
  "meta.ai"
  "you.com"
)
AI_API_CHECKS=(
  "OpenAI|api.openai.com|https://api.openai.com/v1/models|Authorization: Bearer invalid_token_test|Content-Type: application/json"
  "Anthropic|api.anthropic.com|https://api.anthropic.com/v1/models|x-api-key: invalid_token_test|anthropic-version: 2023-06-01"
  "Gemini|generativelanguage.googleapis.com|https://generativelanguage.googleapis.com/v1beta/models?key=invalid_token_test|Content-Type: application/json|"
  "Perplexity|api.perplexity.ai|https://api.perplexity.ai/v1/models|Accept: application/json|"
  "xAI|api.x.ai|https://api.x.ai/v1/models|Authorization: Bearer invalid_token_test|Content-Type: application/json"
  "DeepSeek|api.deepseek.com|https://api.deepseek.com/models|Authorization: Bearer invalid_token_test|Accept: application/json"
  "Mistral|api.mistral.ai|https://api.mistral.ai/v1/models|Authorization: Bearer invalid_token_test|Content-Type: application/json"
  "OpenRouter|openrouter.ai|https://openrouter.ai/api/v1/models|Accept: application/json|"
)

PUBLIC_DNS_SERVERS=("1.1.1.1" "8.8.8.8")

OPENAI_DOMAINS=("openai.com" "api.openai.com" "auth.openai.com" "platform.openai.com" "chatgpt.com" "oaiusercontent.com" "oaistatic.com")
ANTHROPIC_DOMAINS=("anthropic.com" "api.anthropic.com" "claude.ai" "claude.com" "claudeusercontent.com")
GOOGLE_DOMAINS=("google.com" "googleapis.com" "generativelanguage.googleapis.com" "gstatic.com" "googleusercontent.com" "ggpht.com" "ytimg.com" "withgoogle.com" "googletagmanager.com" "googlevideo.com" "gemini.google.com" "aistudio.google.com")
PERPLEXITY_DOMAINS=("perplexity.ai" "perplexity.com" "api.perplexity.ai")
XAI_DOMAINS=("x.ai" "grok.com" "api.x.ai")
MICROSOFT_DOMAINS=("copilot.microsoft.com" "bing.com")
MIDJOURNEY_DOMAINS=("midjourney.com" "alpha.midjourney.com")
DEEPSEEK_DOMAINS=("deepseek.com" "chat.deepseek.com" "api.deepseek.com" "platform.deepseek.com")
MISTRAL_DOMAINS=("mistral.ai" "chat.mistral.ai" "console.mistral.ai" "api.mistral.ai")
OTHER_DOMAINS=("character.ai" "poe.com" "openrouter.ai" "platform.openrouter.ai" "meta.ai" "you.com")

BASE_DOMAINS=("${OPENAI_DOMAINS[@]}" "${ANTHROPIC_DOMAINS[@]}" "${GOOGLE_DOMAINS[@]}" "${PERPLEXITY_DOMAINS[@]}" "${XAI_DOMAINS[@]}" "${MICROSOFT_DOMAINS[@]}" "${MIDJOURNEY_DOMAINS[@]}" "${DEEPSEEK_DOMAINS[@]}" "${MISTRAL_DOMAINS[@]}" "${OTHER_DOMAINS[@]}")

SERVER_IP=""
FIREWALL_BACKEND=""
NODE_WHITELIST_IPS=()

# ================= 基础输出与检查函数 =================
color() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
info() { printf "%b\n" "$(color 36 "ℹ️  $*")"; }
ok() { printf "%b\n" "$(color 32 "✅ $*")"; }
warn() { printf "%b\n" "$(color 33 "⚠️  $*")"; }
err() { printf "%b\n" "$(color 31 "❌ $*")"; }
pause() { read -n 1 -s -r -p "按任意键继续..."; printf "\n"; }

ensure_root() { [ "$EUID" -ne 0 ] && err "请使用 root 权限运行此脚本。" && exit 1; }
command_exists() { command -v "$1" >/dev/null 2>&1; }

ensure_base_dir() {
  mkdir -p "$BASE_DIR"
  touch "$CUSTOM_DOMAIN_FILE" "$NODE_WHITELIST_FILE"
}

detect_public_ip() {
  if [ -n "$SERVER_IP" ]; then printf '%s\n' "$SERVER_IP"; return; fi
  SERVER_IP="$(curl -fs4 --max-time 5 https://ifconfig.me 2>/dev/null || true)"
  if [ -z "$SERVER_IP" ] && command_exists hostname; then SERVER_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; fi
  if [ -z "$SERVER_IP" ]; then read -r -p "请输入解锁机公网 IP: " SERVER_IP; fi
  printf '%s\n' "$SERVER_IP"
}

detect_node_public_ip() {
  local ip=""
  if command_exists curl; then
    ip="$(curl -k -fs4 --max-time 5 https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '/^ip=/ {print $2; exit}')"
    if [ -z "$ip" ]; then ip="$(curl -fs4 --max-time 5 https://ifconfig.me 2>/dev/null || true)"; fi
  fi
  printf '%s\n' "$ip"
}

install_packages() {
  local packages=("$@")
  if command_exists apt-get; then apt-get update -y; DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
  elif command_exists dnf; then dnf install -y "${packages[@]}"
  elif command_exists yum; then yum install -y "${packages[@]}"
  elif command_exists pacman; then pacman -Sy --noconfirm "${packages[@]}"
  elif command_exists zypper; then zypper --non-interactive install -y "${packages[@]}"
  elif command_exists apk; then apk add --no-cache "${packages[@]}"
  else err "未找到包管理器。"; return 1; fi
}

# 强杀清理逻辑 (完全静默处理，避免输出乱码数字)
release_port_53() {
  if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
  fi
  if command_exists fuser; then fuser -k -9 53/tcp 53/udp >/dev/null 2>&1 || true; fi
}

release_port_443() {
  if command_exists fuser; then fuser -k -9 443/tcp >/dev/null 2>&1 || true; fi
  if command_exists killall; then killall -9 sniproxy >/dev/null 2>&1 || true; fi
}

service_restart() { 
  local svc="$1"
  if [ "$svc" == "sniproxy" ]; then release_port_443; sleep 1; fi
  if command_exists systemctl; then systemctl restart "$svc"; elif command_exists service; then service "$svc" restart; fi
}
service_enable() { local svc="$1"; if command_exists systemctl; then systemctl enable "$svc" >/dev/null 2>&1; fi; }
service_start() { 
  local svc="$1"
  if [ "$svc" == "sniproxy" ]; then release_port_443; sleep 1; fi
  if command_exists systemctl; then systemctl start "$svc"; elif command_exists service; then service "$svc" start; fi
}
service_stop() { local svc="$1"; if command_exists systemctl; then systemctl stop "$svc" >/dev/null 2>&1 || true; elif command_exists service; then service "$svc" stop >/dev/null 2>&1 || true; fi; }
service_status() { local svc="$1"; if command_exists systemctl; then systemctl is-active "$svc" >/dev/null 2>&1 && echo "active" || echo "inactive"; else echo "unknown"; fi; }

enable_sniproxy_default() {
  if [ -f "$SNI_DEFAULT" ]; then
    if grep -q '^ENABLED=' "$SNI_DEFAULT"; then
      sed -i 's/^ENABLED=.*/ENABLED=1/' "$SNI_DEFAULT"
    else
      printf '\nENABLED=1\n' >> "$SNI_DEFAULT"
    fi
  else
    printf 'ENABLED=1\n' > "$SNI_DEFAULT"
  fi
}

install_sniproxy_systemd_unit() {
  command_exists systemctl || return 0
  cat > "$SNI_SYSTEMD_SERVICE" <<EOF
[Unit]
Description=HTTPS SNI Proxy
Documentation=man:sniproxy(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/sbin/sniproxy -f -c $SNI_CONF
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
}

validate_sniproxy_config() {
  command_exists timeout || return 0
  command_exists sniproxy || return 0

  local log="/tmp/sniproxy-config-test.log" rc
  release_port_443
  timeout 3s /usr/sbin/sniproxy -f -c "$SNI_CONF" >"$log" 2>&1
  rc=$?
  release_port_443

  if [ "$rc" -eq 124 ]; then
    return 0
  fi

  err "SNIProxy 配置校验失败："
  cat "$log" 2>/dev/null || true
  return 1
}

show_sniproxy_failure() {
  warn "SNIProxy 启动失败，下面是系统日志："
  if command_exists systemctl; then
    systemctl status sniproxy --no-pager -l 2>/dev/null || true
  fi
  if command_exists journalctl; then
    journalctl -u sniproxy --no-pager -n 30 2>/dev/null || true
  fi
  if command_exists ss; then
    info "当前占用 443 端口的进程："
    ss -ltnp 'sport = :443' 2>/dev/null || true
  fi
}

# ================= 防火墙管理核心 =================
firewall_detect_backend() {
  if command_exists nft; then echo "nftables"; return; fi
  if command_exists iptables; then echo "iptables"; return; fi
  echo "none"
}

firewall_backend_ready() { [ "$(firewall_detect_backend)" != "none" ]; }

install_firewall_tools() {
  firewall_backend_ready && return 0
  install_packages nftables iptables || true
  firewall_backend_ready
}

firewall_init_backend() {
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    if ! nft list table inet ai_unlock >/dev/null 2>&1; then nft add table inet ai_unlock; fi
    if nft list chain inet ai_unlock input >/dev/null 2>&1; then nft flush chain inet ai_unlock input; else nft add chain inet ai_unlock input '{ type filter hook input priority 0; policy accept; }'; fi
    if ! nft list set inet ai_unlock node_whitelist >/dev/null 2>&1; then nft add set inet ai_unlock node_whitelist '{ type ipv4_addr; flags interval; }'; fi
    nft add rule inet ai_unlock input iifname "lo" accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol udp udp dport 53 drop 2>/dev/null || true
    nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 drop 2>/dev/null || true
    return 0
  fi
  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    if ! iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then iptables -N "$FIREWALL_CHAIN" 2>/dev/null || true; iptables -A "$FIREWALL_CHAIN" -j DROP 2>/dev/null || true; fi
    iptables -C "$FIREWALL_CHAIN" -i lo -j ACCEPT 2>/dev/null || iptables -I "$FIREWALL_CHAIN" 1 -i lo -j ACCEPT 2>/dev/null || true
    iptables -C INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || iptables -I INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -C INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || iptables -I INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null || true
    return 0
  fi
  return 1
}

load_node_whitelist() {
  NODE_WHITELIST_IPS=()
  [ -f "$NODE_WHITELIST_FILE" ] || return 0
  while IFS= read -r line; do
    line="$(echo "$line" | sed 's/^[ \t]*//;s/[ \t]*$//')"
    [ -z "$line" ] && continue
    case "$line" in \#*) continue ;; esac
    NODE_WHITELIST_IPS+=("$line")
  done < "$NODE_WHITELIST_FILE"
}

save_node_whitelist() {
  : > "$NODE_WHITELIST_FILE"
  for ip in "${NODE_WHITELIST_IPS[@]}"; do printf '%s\n' "$ip" >> "$NODE_WHITELIST_FILE"; done
}

sync_firewall_whitelist() {
  firewall_init_backend || return 1
  load_node_whitelist
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    nft flush set inet ai_unlock node_whitelist 2>/dev/null || true
    for ip in "${NODE_WHITELIST_IPS[@]}"; do
      validate_ipv4 "$ip" || continue
      nft add element inet ai_unlock node_whitelist "{ $ip }" 2>/dev/null || true
    done
    ok "nftables 白名单已同步。"
    return 0
  fi
  if [ "$FIREWALL_BACKEND" = "iptables" ]; then
    iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -i lo -j ACCEPT 2>/dev/null || true
    for ip in "${NODE_WHITELIST_IPS[@]}"; do
      validate_ipv4 "$ip" || continue
      iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
      iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
    done
    iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -j DROP 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -j DROP 2>/dev/null || true
    ok "iptables 白名单已同步。"
    return 0
  fi
  return 1
}

setup_firewall_persistence() {
  cat > "$SYNC_SCRIPT" << 'EOF'
#!/bin/bash
NODE_WHITELIST_FILE="/etc/ai_unlock/node_whitelist.conf"
FIREWALL_CHAIN="AI_UNLOCK_DNS"
if command -v nft >/dev/null 2>&1 && nft list table inet ai_unlock >/dev/null 2>&1; then
  if nft list chain inet ai_unlock input >/dev/null 2>&1; then
    nft flush chain inet ai_unlock input 2>/dev/null || true
  else
    nft add chain inet ai_unlock input '{ type filter hook input priority 0; policy accept; }' 2>/dev/null || true
  fi
  nft flush set inet ai_unlock node_whitelist 2>/dev/null || true
  nft add rule inet ai_unlock input iifname "lo" accept 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do [[ -z "$ip" || "$ip" == \#* ]] && continue; nft add element inet ai_unlock node_whitelist "{ $ip }" 2>/dev/null || true; done < "$NODE_WHITELIST_FILE"
  nft add rule inet ai_unlock input ip protocol udp udp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
  nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 ip saddr @node_whitelist accept 2>/dev/null || true
  nft add rule inet ai_unlock input ip protocol udp udp dport 53 drop 2>/dev/null || true
  nft add rule inet ai_unlock input ip protocol tcp tcp dport 53 drop 2>/dev/null || true
elif command -v iptables >/dev/null 2>&1 && iptables -nL "$FIREWALL_CHAIN" >/dev/null 2>&1; then
  iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
  iptables -A "$FIREWALL_CHAIN" -i lo -j ACCEPT 2>/dev/null || true
  [ -f "$NODE_WHITELIST_FILE" ] || exit 0
  while IFS= read -r ip; do
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
    iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -s "$ip" -j ACCEPT 2>/dev/null || true
  done < "$NODE_WHITELIST_FILE"
  iptables -A "$FIREWALL_CHAIN" -p udp --dport 53 -j DROP 2>/dev/null || true; iptables -A "$FIREWALL_CHAIN" -p tcp --dport 53 -j DROP 2>/dev/null || true
fi
EOF
  chmod +x "$SYNC_SCRIPT"

  cat > "$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=AI Unlock DNS Firewall Sync
After=network.target iptables.service nftables.service firewalld.service ufw.service

[Service]
Type=oneshot
ExecStart=/bin/bash $SYNC_SCRIPT
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

  if command_exists systemctl; then
    systemctl daemon-reload
    systemctl enable ai-unlock-firewall.service >/dev/null 2>&1
  fi
}

remove_firewall_rules() {
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  if [ "$FIREWALL_BACKEND" = "nftables" ]; then
    nft delete table inet ai_unlock 2>/dev/null || true
  elif [ "$FIREWALL_BACKEND" = "iptables" ]; then
    while iptables -D INPUT -p udp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null; do :; done
    while iptables -D INPUT -p tcp --dport 53 -j "$FIREWALL_CHAIN" 2>/dev/null; do :; done
    iptables -F "$FIREWALL_CHAIN" 2>/dev/null || true
    iptables -X "$FIREWALL_CHAIN" 2>/dev/null || true
  fi
}

validate_ipv4() {
  local ip="$1" a b c d extra; IFS=. read -r a b c d extra <<EOF
$ip
EOF
  [ -n "$a" ] && [ -n "$b" ] && [ -n "$c" ] && [ -n "$d" ] && [ -z "$extra" ] || return 1
  for octet in "$a" "$b" "$c" "$d"; do case "$octet" in ''|*[!0-9]*) return 1 ;; esac; [ "$octet" -ge 0 ] 2>/dev/null && [ "$octet" -le 255 ] 2>/dev/null || return 1; done
  return 0
}

# ================= 连通性测试与环境检查 =================
http_code_is_unlocked() {
  local code="$1"
  case "$code" in
    2*) return 0 ;;
    *) return 1 ;;
  esac
}

print_ai_http_result() {
  local prefix="$1" url="$2" code="$3"
  if [ -z "$code" ] || [ "$code" = "000" ]; then
    printf "  %b %s\n" "$(color 31 "[$prefix失败]")" "$url"
    return 1
  fi
  if http_code_is_unlocked "$code"; then
    printf "  %b %s\n" "$(color 32 "[$prefix通过]")" "$url"
    return 0
  fi
  case "$code" in
    401) printf "  %b %s\n" "$(color 33 "[$prefix需认证]")" "$url" ;;
    3*) printf "  %b %s\n" "$(color 33 "[$prefix跳转]")" "$url" ;;
    *) printf "  %b %s\n" "$(color 31 "[$prefix失败]")" "$url" ;;
  esac
  return 1
}

resolve_a_record() {
  local server="$1" domain="$2" resolved=""
  if command_exists dig; then
    resolved="$(dig @"$server" "$domain" A +time=3 +tries=1 +short 2>/dev/null | awk '/^[0-9]+\./ {print; exit}')"
  fi
  if [ -z "$resolved" ] && command_exists nslookup; then
    resolved="$(nslookup -type=A "$domain" "$server" 2>/dev/null | awk '/^Address: / {print $2}' | grep -E '^[0-9]+\.' | tail -n 1)"
  fi
  printf '%s\n' "$resolved"
}

print_port_check() {
  local proto="$1" port="$2" name="$3"
  if ! command_exists ss; then
    printf "  %b 未安装 ss，跳过 %s %s 检测\n" "$(color 33 "[跳过]")" "$name" "$port"
    return 1
  fi
  if [ "$proto" = "udp" ]; then
    if ss -H -lun "sport = :$port" 2>/dev/null | awk 'NF {found=1} END{exit found?0:1}'; then
      printf "  %b %s UDP %s 正在监听\n" "$(color 32 "[通过]")" "$name" "$port"
      return 0
    fi
    printf "  %b %s UDP %s 未监听\n" "$(color 31 "[失败]")" "$name" "$port"
    return 1
  fi
  if ss -H -ltn "sport = :$port" 2>/dev/null | awk 'NF {found=1} END{exit found?0:1}'; then
    printf "  %b %s TCP %s 正在监听\n" "$(color 32 "[通过]")" "$name" "$port"
    return 0
  fi
  printf "  %b %s TCP %s 未监听\n" "$(color 31 "[失败]")" "$name" "$port"
  return 1
}

check_unlock_dns_split() {
  local server_ip="$1" domain="$2" resolved
  resolved="$(resolve_a_record "127.0.0.1" "$domain")"
  if [ -z "$resolved" ]; then
    printf "  %b %s -> 无响应\n" "$(color 31 "[DNS失败]")" "$domain"
    return 1
  fi
  if [ "$resolved" = "$server_ip" ]; then
    printf "  %b %s -> %s\n" "$(color 32 "[DNS命中]")" "$domain" "$resolved"
    return 0
  fi
  printf "  %b %s -> %s（应为 %s）\n" "$(color 31 "[DNS错配]")" "$domain" "$resolved" "$server_ip"
  return 1
}

check_unlock_dns_forward() {
  local server_ip="$1" domain="${2:-example.com}" resolved
  resolved="$(resolve_a_record "127.0.0.1" "$domain")"
  if [ -z "$resolved" ]; then
    printf "  %b %s -> 无响应\n" "$(color 31 "[转发失败]")" "$domain"
    return 1
  fi
  if [ "$resolved" = "$server_ip" ]; then
    printf "  %b %s -> %s（普通域名不应回解锁机）\n" "$(color 31 "[转发错配]")" "$domain" "$resolved"
    return 1
  fi
  printf "  %b %s -> %s\n" "$(color 32 "[转发通过]")" "$domain" "$resolved"
  return 0
}

check_ai_api_endpoint() {
  local server_ip="$1" name="$2" host="$3" url="$4" header1="$5" header2="$6"
  local code="" try
  for try in 1 2; do
    if [ -n "$header2" ]; then
      code="$(curl -k -sS --connect-timeout 5 --max-time 12 \
        --resolve "${host}:443:${server_ip}" \
        -H "$header1" -H "$header2" \
        -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    else
      code="$(curl -k -sS --connect-timeout 5 --max-time 12 \
        --resolve "${host}:443:${server_ip}" \
        -H "$header1" \
        -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
    fi
    [ -n "$code" ] && [ "$code" != "000" ] && break
    sleep 1
  done
  case "$code" in
    ""|000)
      printf "  %b %-10s %s\n" "$(color 31 "[失败]")" "$name" "$host"
      return 1
      ;;
    403|451)
      printf "  %b %-10s %s HTTP %s\n" "$(color 31 "[受限]")" "$name" "$host" "$code"
      return 1
      ;;
    *)
      printf "  %b %-10s %s HTTP %s\n" "$(color 32 "[可达]")" "$name" "$host" "$code"
      return 0
      ;;
  esac
}

check_all_ai_api_unlock() {
  local server_ip="$1" item name host url header1 header2 ok_count=0 total=0
  for item in "${AI_API_CHECKS[@]}"; do
    IFS='|' read -r name host url header1 header2 <<EOF
$item
EOF
    total=$((total + 1))
    if check_ai_api_endpoint "$server_ip" "$name" "$host" "$url" "$header1" "$header2"; then
      ok_count=$((ok_count + 1))
    fi
  done
  printf "  可达: %s/%s\n" "$ok_count" "$total"
}

collect_ai_check_hosts() {
  local item name host url header1 header2 seen_hosts="" check_host
  for item in "${AI_API_CHECKS[@]}"; do
    IFS='|' read -r name host url header1 header2 <<EOF
$item
EOF
    [ -z "$host" ] && continue
    case " $seen_hosts " in *" $host "*) continue ;; esac
    seen_hosts="$seen_hosts $host"
    printf '%s\n' "$host"
  done
  for check_host in "${AI_CHECK_HOSTS[@]}"; do
    [ -z "$check_host" ] && continue
    case " $seen_hosts " in *" $check_host "*) continue ;; esac
    seen_hosts="$seen_hosts $check_host"
    printf '%s\n' "$check_host"
  done
}

show_unlock_summary() {
  clear
  local server_ip
  server_ip="$(detect_public_ip)"
  printf "%b\n" "$(color 36 "======================================")"
  printf "%b\n" "$(color 36 "           运行状态检测")"
  printf "%b\n" "$(color 36 "======================================")"
  printf "公网 IP: %s\n" "$server_ip"
  echo "--------------------------------------"
  printf "核心服务状态：\n"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
  
  if [ "$(service_status sniproxy)" != "active" ]; then
    warn "SNIProxy 未运行！系统可能存在其他进程死锁 443 端口。"
  fi
  
  echo "--------------------------------------"
  FIREWALL_BACKEND="$(firewall_detect_backend)"
  printf "防火墙后端: %s (放行 IP 数: %s)\n" "$FIREWALL_BACKEND" "$([ -s "$NODE_WHITELIST_FILE" ] && wc -l < "$NODE_WHITELIST_FILE" || echo 0)"
  echo "--------------------------------------"
  printf "端口监听：\n"
  print_port_check udp 53 "dnsmasq"
  print_port_check tcp 53 "dnsmasq"
  print_port_check tcp 443 "sniproxy"
  echo "--------------------------------------"
  printf "DNS 分流检测（查询本机 dnsmasq）：\n"
  local domain dns_ok_count=0 dns_total=0
  check_unlock_dns_forward "$server_ip" "example.com" || true
  while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    dns_total=$((dns_total + 1))
    if check_unlock_dns_split "$server_ip" "$domain"; then dns_ok_count=$((dns_ok_count + 1)); fi
  done < <(collect_ai_check_hosts)
  printf "  AI 域名命中: %s/%s\n" "$dns_ok_count" "$dns_total"
  echo "--------------------------------------"
  printf "AI API 连通检测：\n"
  check_all_ai_api_unlock "127.0.0.1" || true
  echo "--------------------------------------"
}

show_service_status_detail() {
  local svc="$1"
  printf "\n%b\n" "$(color 36 "===== $svc 状态 =====")"
  if command_exists systemctl; then
    systemctl status "$svc" --no-pager -l 2>/dev/null || true
  elif command_exists service; then
    service "$svc" status 2>/dev/null || true
  else
    warn "当前系统没有 systemctl/service，无法查看服务状态。"
  fi
}

show_service_logs() {
  local svc="$1"
  printf "\n%b\n" "$(color 36 "===== $svc 最近日志 =====")"
  if command_exists journalctl; then
    journalctl -u "$svc" --no-pager -n 80 2>/dev/null || true
  else
    show_service_status_detail "$svc"
  fi
}

show_unlock_logs() {
  show_service_status_detail dnsmasq
  show_service_logs dnsmasq
  show_service_status_detail sniproxy
  show_service_logs sniproxy
  if command_exists ss; then
    printf "\n%b\n" "$(color 36 "===== 端口监听 =====")"
    ss -lntup 2>/dev/null | awk 'NR==1 || /:53|:443/'
  fi
  printf "\n%b\n" "$(color 36 "===== 节点白名单 =====")"
  if [ -s "$NODE_WHITELIST_FILE" ]; then
    cat "$NODE_WHITELIST_FILE"
  else
    printf "  暂无节点 IP\n"
  fi
  printf "\n%b\n" "$(color 36 "===== 防火墙规则 =====")"
  if command_exists nft && nft list table inet ai_unlock >/dev/null 2>&1; then
    nft list table inet ai_unlock 2>/dev/null || true
  elif command_exists iptables; then
    iptables -nL "$FIREWALL_CHAIN" 2>/dev/null || true
  else
    warn "未检测到 nftables/iptables。"
  fi
}

restart_unlock_services() {
  update_rules || return 1
  ok "解锁规则已重新生成，服务已重启。"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
}

stop_unlock_services() {
  service_stop dnsmasq
  service_stop sniproxy
  if command_exists killall; then killall -9 sniproxy >/dev/null 2>&1 || true; fi
  ok "解锁服务已暂停。"
  printf "  dnsmasq: %s\n" "$(service_status dnsmasq)"
  printf "  sniproxy: %s\n" "$(service_status sniproxy)"
}

# ================= Web 面板 =================
random_string() {
  if command_exists tr; then tr -dc 'A-Za-z0-9' </dev/urandom 2>/dev/null | head -c "${1:-24}"; else date +%s%N; fi
}

panel_port() {
  if [ -s "$PANEL_PORT_FILE" ]; then tr -cd '0-9' < "$PANEL_PORT_FILE"; else printf '%s' "$PANEL_DEFAULT_PORT"; fi
}


panel_status() {
  local port show_ip
  port="$(panel_port)"
  show_ip="$(detect_public_ip)"
  printf "Web 面板服务: %s\n" "$(service_status ai-unlock-panel)"
  printf "访问地址: http://%s:%s\n" "$show_ip" "$port"
}

panel_logs() {
  if command_exists journalctl; then journalctl -u ai-unlock-panel --no-pager -n 80; else panel_status; fi
}

change_panel_port() {
  local old_port new_port
  old_port="$(panel_port)"
  read -r -p "输入新的 Web 面板端口 [当前 $old_port]: " new_port
  [ -z "$new_port" ] && return 0
  if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [ "$new_port" -lt 1 ] || [ "$new_port" -gt 65535 ]; then warn "端口无效。"; return 1; fi
  printf '%s\n' "$new_port" > "$PANEL_PORT_FILE"
  service_restart ai-unlock-panel
  ok "端口已修改。"
  panel_status
}

reset_panel_password() {
  local pass
  pass="$(random_string 18)"
  set_panel_password "admin" "$pass" || return 1
  service_restart ai-unlock-panel
  ok "Web 面板密码已重置。"
  printf "用户名: admin\n新密码: %s\n" "$pass"
}

stop_panel_service() {
  service_stop ai-unlock-panel
  ok "Web 面板已停止。"
}


panel_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           Web 面板管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 安装/更新 Web 面板\n" "$(color 32 "1.")"
    printf "  %b 查看面板状态\n" "$(color 32 "2.")"
    printf "  %b 查看面板日志\n" "$(color 32 "3.")"
    printf "  %b 修改面板端口\n" "$(color 32 "4.")"
    printf "  %b 重置登录密码\n" "$(color 32 "5.")"
    printf "  %b 停止面板\n" "$(color 32 "6.")"
    printf "  %b 卸载面板程序\n" "$(color 32 "7.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-7]: " choice
    case "$choice" in
      1) install_panel_service; pause ;;
      2) panel_status; pause ;;
      3) panel_logs; pause ;;
      4) change_panel_port; pause ;;
      5) reset_panel_password; pause ;;
      6) stop_panel_service; pause ;;
      7) uninstall_panel_service; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}


write_embedded_panel_source() {
  local source_dir="$BASE_DIR/panel_src"
  rm -rf "$source_dir"
  mkdir -p "$source_dir/src"
  cat > "$source_dir/Cargo.toml" <<'AI_UNLOCK_PANEL_CARGO_EOF'
[package]
name = "ai-unlock-panel"
version = "0.1.0"
edition = "2021"

[dependencies]
axum = { version = "0.7", features = ["macros"] }
hmac = "0.12"
pbkdf2 = "0.12"
rand = "0.8"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
tokio = { version = "1", features = ["full"] }
tower-cookies = "0.10"
time = "=0.3.36"
urlencoding = "2"
uuid = { version = "1", features = ["v4", "serde"] }
AI_UNLOCK_PANEL_CARGO_EOF
  cat > "$source_dir/src/main.rs" <<'AI_UNLOCK_PANEL_MAIN_EOF'
use axum::{
    extract::{Form, Query, State},
    http::{header::HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Router,
};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{distributions::Alphanumeric, Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{
    collections::{BTreeSet, HashMap},
    env, fs, io,
    net::SocketAddr,
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpListener;
use tower_cookies::{cookie::SameSite, Cookie, CookieManagerLayer, Cookies};
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

struct ApiCheck {
    name: &'static str,
    host: &'static str,
    url: &'static str,
    header1: &'static str,
    header2: &'static str,
}

const BASE_DIR: &str = "/etc/ai_unlock";
const CUSTOM_DOMAIN_FILE: &str = "/etc/ai_unlock/custom_domains.conf";
const NODE_WHITELIST_FILE: &str = "/etc/ai_unlock/node_whitelist.conf";
const NODES_FILE: &str = "/etc/ai_unlock/nodes.json";
const AUTH_FILE: &str = "/etc/ai_unlock/panel_auth.conf";
const SECRET_FILE: &str = "/etc/ai_unlock/panel_secret";
const TOKEN_FILE: &str = "/etc/ai_unlock/node_join_token";
const PORT_FILE: &str = "/etc/ai_unlock/panel_port.conf";
const DNSMASQ_CONF: &str = "/etc/dnsmasq.d/ai_unlock.conf";
const SNI_CONF: &str = "/etc/sniproxy.conf";
const SNI_CONF_DIR: &str = "/etc/sniproxy/sniproxy.conf";
const SNI_DEFAULT: &str = "/etc/default/sniproxy";
const SNI_SYSTEMD_SERVICE: &str = "/etc/systemd/system/sniproxy.service";
const FIREWALL_CHAIN: &str = "AI_UNLOCK_DNS";
const DEFAULT_PORT: u16 = 8088;
const PUBLIC_DNS: &[&str] = &["1.1.1.1", "8.8.8.8"];
const API_CHECKS: &[ApiCheck] = &[
    ApiCheck { name: "OpenAI", host: "api.openai.com", url: "https://api.openai.com/v1/models", header1: "Authorization: Bearer invalid_token_test", header2: "Content-Type: application/json" },
    ApiCheck { name: "Anthropic", host: "api.anthropic.com", url: "https://api.anthropic.com/v1/models", header1: "x-api-key: invalid_token_test", header2: "anthropic-version: 2023-06-01" },
    ApiCheck { name: "Gemini", host: "generativelanguage.googleapis.com", url: "https://generativelanguage.googleapis.com/v1beta/models?key=invalid_token_test", header1: "Content-Type: application/json", header2: "" },
    ApiCheck { name: "Perplexity", host: "api.perplexity.ai", url: "https://api.perplexity.ai/v1/models", header1: "Accept: application/json", header2: "" },
    ApiCheck { name: "xAI", host: "api.x.ai", url: "https://api.x.ai/v1/models", header1: "Authorization: Bearer invalid_token_test", header2: "Content-Type: application/json" },
    ApiCheck { name: "DeepSeek", host: "api.deepseek.com", url: "https://api.deepseek.com/models", header1: "Authorization: Bearer invalid_token_test", header2: "Accept: application/json" },
    ApiCheck { name: "Mistral", host: "api.mistral.ai", url: "https://api.mistral.ai/v1/models", header1: "Authorization: Bearer invalid_token_test", header2: "Content-Type: application/json" },
    ApiCheck { name: "OpenRouter", host: "openrouter.ai", url: "https://openrouter.ai/api/v1/models", header1: "Accept: application/json", header2: "" },
];
const BASE_DOMAINS: &[&str] = &[
    "openai.com",
    "api.openai.com",
    "auth.openai.com",
    "platform.openai.com",
    "chatgpt.com",
    "oaiusercontent.com",
    "oaistatic.com",
    "anthropic.com",
    "api.anthropic.com",
    "claude.ai",
    "claude.com",
    "claudeusercontent.com",
    "google.com",
    "googleapis.com",
    "generativelanguage.googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "ggpht.com",
    "ytimg.com",
    "withgoogle.com",
    "googletagmanager.com",
    "googlevideo.com",
    "gemini.google.com",
    "aistudio.google.com",
    "perplexity.ai",
    "perplexity.com",
    "api.perplexity.ai",
    "x.ai",
    "grok.com",
    "api.x.ai",
    "copilot.microsoft.com",
    "bing.com",
    "midjourney.com",
    "alpha.midjourney.com",
    "deepseek.com",
    "chat.deepseek.com",
    "api.deepseek.com",
    "platform.deepseek.com",
    "mistral.ai",
    "chat.mistral.ai",
    "console.mistral.ai",
    "api.mistral.ai",
    "character.ai",
    "poe.com",
    "openrouter.ai",
    "platform.openrouter.ai",
    "meta.ai",
    "you.com",
];

#[derive(Clone)]
struct AppState {
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    failures: Arc<Mutex<HashMap<String, Failure>>>,
    secret: Arc<Vec<u8>>,
    join_token: Arc<String>,
    port: u16,
}

#[derive(Clone)]
struct Session {
    expires: u64,
    csrf: String,
}

#[derive(Clone, Default)]
struct Failure {
    count: u32,
    last: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Node {
    id: String,
    ip: String,
    name: String,
    note: String,
    created: String,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--hash-password") {
        let user = args.get(2).map(String::as_str).unwrap_or("admin");
        let pass = args.get(3).map(String::as_str).unwrap_or("");
        if pass.is_empty() {
            eprintln!("password is empty");
            std::process::exit(2);
        }
        println!("{}", make_auth_line(user, pass));
        return Ok(());
    }

    ensure_base()?;
    let port = read_port();
    let state = Arc::new(AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        failures: Arc::new(Mutex::new(HashMap::new())),
        secret: Arc::new(ensure_secret()?),
        join_token: Arc::new(ensure_token()?),
        port,
    });

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_page).post(login_post))
        .route("/logout", post(logout))
        .route("/nodes", get(nodes_page))
        .route("/nodes/add", post(nodes_add))
        .route("/nodes/edit", post(nodes_edit))
        .route("/nodes/delete", post(nodes_delete))
        .route("/nodes/batch-add", post(nodes_batch_add))
        .route("/nodes/batch-delete", post(nodes_batch_delete))
        .route("/domains", get(domains_page))
        .route("/domains/add", post(domains_add))
        .route("/domains/delete", post(domains_delete))
        .route("/domains/clear", post(domains_clear))
        .route("/action/update", post(action_update))
        .route("/action/sync", post(action_sync))
        .route("/action/stop", post(action_stop))
        .route("/node.sh", get(node_script))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    println!("AI Unlock Panel listening on http://{addr}");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

async fn login_page(State(state): State<Arc<AppState>>, cookies: Cookies) -> Response {
    if auth_session(&state, &cookies).is_some() {
        return Redirect::to("/").into_response();
    }
    Html(login_html("")).into_response()
}

async fn login_post(
    State(state): State<Arc<AppState>>,
    cookies: Cookies,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let remote = headers
        .get("x-real-ip")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("local")
        .to_string();

    {
        let failures = state.failures.lock().unwrap();
        if let Some(f) = failures.get(&remote) {
            if f.count >= 8 && now() - f.last < 600 {
                return Html(login_html("失败次数过多，请稍后再试")).into_response();
            }
        }
    }

    let username = form.get("username").map(String::as_str).unwrap_or("");
    let password = form.get("password").map(String::as_str).unwrap_or("");
    if verify_password(username, password) {
        let sid = random_string(40);
        let csrf = random_string(32);
        state.sessions.lock().unwrap().insert(
            sid.clone(),
            Session {
                expires: now() + 43200,
                csrf,
            },
        );
        let mut cookie = Cookie::new("ai_unlock_session", format!("{}.{}", sid, sign(&state.secret, &sid)));
        cookie.set_path("/");
        cookie.set_http_only(true);
        cookie.set_same_site(SameSite::Strict);
        cookies.add(cookie);
        return Redirect::to("/").into_response();
    }

    let mut failures = state.failures.lock().unwrap();
    let f = failures.entry(remote).or_default();
    f.count += 1;
    f.last = now();
    Html(login_html("用户名或密码错误")).into_response()
}

async fn logout(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/").into_response();
    }
    state.sessions.lock().unwrap().remove(&sid);
    let mut cookie = Cookie::new("ai_unlock_session", "");
    cookie.set_path("/");
    cookies.remove(cookie);
    Redirect::to("/login").into_response()
}

async fn dashboard(State(state): State<Arc<AppState>>, cookies: Cookies, headers: HeaderMap, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{}:{}", detect_public_ip(), state.port));
    Html(layout("仪表盘", &session, &dashboard_html(&state, &session, &host, &q))).into_response()
}

async fn nodes_page(State(state): State<Arc<AppState>>, cookies: Cookies, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    let nodes = load_nodes().unwrap_or_default();
    Html(layout("节点管理", &session, &nodes_html(&session, &nodes, &q))).into_response()
}

async fn domains_page(State(state): State<Arc<AppState>>, cookies: Cookies, Query(q): Query<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    let custom = load_custom_domains().unwrap_or_default();
    Html(layout("域名池", &session, &domains_html(&session, &custom, &q))).into_response()
}

async fn nodes_add(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/nodes?err=csrf").into_response();
    }
    let ip = form.get("ip").map(String::as_str).unwrap_or("").trim();
    if !valid_ip(ip) {
        return Redirect::to("/nodes?err=bad_ip").into_response();
    }
    let mut nodes = load_nodes().unwrap_or_default();
    if nodes.iter().any(|n| n.ip == ip) {
        return Redirect::to("/nodes?err=exists").into_response();
    }
    nodes.push(Node {
        id: Uuid::new_v4().to_string(),
        ip: ip.to_string(),
        name: val(&form, "name"),
        note: val(&form, "note"),
        created: now_label(),
    });
    let _ = save_nodes(&nodes, true);
    Redirect::to("/nodes?ok=saved").into_response()
}

async fn nodes_edit(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/nodes?err=csrf").into_response();
    }
    let id = val(&form, "id");
    let ip = val(&form, "ip");
    if !valid_ip(&ip) {
        return Redirect::to("/nodes?err=bad_ip").into_response();
    }
    let mut nodes = load_nodes().unwrap_or_default();
    if nodes.iter().any(|n| n.id != id && n.ip == ip) {
        return Redirect::to("/nodes?err=exists").into_response();
    }
    for n in &mut nodes {
        if n.id == id {
            n.ip = ip.clone();
            n.name = val(&form, "name");
            n.note = val(&form, "note");
        }
    }
    let _ = save_nodes(&nodes, true);
    Redirect::to("/nodes?ok=saved").into_response()
}

async fn nodes_delete(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/nodes?err=csrf").into_response();
    }
    let id = val(&form, "id");
    let mut nodes = load_nodes().unwrap_or_default();
    nodes.retain(|n| n.id != id);
    let _ = save_nodes(&nodes, true);
    Redirect::to("/nodes?ok=deleted").into_response()
}

async fn nodes_batch_add(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/nodes?err=csrf").into_response();
    }
    let mut nodes = load_nodes().unwrap_or_default();
    let mut seen: BTreeSet<String> = nodes.iter().map(|n| n.ip.clone()).collect();
    for line in val(&form, "items").replace(',', " ").lines() {
        let parts = line.split_whitespace().collect::<Vec<_>>();
        if parts.is_empty() || !valid_ip(parts[0]) || seen.contains(parts[0]) {
            continue;
        }
        nodes.push(Node {
            id: Uuid::new_v4().to_string(),
            ip: parts[0].to_string(),
            name: parts[1..].join(" "),
            note: String::new(),
            created: now_label(),
        });
        seen.insert(parts[0].to_string());
    }
    let _ = save_nodes(&nodes, true);
    Redirect::to("/nodes?ok=saved").into_response()
}

async fn nodes_batch_delete(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/nodes?err=csrf").into_response();
    }
    let ips = val(&form, "items")
        .replace(',', " ")
        .split_whitespace()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let mut nodes = load_nodes().unwrap_or_default();
    nodes.retain(|n| !ips.contains(&n.ip));
    let _ = save_nodes(&nodes, true);
    Redirect::to("/nodes?ok=deleted").into_response()
}

async fn domains_add(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/domains?err=csrf").into_response();
    }
    let domain = clean_domain(&val(&form, "domain"));
    if domain.is_empty() {
        return Redirect::to("/domains?err=bad_domain").into_response();
    }
    let mut domains = load_custom_domains().unwrap_or_default();
    if !domains.contains(&domain) {
        domains.push(domain);
    }
    let _ = save_custom_domains(&domains);
    Redirect::to("/domains?ok=saved").into_response()
}

async fn domains_delete(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/domains?err=csrf").into_response();
    }
    let domain = val(&form, "domain");
    let mut domains = load_custom_domains().unwrap_or_default();
    domains.retain(|d| d != &domain);
    let _ = save_custom_domains(&domains);
    Redirect::to("/domains?ok=deleted").into_response()
}

async fn domains_clear(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    let Some((_sid, session)) = auth_session(&state, &cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, &form) {
        return Redirect::to("/domains?err=csrf").into_response();
    }
    let _ = save_custom_domains(&[]);
    Redirect::to("/domains?ok=cleared").into_response()
}

async fn action_update(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    action_guard(&state, &cookies, &form, || update_rules())
}

async fn action_sync(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    action_guard(&state, &cookies, &form, || sync_firewall(&load_nodes().unwrap_or_default()))
}

async fn action_stop(State(state): State<Arc<AppState>>, cookies: Cookies, Form(form): Form<HashMap<String, String>>) -> Response {
    action_guard(&state, &cookies, &form, || {
        run_ignore("systemctl", &["stop", "dnsmasq"]);
        run_ignore("systemctl", &["stop", "sniproxy"]);
        Ok(())
    })
}

fn action_guard<F>(state: &AppState, cookies: &Cookies, form: &HashMap<String, String>, f: F) -> Response
where
    F: FnOnce() -> io::Result<()>,
{
    let Some((_sid, session)) = auth_session(state, cookies) else {
        return Redirect::to("/login").into_response();
    };
    if !csrf_ok(&session, form) {
        return Redirect::to("/?err=csrf").into_response();
    }
    let _ = f();
    Redirect::to("/?ok=done").into_response()
}

async fn node_script(State(state): State<Arc<AppState>>, Query(q): Query<HashMap<String, String>>) -> Response {
    if q.get("token").map(String::as_str) != Some(state.join_token.as_str()) {
        return (StatusCode::FORBIDDEN, "forbidden").into_response();
    }
    let ip = detect_public_ip();
    let body = format!(
        r#"#!/bin/bash
set -e
[ "$EUID" -ne 0 ] && echo "请使用 root 权限运行" && exit 1
UNLOCK_IP="{ip}"
if command -v systemctl >/dev/null 2>&1 && systemctl is-active systemd-resolved >/dev/null 2>&1; then
  systemctl stop systemd-resolved 2>/dev/null || true
  systemctl disable systemd-resolved 2>/dev/null || true
fi
chattr -i /etc/resolv.conf 2>/dev/null || true
rm -f /etc/resolv.conf
printf 'nameserver %s\n' "$UNLOCK_IP" > /etc/resolv.conf
chattr +i /etc/resolv.conf 2>/dev/null || true
echo "节点机 DNS 已指向 $UNLOCK_IP"
"#
    );
    ([(axum::http::header::CONTENT_TYPE, "text/x-shellscript; charset=utf-8")], body).into_response()
}

fn dashboard_html(state: &AppState, session: &Session, host: &str, q: &HashMap<String, String>) -> String {
    let ip = detect_public_ip();
    let nodes = load_nodes().unwrap_or_default();
    let quick = format!(
        "curl -fsSL http://{}/node.sh?token={} | bash",
        host,
        urlencoding::encode(&state.join_token)
    );
    let api_checks = API_CHECKS
        .iter()
        .map(|check| {
            let ok = check_ai_api(check, "127.0.0.1");
            format!(
                r#"<div class="check"><span class="{}">{}</span><strong>{}: {}</strong></div>"#,
                if ok { "ok" } else { "bad" },
                if ok { "可达" } else { "失败" },
                html(check.name),
                html(check.host)
            )
        })
        .collect::<String>();
    format!(
        r#"{flash}
<section class="grid metrics">
  <div class="metric"><span>公网 IP</span><strong>{ip}</strong></div>
  <div class="metric"><span>dnsmasq</span><strong class="{dns_cls}">{dns}</strong></div>
  <div class="metric"><span>sniproxy</span><strong class="{sni_cls}">{sni}</strong></div>
  <div class="metric"><span>白名单节点</span><strong>{count}</strong></div>
</section>
<section class="glass">
  <div class="head"><div><h2>快捷操作</h2><p>规则、白名单和服务控制。</p></div></div>
  <div class="actions">
    <form method="post" action="/action/update"><input type="hidden" name="csrf" value="{csrf}"><button>重新生成规则</button></form>
    <form method="post" action="/action/sync"><input type="hidden" name="csrf" value="{csrf}"><button>同步白名单</button></form>
    <form method="post" action="/action/stop"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">暂停服务</button></form>
  </div>
</section>
<section class="glass"><div class="head"><div><h2>节点机快速使用命令</h2><p>在节点机 root 终端执行。</p></div></div><pre class="cmd">{quick}</pre></section>
<section class="glass"><div class="head"><div><h2>AI API 连通检测</h2></div></div><div class="checks">{api_checks}</div></section>"#,
        flash = flash(q),
        ip = html(&ip),
        dns = service_status("dnsmasq"),
        sni = service_status("sniproxy"),
        dns_cls = if service_status("dnsmasq") == "active" { "ok" } else { "bad" },
        sni_cls = if service_status("sniproxy") == "active" { "ok" } else { "bad" },
        count = nodes.len(),
        csrf = html(&session.csrf),
        quick = html(&quick),
        api_checks = api_checks
    )
}

fn nodes_html(session: &Session, nodes: &[Node], q: &HashMap<String, String>) -> String {
    let rows = nodes
        .iter()
        .map(|n| {
            format!(
                r#"<tr>
<td><code>{ip}</code></td>
<td><form class="inline" method="post" action="/nodes/edit"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{id}"><input name="ip" value="{ip}"><input name="name" value="{name}" placeholder="名称"><input name="note" value="{note}" placeholder="备注"><button>保存</button></form></td>
<td class="muted">{created}</td>
<td><form method="post" action="/nodes/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{id}"><button class="ghost danger">删除</button></form></td>
</tr>"#,
                ip = html(&n.ip),
                id = html(&n.id),
                name = html(&n.name),
                note = html(&n.note),
                created = html(&n.created),
                csrf = html(&session.csrf)
            )
        })
        .collect::<String>();
    format!(
        r#"{flash}
<section class="grid split">
  <div class="glass"><div class="head"><div><h2>添加节点</h2><p>添加后自动同步白名单。</p></div></div><form class="stack" method="post" action="/nodes/add"><input type="hidden" name="csrf" value="{csrf}"><label>节点公网 IP<input name="ip" required placeholder="1.2.3.4"></label><label>名称<input name="name"></label><label>备注<input name="note"></label><button>添加节点</button></form></div>
  <div class="glass"><div class="head"><div><h2>批量添加</h2><p>每行一个 IP，可跟名称。</p></div></div><form class="stack" method="post" action="/nodes/batch-add"><input type="hidden" name="csrf" value="{csrf}"><textarea name="items" rows="7" placeholder="1.2.3.4 节点A&#10;5.6.7.8 节点B"></textarea><button>批量添加</button></form></div>
</section>
<section class="glass"><div class="head"><div><h2>节点列表</h2><p>共 {count} 个。</p></div></div><div class="table"><table><thead><tr><th>IP</th><th>编辑</th><th>添加时间</th><th></th></tr></thead><tbody>{rows}</tbody></table></div></section>
<section class="glass"><div class="head"><div><h2>批量删除</h2><p>输入要删除的 IP。</p></div></div><form class="stack" method="post" action="/nodes/batch-delete"><input type="hidden" name="csrf" value="{csrf}"><textarea name="items" rows="5"></textarea><button class="danger">批量删除</button></form></section>"#,
        flash = flash(q),
        csrf = html(&session.csrf),
        count = nodes.len(),
        rows = rows
    )
}

fn domains_html(session: &Session, custom: &[String], q: &HashMap<String, String>) -> String {
    let custom_html = if custom.is_empty() {
        r#"<p class="muted">暂无自定义域名</p>"#.to_string()
    } else {
        custom
            .iter()
            .map(|d| {
                format!(
                    r#"<div class="domain"><code>{}</code><form method="post" action="/domains/delete"><input type="hidden" name="csrf" value="{}"><input type="hidden" name="domain" value="{}"><button class="ghost danger">删除</button></form></div>"#,
                    html(d),
                    html(&session.csrf),
                    html(d)
                )
            })
            .collect::<String>()
    };
    let pills = BASE_DOMAINS
        .iter()
        .map(|d| format!(r#"<span class="pill">{}</span>"#, html(d)))
        .collect::<String>();
    format!(
        r#"{flash}
<section class="glass"><div class="head"><div><h2>添加自定义域名</h2><p>保存后自动重新生成规则。</p></div></div><form class="row" method="post" action="/domains/add"><input type="hidden" name="csrf" value="{csrf}"><input name="domain" required placeholder="example.ai"><button>添加</button></form></section>
<section class="glass"><div class="head"><div><h2>自定义域名池</h2><p>共 {count} 个。</p></div></div>{custom}<form method="post" action="/domains/clear"><input type="hidden" name="csrf" value="{csrf}"><button class="danger">清空自定义域名</button></form></section>
<section class="glass"><div class="head"><div><h2>默认域名池</h2><p>内置只读。</p></div></div><div class="pills">{pills}</div></section>"#,
        flash = flash(q),
        csrf = html(&session.csrf),
        count = custom.len(),
        custom = custom_html,
        pills = pills
    )
}

fn layout(title: &str, session: &Session, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} - AI Unlock</title><style>{css}</style></head>
<body>
<div class="bg"></div>
<header class="nav"><div class="brand">AI Unlock</div><nav><a href="/">仪表盘</a><a href="/nodes">节点管理</a><a href="/domains">域名池</a></nav><form method="post" action="/logout"><input type="hidden" name="csrf" value="{csrf}"><button class="ghost">退出</button></form></header>
<main class="wrap"><div class="page-title"><h1>{title}</h1></div>{body}</main>
</body></html>"#,
        title = html(title),
        css = CSS,
        csrf = html(&session.csrf),
        body = body
    )
}

fn login_html(error: &str) -> String {
    let err = if error.is_empty() {
        String::new()
    } else {
        format!(r#"<div class="alert bad">{}</div>"#, html(error))
    };
    format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>登录 - AI Unlock</title><style>{css}</style></head><body class="login"><div class="bg"></div><form class="login-box" method="post" action="/login"><h1>AI Unlock</h1><p>登录管理面板</p>{err}<label>用户名<input name="username" value="admin" autocomplete="username"></label><label>密码<input name="password" type="password" autocomplete="current-password" autofocus></label><button>登录</button></form></body></html>"#,
        css = CSS,
        err = err
    )
}

fn auth_session(state: &AppState, cookies: &Cookies) -> Option<(String, Session)> {
    let cookie = cookies.get("ai_unlock_session")?;
    let value = cookie.value();
    let (sid, sig) = value.split_once('.')?;
    if sign(&state.secret, sid) != sig {
        return None;
    }
    let session = state.sessions.lock().unwrap().get(sid).cloned()?;
    if session.expires < now() {
        return None;
    }
    Some((sid.to_string(), session))
}

fn csrf_ok(session: &Session, form: &HashMap<String, String>) -> bool {
    form.get("csrf").map(String::as_str) == Some(session.csrf.as_str())
}

fn flash(q: &HashMap<String, String>) -> String {
    if let Some(ok) = q.get("ok") {
        let msg = match ok.as_str() {
            "saved" => "已保存",
            "deleted" => "已删除",
            "cleared" => "已清空",
            "done" => "操作完成",
            _ => "操作完成",
        };
        return format!(r#"<div class="alert ok">{msg}</div>"#);
    }
    if let Some(err) = q.get("err") {
        let msg = match err.as_str() {
            "csrf" => "页面已过期，请刷新重试",
            "bad_ip" => "IP 格式错误",
            "exists" => "IP 已存在",
            "bad_domain" => "域名格式错误",
            _ => "操作失败",
        };
        return format!(r#"<div class="alert bad">{msg}</div>"#);
    }
    String::new()
}

fn ensure_base() -> io::Result<()> {
    fs::create_dir_all(BASE_DIR)?;
    touch(CUSTOM_DOMAIN_FILE)?;
    touch(NODE_WHITELIST_FILE)?;
    Ok(())
}

fn touch(path: &str) -> io::Result<()> {
    if !Path::new(path).exists() {
        fs::write(path, "")?;
    }
    Ok(())
}

fn read_port() -> u16 {
    fs::read_to_string(PORT_FILE)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(DEFAULT_PORT)
}

fn ensure_secret() -> io::Result<Vec<u8>> {
    if let Ok(raw) = fs::read_to_string(SECRET_FILE) {
        let raw = raw.trim();
        if !raw.is_empty() {
            return Ok(raw.as_bytes().to_vec());
        }
    }
    let value = random_string(64).into_bytes();
    fs::write(SECRET_FILE, &value)?;
    Ok(value)
}

fn ensure_token() -> io::Result<String> {
    if let Ok(raw) = fs::read_to_string(TOKEN_FILE) {
        let raw = raw.trim();
        if !raw.is_empty() {
            return Ok(raw.to_string());
        }
    }
    let value = random_string(32);
    fs::write(TOKEN_FILE, format!("{value}\n"))?;
    Ok(value)
}

fn verify_password(user: &str, password: &str) -> bool {
    let raw = fs::read_to_string(AUTH_FILE).unwrap_or_default();
    let parts = raw.trim().split(':').collect::<Vec<_>>();
    if parts.len() != 3 || parts[0] != user {
        return false;
    }
    let Some(salt) = hex_decode(parts[1]) else {
        return false;
    };
    let Some(expected) = hex_decode(parts[2]) else {
        return false;
    };
    let mut actual = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 180_000, &mut actual);
    hmac_eq(&actual, &expected)
}

fn make_auth_line(user: &str, password: &str) -> String {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut digest = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 180_000, &mut digest);
    format!("{}:{}:{}", user, hex_encode(&salt), hex_encode(&digest))
}

fn load_nodes() -> io::Result<Vec<Node>> {
    if Path::new(NODES_FILE).exists() {
        if let Ok(raw) = fs::read_to_string(NODES_FILE) {
            if let Ok(nodes) = serde_json::from_str(&raw) {
                return Ok(nodes);
            }
        }
    }
    let mut nodes = Vec::new();
    if let Ok(raw) = fs::read_to_string(NODE_WHITELIST_FILE) {
        for line in raw.lines() {
            let ip = line.trim();
            if valid_ip(ip) {
                nodes.push(Node {
                    id: Uuid::new_v4().to_string(),
                    ip: ip.to_string(),
                    name: String::new(),
                    note: String::new(),
                    created: now_label(),
                });
            }
        }
    }
    save_nodes(&nodes, false)?;
    Ok(nodes)
}

fn save_nodes(nodes: &[Node], sync: bool) -> io::Result<()> {
    fs::write(NODES_FILE, serde_json::to_string_pretty(nodes).unwrap_or_default())?;
    let mut whitelist = String::new();
    for node in nodes {
        if valid_ip(&node.ip) {
            whitelist.push_str(&node.ip);
            whitelist.push('\n');
        }
    }
    fs::write(NODE_WHITELIST_FILE, whitelist)?;
    if sync {
        sync_firewall(nodes)?;
    }
    Ok(())
}

fn load_custom_domains() -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    if let Ok(raw) = fs::read_to_string(CUSTOM_DOMAIN_FILE) {
        for line in raw.lines() {
            let domain = clean_domain(line);
            if !domain.is_empty() && !out.contains(&domain) {
                out.push(domain);
            }
        }
    }
    Ok(out)
}

fn save_custom_domains(domains: &[String]) -> io::Result<()> {
    fs::write(CUSTOM_DOMAIN_FILE, domains.join("\n") + if domains.is_empty() { "" } else { "\n" })?;
    update_rules()
}

fn collect_domains() -> io::Result<Vec<String>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for domain in BASE_DOMAINS {
        let domain = clean_domain(domain);
        if !domain.is_empty() && seen.insert(domain.clone()) {
            out.push(domain);
        }
    }
    for domain in load_custom_domains()? {
        if seen.insert(domain.clone()) {
            out.push(domain);
        }
    }
    Ok(out)
}

fn sync_firewall(nodes: &[Node]) -> io::Result<()> {
    if command_exists("nft") {
        run_ignore("nft", &["add", "table", "inet", "ai_unlock"]);
        run_ignore("nft", &["add", "set", "inet", "ai_unlock", "node_whitelist", "{ type ipv4_addr; flags interval; }"]);
        if run_status("nft", &["list", "chain", "inet", "ai_unlock", "input"]) {
            run_ignore("nft", &["flush", "chain", "inet", "ai_unlock", "input"]);
        } else {
            run_ignore("nft", &["add", "chain", "inet", "ai_unlock", "input", "{ type filter hook input priority 0; policy accept; }"]);
        }
        run_ignore("nft", &["flush", "set", "inet", "ai_unlock", "node_whitelist"]);
        for node in nodes {
            if valid_ip(&node.ip) {
                run_ignore("nft", &["add", "element", "inet", "ai_unlock", "node_whitelist", &format!("{{ {} }}", node.ip)]);
            }
        }
        for rule in [
            vec!["iifname", "lo", "accept"],
            vec!["ip", "protocol", "udp", "udp", "dport", "53", "ip", "saddr", "@node_whitelist", "accept"],
            vec!["ip", "protocol", "tcp", "tcp", "dport", "53", "ip", "saddr", "@node_whitelist", "accept"],
            vec!["ip", "protocol", "udp", "udp", "dport", "53", "drop"],
            vec!["ip", "protocol", "tcp", "tcp", "dport", "53", "drop"],
        ] {
            let mut args = vec!["add", "rule", "inet", "ai_unlock", "input"];
            args.extend(rule);
            run_ignore("nft", &args);
        }
    } else if command_exists("iptables") {
        if !run_status("iptables", &["-nL", FIREWALL_CHAIN]) {
            run_ignore("iptables", &["-N", FIREWALL_CHAIN]);
        }
        run_ignore("iptables", &["-F", FIREWALL_CHAIN]);
        run_ignore("iptables", &["-A", FIREWALL_CHAIN, "-i", "lo", "-j", "ACCEPT"]);
        for node in nodes {
            if valid_ip(&node.ip) {
                run_ignore("iptables", &["-A", FIREWALL_CHAIN, "-p", "udp", "--dport", "53", "-s", &node.ip, "-j", "ACCEPT"]);
                run_ignore("iptables", &["-A", FIREWALL_CHAIN, "-p", "tcp", "--dport", "53", "-s", &node.ip, "-j", "ACCEPT"]);
            }
        }
        run_ignore("iptables", &["-A", FIREWALL_CHAIN, "-p", "udp", "--dport", "53", "-j", "DROP"]);
        run_ignore("iptables", &["-A", FIREWALL_CHAIN, "-p", "tcp", "--dport", "53", "-j", "DROP"]);
        if !run_status("iptables", &["-C", "INPUT", "-p", "udp", "--dport", "53", "-j", FIREWALL_CHAIN]) {
            run_ignore("iptables", &["-I", "INPUT", "-p", "udp", "--dport", "53", "-j", FIREWALL_CHAIN]);
        }
        if !run_status("iptables", &["-C", "INPUT", "-p", "tcp", "--dport", "53", "-j", FIREWALL_CHAIN]) {
            run_ignore("iptables", &["-I", "INPUT", "-p", "tcp", "--dport", "53", "-j", FIREWALL_CHAIN]);
        }
    }
    Ok(())
}

fn update_rules() -> io::Result<()> {
    fs::create_dir_all("/etc/dnsmasq.d")?;
    let server_ip = detect_public_ip();
    let domains = collect_domains()?;
    let mut dns = String::from("# generated by ai-unlock-panel\nport=53\nlisten-address=0.0.0.0\nbind-interfaces\nno-resolv\n");
    for upstream in PUBLIC_DNS {
        dns.push_str(&format!("server={upstream}\n"));
    }
    dns.push_str("cache-size=10000\ndomain-needed\nbogus-priv\n");
    for domain in &domains {
        dns.push_str(&format!("local=/{domain}/\naddress=/{domain}/{server_ip}\n"));
    }
    fs::write(DNSMASQ_CONF, dns)?;

    let listen = if output("ip", &["-6", "addr", "show", "scope", "global"]).contains("inet6") {
        "443"
    } else {
        "0.0.0.0:443"
    };
    let mut sni = format!(
        "user daemon\npidfile /var/run/sniproxy.pid\n\nerror_log {{\n    syslog daemon\n    priority notice\n}}\n\nlisten {listen} {{\n    proto tls\n    table https_hosts\n}}\n\ntable https_hosts {{\n"
    );
    for domain in &domains {
        let escaped = domain.replace('.', "\\.");
        sni.push_str(&format!("    ^{escaped}$ *:443\n    .*\\.{escaped}$ *:443\n"));
    }
    sni.push_str("    .* *:443\n}\n");
    fs::write(SNI_CONF, &sni)?;
    fs::create_dir_all("/etc/sniproxy")?;
    fs::write(SNI_CONF_DIR, sni)?;
    enable_sniproxy()?;
    run_ignore("systemctl", &["restart", "dnsmasq"]);
    run_ignore("systemctl", &["restart", "sniproxy"]);
    Ok(())
}

fn enable_sniproxy() -> io::Result<()> {
    let mut data = fs::read_to_string(SNI_DEFAULT).unwrap_or_default();
    if data.lines().any(|line| line.starts_with("ENABLED=")) {
        data = data
            .lines()
            .map(|line| if line.starts_with("ENABLED=") { "ENABLED=1" } else { line })
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
    } else {
        data.push_str("\nENABLED=1\n");
    }
    fs::write(SNI_DEFAULT, data)?;
    fs::write(
        SNI_SYSTEMD_SERVICE,
        format!(
            "[Unit]\nDescription=HTTPS SNI Proxy\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=/usr/sbin/sniproxy -f -c {SNI_CONF}\nExecReload=/bin/kill -HUP $MAINPID\nRestart=on-failure\nRestartSec=2\n\n[Install]\nWantedBy=multi-user.target\n"
        ),
    )?;
    run_ignore("systemctl", &["daemon-reload"]);
    Ok(())
}

fn detect_public_ip() -> String {
    let ip = output("curl", &["-fs4", "--max-time", "5", "https://ifconfig.me"]);
    if valid_ip(&ip) {
        return ip;
    }
    output("sh", &["-c", "hostname -I 2>/dev/null | awk '{print $1}'"])
}

fn check_ai_api(check: &ApiCheck, server_ip: &str) -> bool {
    if server_ip.is_empty() {
        return false;
    }
    let resolve = format!("{}:443:{server_ip}", check.host);
    let mut command = Command::new("curl");
    command.args([
        "-k",
        "-sS",
        "--connect-timeout",
        "5",
        "--max-time",
        "12",
        "--resolve",
        resolve.as_str(),
        "-H",
        check.header1,
    ]);
    if !check.header2.is_empty() {
        command.args(["-H", check.header2]);
    }
    command.args(["-o", "/dev/null", "-w", "%{http_code}", check.url]);
    let code = command
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default();
    !code.is_empty() && code != "000" && code != "403" && code != "451"
}

fn service_status(name: &str) -> String {
    if run_status("systemctl", &["is-active", name]) {
        "active".to_string()
    } else {
        "inactive".to_string()
    }
}

fn command_exists(cmd: &str) -> bool {
    run_status("sh", &["-c", &format!("command -v {} >/dev/null 2>&1", shell_word(cmd))])
}

fn run_status(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn run_ignore(program: &str, args: &[&str]) {
    let _ = Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn output(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn clean_domain(input: &str) -> String {
    let mut s = input.trim().to_ascii_lowercase();
    if let Some(pos) = s.find("://") {
        s = s[(pos + 3)..].to_string();
    }
    if let Some(rest) = s.strip_prefix("*.") {
        s = rest.to_string();
    }
    if let Some(pos) = s.find('/') {
        s.truncate(pos);
    }
    if let Some(pos) = s.find(':') {
        s.truncate(pos);
    }
    if s.contains('.') && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-') {
        s
    } else {
        String::new()
    }
}

fn valid_ip(ip: &str) -> bool {
    let parts = ip.split('.').collect::<Vec<_>>();
    parts.len() == 4
        && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && p.parse::<u8>().is_ok())
}

fn val(form: &HashMap<String, String>, key: &str) -> String {
    form.get(key).map(|v| v.trim().to_string()).unwrap_or_default()
}

fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

fn sign(secret: &[u8], data: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
    mac.update(data.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn hmac_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn now_label() -> String {
    output("date", &["+%Y-%m-%d %H:%M"])
}

fn html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn shell_word(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

const CSS: &str = r#"
:root{--primary:#3b82f6;--danger:#ef4444;--success:#10b981;--warn:#d97706;--ink:#374151;--muted:#6b7280}
*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:#e9eef6;letter-spacing:0}.bg{position:fixed;inset:0;z-index:-1;background:linear-gradient(135deg,#d8e6f7 0%,#eef2f7 45%,#d7efe7 100%)}.nav{position:sticky;top:0;z-index:10;background:rgba(255,255,255,.34);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border-bottom:1px solid rgba(255,255,255,.45);padding:14px 28px;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{font-weight:800;font-size:18px}.nav nav{display:flex;gap:8px}.nav a{color:var(--ink);text-decoration:none;border-radius:12px;padding:9px 12px}.nav a:hover{background:rgba(255,255,255,.42)}.wrap{width:min(1180px,94vw);margin:24px auto 40px;display:grid;gap:18px}.page-title h1{margin:0;font-size:28px}.grid{display:grid;gap:16px}.metrics{grid-template-columns:repeat(4,minmax(0,1fr))}.split{grid-template-columns:repeat(2,minmax(0,1fr))}.glass,.metric,.login-box{background:rgba(255,255,255,.38);backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);border:1px solid rgba(255,255,255,.58);border-radius:18px;box-shadow:0 8px 30px rgba(31,41,55,.06);padding:20px}.metric span{display:block;color:var(--muted);font-size:13px}.metric strong{display:block;margin-top:6px;font-size:24px;overflow-wrap:anywhere}.head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:15px}.head h2{margin:0;font-size:18px}.head p{margin:3px 0 0;color:var(--muted)}button{border:0;border-radius:12px;background:rgba(59,130,246,.9);color:white;padding:10px 15px;font-weight:700;cursor:pointer;white-space:nowrap}button:hover{filter:brightness(.96);transform:translateY(-1px)}button.danger,.danger{background:rgba(239,68,68,.9);color:white}button.ghost,.ghost{background:rgba(255,255,255,.55);color:var(--ink)}.actions{display:flex;gap:10px;flex-wrap:wrap}input,textarea{width:100%;border:1px solid rgba(255,255,255,.55);background:rgba(255,255,255,.55);border-radius:12px;padding:11px 12px;color:var(--ink);outline:none}input:focus,textarea:focus{background:rgba(255,255,255,.82);border-color:#93c5fd}textarea{resize:vertical}.stack{display:grid;gap:12px}label{display:grid;gap:6px;color:var(--muted)}.row{display:grid;grid-template-columns:1fr auto;gap:10px}.inline{display:grid;grid-template-columns:135px 1fr 1fr auto;gap:8px}.table{overflow:auto}table{width:100%;border-collapse:separate;border-spacing:0 10px}th{color:var(--muted);text-align:left;font-size:13px;padding:0 10px}td{background:rgba(255,255,255,.42);padding:10px;border-top:1px solid rgba(255,255,255,.44);border-bottom:1px solid rgba(255,255,255,.44)}td:first-child{border-left:1px solid rgba(255,255,255,.44);border-radius:14px 0 0 14px}td:last-child{border-right:1px solid rgba(255,255,255,.44);border-radius:0 14px 14px 0}code,.cmd{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.cmd{margin:0;background:rgba(15,23,42,.88);color:#eef6ff;border-radius:14px;padding:15px;white-space:pre-wrap;overflow:auto}.checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.check{display:flex;justify-content:space-between;gap:12px;background:rgba(255,255,255,.42);border:1px solid rgba(255,255,255,.48);border-radius:14px;padding:10px 12px}.ok{color:var(--success)}.bad{color:var(--danger)}.warn{color:var(--warn)}.muted{color:var(--muted)}.alert{border-radius:14px;padding:11px 13px;background:rgba(255,255,255,.5);border:1px solid rgba(255,255,255,.6)}.alert.ok{color:#047857}.alert.bad{color:#b91c1c}.pills{display:flex;flex-wrap:wrap;gap:8px}.pill{background:rgba(255,255,255,.45);border:1px solid rgba(255,255,255,.55);border-radius:999px;padding:7px 11px}.domain{display:flex;align-items:center;justify-content:space-between;background:rgba(255,255,255,.42);border:1px solid rgba(255,255,255,.5);border-radius:14px;padding:10px 12px;margin-bottom:8px}.login{min-height:100vh;display:grid;place-items:center;padding:24px}.login-box{width:min(390px,92vw);display:grid;gap:16px;text-align:left}.login-box h1{margin:0;font-size:28px}.login-box p{margin:0;color:var(--muted)}@media(max-width:780px){.nav{padding:12px 16px;flex-wrap:wrap}.wrap{margin:18px auto}.metrics,.split,.checks{grid-template-columns:1fr}.inline{grid-template-columns:1fr}th{display:none}tr,td{display:block}td{border:0!important;border-radius:0!important}td:first-child{border-radius:14px 14px 0 0!important}td:last-child{border-radius:0 0 14px 14px!important}}
"#;
AI_UNLOCK_PANEL_MAIN_EOF
  printf '%s
' "$source_dir"
}

prepare_panel_source() {
  write_embedded_panel_source
}

cargo_supports_2024() {
  command_exists cargo || return 1
  local version major minor rest
  version="$(cargo -V 2>/dev/null | awk '{print $2}')"
  major="${version%%.*}"
  rest="${version#*.}"
  minor="${rest%%.*}"
  [ -n "$major" ] && [ -n "$minor" ] || return 1
  if [ "$major" -gt 1 ] 2>/dev/null; then return 0; fi
  if [ "$major" -eq 1 ] 2>/dev/null && [ "$minor" -ge 85 ] 2>/dev/null; then return 0; fi
  return 1
}

install_rustup_stable() {
  command_exists curl || install_packages curl ca-certificates || return 1
  info "系统 Cargo 过旧，安装 rustup stable 工具链..."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable || return 1
  if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
  cargo_supports_2024
}

install_rust_build_deps() {
  if command_exists cargo && command_exists rustc && cargo_supports_2024; then return 0; fi
  info "安装 Rust 本地编译环境..."
  if command_exists apt-get; then
    apt-get update -y
    DEBIAN_FRONTEND=noninteractive apt-get install -y cargo rustc build-essential pkg-config ca-certificates curl
  elif command_exists dnf; then
    dnf install -y cargo rust rustc gcc gcc-c++ make pkgconf-pkg-config ca-certificates curl
  elif command_exists yum; then
    yum install -y cargo rust rustc gcc gcc-c++ make pkgconfig ca-certificates curl
  elif command_exists pacman; then
    pacman -Sy --noconfirm cargo rust base-devel pkgconf ca-certificates curl
  elif command_exists zypper; then
    zypper --non-interactive install -y cargo rust gcc gcc-c++ make pkg-config ca-certificates curl
  elif command_exists apk; then
    apk add --no-cache cargo rust build-base pkgconf ca-certificates curl
  else
    err "未找到可用包管理器，无法安装 Rust。"
    return 1
  fi
  if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi
  if command_exists cargo && command_exists rustc && cargo_supports_2024; then return 0; fi
  install_rustup_stable || {
    err "Cargo 版本过旧，且 rustup stable 安装失败。请手动安装 Rust 1.85+ 后重试。"
    return 1
  }
}

set_panel_password() {
  local user="${1:-admin}" pass="$2"
  [ -z "$pass" ] && return 1
  [ -x "$PANEL_BIN" ] || return 1
  "$PANEL_BIN" --hash-password "$user" "$pass" > "$PANEL_AUTH_FILE"
}

install_panel_service() {
  ensure_root
  ensure_base_dir

  local source_dir port input_port pass show_ip reset_pass
  source_dir="$(prepare_panel_source)" || return 1
  if [ ! -f "$source_dir/Cargo.toml" ] || [ ! -f "$source_dir/src/main.rs" ]; then
    err "未找到 Rust 面板源码：$source_dir"
    return 1
  fi

  install_rust_build_deps || return 1
  if [ -f "$HOME/.cargo/env" ]; then . "$HOME/.cargo/env"; fi

  port="${AI_UNLOCK_PANEL_PORT:-$(panel_port)}"
  if [ -z "${AI_UNLOCK_PANEL_PORT:-}" ]; then
    read -r -p "Web 面板端口 [${port}]: " input_port
  fi
  [ -n "$input_port" ] && port="$input_port"
  if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then warn "端口无效。"; return 1; fi
  printf '%s\n' "$port" > "$PANEL_PORT_FILE"

  info "复制 Rust 面板源码..."
  rm -rf "$PANEL_WORK_DIR"
  mkdir -p "$PANEL_WORK_DIR"
  cp -a "$source_dir/." "$PANEL_WORK_DIR/"

  info "本地编译 Rust 面板..."
  (cd "$PANEL_WORK_DIR" && cargo build --release) || return 1
  install -m 755 "$PANEL_WORK_DIR/target/release/ai-unlock-panel" "$PANEL_BIN" || return 1

  if [ ! -s "$PANEL_AUTH_FILE" ]; then
    pass="$(random_string 18)"
    set_panel_password "admin" "$pass" || return 1
  else
    reset_pass="${AI_UNLOCK_PANEL_RESET_PASSWORD:-}"
    if [ -z "$reset_pass" ]; then
      read -r -p "是否重置 Web 面板 admin 密码？(y/N): " reset_pass
    fi
    if [ "$reset_pass" = "y" ] || [ "$reset_pass" = "Y" ]; then
      pass="$(random_string 18)"
      set_panel_password "admin" "$pass" || return 1
    fi
  fi

  [ -s "$PANEL_SECRET_FILE" ] || random_string 64 > "$PANEL_SECRET_FILE"
  [ -s "$PANEL_TOKEN_FILE" ] || random_string 32 > "$PANEL_TOKEN_FILE"

  cat > "$PANEL_SERVICE" <<EOF
[Unit]
Description=AI Unlock Web Panel
After=network-online.target dnsmasq.service sniproxy.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$PANEL_BIN
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

  if command_exists systemctl; then
    systemctl daemon-reload
    systemctl enable ai-unlock-panel.service >/dev/null 2>&1
    systemctl restart ai-unlock-panel.service
  fi

  show_ip="$(detect_public_ip)"
  ok "Rust Web 面板已本地编译并启动。"
  printf "访问地址: http://%s:%s\n" "$show_ip" "$port"
  printf "用户名: admin\n"
  [ -n "$pass" ] && printf "初始密码: %s\n" "$pass"
  warn "请在云安全组放行面板端口，建议只允许自己的 IP 访问。"
}

cleanup_panel_rust_artifacts() {
  rm -f "$PANEL_BIN"
  rm -rf "$PANEL_WORK_DIR"
  rm -rf "$BASE_DIR/panel_src"
}

uninstall_panel_service() {
  if command_exists systemctl; then
    systemctl disable ai-unlock-panel.service 2>/dev/null || true
    systemctl stop ai-unlock-panel.service 2>/dev/null || true
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$PANEL_SERVICE"
  cleanup_panel_rust_artifacts
  ok "Web 面板程序已卸载。"
}

# ================= 核心环境安装/更新 =================
is_unlock_installed() { if [ -f "$DNSMASQ_CONF" ] && [ -f "$SNI_CONF" ]; then return 0; fi; return 1; }
confirm_reinstall_requested() { if ! is_unlock_installed; then return 0; fi; read -r -p "检测到已安装，覆盖重装更新配置？(y/N): " confirm; case "$confirm" in y|Y) return 0 ;; *) warn "已取消。"; return 1 ;; esac; }
require_unlock_installed() {
  if is_unlock_installed; then return 0; fi
  warn "请先执行【安装】完成解锁机部署。"
  return 1
}

sanitize_domain() { printf '%s' "$1" | sed -e 's#^[a-zA-Z][a-zA-Z0-9+.-]*://##' -e 's#^\\*\\.##' -e 's#/.*##' -e 's/:.*//'; }
write_custom_domains() { : > "$CUSTOM_DOMAIN_FILE"; for domain in "${CUSTOM_DOMAINS[@]}"; do printf '%s\n' "$domain" >> "$CUSTOM_DOMAIN_FILE"; done; }

load_custom_domains() {
  CUSTOM_DOMAINS=()
  [ -f "$CUSTOM_DOMAIN_FILE" ] || return 0
  while IFS= read -r line; do
    line="$(sanitize_domain "$line")"; [ -z "$line" ] && continue; case "$line" in \#*) continue ;; esac; CUSTOM_DOMAINS+=("$line")
  done < "$CUSTOM_DOMAIN_FILE"
}

collect_domains() {
  declare -A seen=()
  for domain in "${BASE_DOMAINS[@]}"; do domain="$(sanitize_domain "$domain")"; [ -z "$domain" ] && continue; if [ -z "${seen[$domain]+x}" ]; then seen["$domain"]=1; printf '%s\n' "$domain"; fi; done
  load_custom_domains
  for domain in "${CUSTOM_DOMAINS[@]}"; do domain="$(sanitize_domain "$domain")"; [ -z "$domain" ] && continue; if [ -z "${seen[$domain]+x}" ]; then seen["$domain"]=1; printf '%s\n' "$domain"; fi; done
}

escape_regex_domain() { printf '%s' "$1" | sed 's/\./\\./g'; }

update_rules() {
  ensure_base_dir; mkdir -p /etc/dnsmasq.d
  SERVER_IP="$(detect_public_ip)"
  info "生成分流配置..."
  {
    printf '# generated by ai_unlock installer\n'
    printf 'port=53\n'
    printf 'listen-address=0.0.0.0\n'
    printf 'bind-interfaces\n'
    printf 'no-resolv\n'
    for dns in "${PUBLIC_DNS_SERVERS[@]}"; do printf 'server=%s\n' "$dns"; done
    printf 'cache-size=10000\n'
    printf 'domain-needed\n'
    printf 'bogus-priv\n'
    while IFS= read -r domain; do
      [ -z "$domain" ] && continue
      printf 'local=/%s/\n' "$domain"
      printf 'address=/%s/%s\n' "$domain" "$SERVER_IP"
    done < <(collect_domains)
  } > "$DNSMASQ_CONF"
  
  # 智能判断 IPv6 环境：若系统有公网 IPv6 则双栈监听，否则只监听 IPv4 防止报错崩溃
  local listen_addr="0.0.0.0:443"
  if ip -6 addr show scope global 2>/dev/null | grep -q "inet6"; then
    listen_addr="443"
  fi

  {
    cat <<EOF
user daemon
pidfile /var/run/sniproxy.pid

error_log {
    syslog daemon
    priority notice
}

listen $listen_addr {
    proto tls
    table https_hosts
}

table https_hosts {
EOF
    while IFS= read -r domain; do [ -z "$domain" ] && continue; escaped="$(escape_regex_domain "$domain")"; printf '    ^%s$ *:443\n    .*\\.%s$ *:443\n' "$escaped" "$escaped"; done < <(collect_domains)
    printf '    .* *:443\n'
    printf '}\n'
  } > "$SNI_CONF"
  mkdir -p "$(dirname "$SNI_CONF_DIR")"
  cp -f "$SNI_CONF" "$SNI_CONF_DIR"

  # 重启时会触发前面的强杀逻辑，确保干干净净拉起新进程
  service_restart dnsmasq
  enable_sniproxy_default
  install_sniproxy_systemd_unit
  validate_sniproxy_config || return 1
  service_start sniproxy
  if [ "$(service_status sniproxy)" != "active" ]; then
    show_sniproxy_failure
    return 1
  fi
  ok "配置已更新并重启服务。"
}

install_unlock_core() {
  if ! confirm_reinstall_requested; then return 1; fi
  
  info "环境准备与清理..."
  release_port_53
  release_port_443

  info "安装依赖组件..."
  install_packages dnsmasq sniproxy curl e2fsprogs iproute2 psmisc dnsutils || return 1
  install_firewall_tools || true
  firewall_init_backend || warn "未检测到可用防火墙后端。"

  enable_sniproxy_default
  install_sniproxy_systemd_unit
  service_enable dnsmasq; service_enable sniproxy
  update_rules
  setup_firewall_persistence
  
  show_unlock_summary
  ok "部署完成！请进入白名单管理添加节点 IP。"
}

uninstall_unlock_core() {
  read -r -p "确认彻底卸载并清理全部环境？(y/n): " confirm
  if [ "$confirm" = "y" ]; then
    info "正在清理服务与残留..."
    if command_exists systemctl; then
      systemctl disable ai-unlock-panel.service 2>/dev/null || true
      systemctl stop ai-unlock-panel.service 2>/dev/null || true
      systemctl disable ai-unlock-firewall.service 2>/dev/null || true
      systemctl stop ai-unlock-firewall.service 2>/dev/null || true
      systemctl disable sniproxy.service 2>/dev/null || true
      systemctl stop sniproxy.service 2>/dev/null || true
      systemctl daemon-reload 2>/dev/null || true
    fi
    rm -f "$PANEL_SERVICE" "$SYSTEMD_SERVICE" "$SNI_SYSTEMD_SERVICE"
    remove_firewall_rules
    cleanup_panel_rust_artifacts
    
    rm -rf "$BASE_DIR"
    rm -f "$DNSMASQ_CONF" "$SNI_CONF" "$SNI_CONF_DIR"
    
    service_stop dnsmasq
    service_stop sniproxy
    release_port_443
    
    ok "清理完毕。"
  fi
}

# ================= DNS 辅助 =================
write_public_resolv_conf() {
  chattr -i /etc/resolv.conf 2>/dev/null || true; rm -f /etc/resolv.conf
  for dns in "${PUBLIC_DNS_SERVERS[@]}"; do printf 'nameserver %s\n' "$dns" >> /etc/resolv.conf; done
}

backup_resolv_conf() { ensure_base_dir; if [ ! -f "$RESOLV_BACKUP" ]; then cp -a /etc/resolv.conf "$RESOLV_BACKUP" 2>/dev/null || true; fi; }
restore_resolv_conf() {
  chattr -i /etc/resolv.conf 2>/dev/null || true
  write_public_resolv_conf
  ok "已恢复公共 DNS: ${PUBLIC_DNS_SERVERS[*]}"
}

# ================= 菜单管理系统 =================
show_domain_pool() {
  load_custom_domains
  printf "\n%b\n" "$(color 36 "默认域名池")"
  local i=1; for d in "${BASE_DOMAINS[@]}"; do printf "  [%b] %s\n" "$(color 33 "$i")" "$d"; ((i++)); done
  
  printf "\n%b\n" "$(color 36 "自定义域名池")"
  if [ "${#CUSTOM_DOMAINS[@]}" -eq 0 ]; then echo "  暂无"; else 
    local j=1; for d in "${CUSTOM_DOMAINS[@]}"; do printf "  [%b] %s\n" "$(color 33 "$j")" "$d"; ((j++)); done
  fi
  echo ""
}

domain_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         域名池管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 查看域名池\n" "$(color 32 "1.")"
    printf "  %b 添加自定义域名\n" "$(color 32 "2.")"
    printf "  %b 删除自定义域名\n" "$(color 32 "3.")"
    printf "  %b 清空自定义域名\n" "$(color 32 "4.")"
    printf "  %b 恢复默认配置\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice
    case "$choice" in
      1) show_domain_pool; pause ;;
      2) read -r -p "输入要添加的域名: " d; d="$(sanitize_domain "$d")"; if [ -n "$d" ]; then load_custom_domains; CUSTOM_DOMAINS+=("$d"); write_custom_domains; ok "已添加 $d"; update_rules; fi; pause ;;
      3) 
         load_custom_domains
         if [ "${#CUSTOM_DOMAINS[@]}" -eq 0 ]; then warn "无自定义域名。"; pause; continue; fi
         show_domain_pool; read -r -p "输入要删除的序号: " idx
         if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#CUSTOM_DOMAINS[@]}" ]; then
           local del_d="${CUSTOM_DOMAINS[$((idx - 1))]}"; local nx=(); for d in "${CUSTOM_DOMAINS[@]}"; do if [ "$d" != "$del_d" ]; then nx+=("$d"); fi; done
           CUSTOM_DOMAINS=("${nx[@]}"); write_custom_domains; ok "已删除: $del_d"; update_rules
         else warn "序号无效。"; fi; pause ;;
      4) CUSTOM_DOMAINS=(); write_custom_domains; ok "已清空"; update_rules; pause ;;
      5) : > "$CUSTOM_DOMAIN_FILE"; ok "已恢复默认"; update_rules; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

list_firewall_whitelist() {
  firewall_init_backend || return 1
  load_node_whitelist
  printf "防火墙后端: %s\n" "$FIREWALL_BACKEND"
  if [ "${#NODE_WHITELIST_IPS[@]}" -eq 0 ]; then printf "  暂无节点 IP\n"; else
    local i=1; for ip in "${NODE_WHITELIST_IPS[@]}"; do printf "  [%b] %s\n" "$(color 33 "$i")" "$ip"; ((i++)); done
  fi
}

firewall_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         白名单管理")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 查看白名单\n" "$(color 32 "1.")"
    printf "  %b 添加单个 IP\n" "$(color 32 "2.")"
    printf "  %b 批量添加 IP\n" "$(color 32 "3.")"
    printf "  %b 删除节点 IP\n" "$(color 32 "4.")"
    printf "  %b 清空白名单\n" "$(color 32 "5.")"
    printf "  %b 返回\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-5]: " choice
    case "$choice" in
      1) list_firewall_whitelist; echo ""; pause ;;
      2) read -r -p "输入要放行的 IP: " ip; if ! validate_ipv4 "$ip"; then warn "IP 格式错误。"; else load_node_whitelist; local exists=0; for item in "${NODE_WHITELIST_IPS[@]}"; do if [ "$item" = "$ip" ]; then exists=1; break; fi; done; if [ "$exists" -eq 1 ]; then warn "IP 已存在。"; else NODE_WHITELIST_IPS+=("$ip"); save_node_whitelist; sync_firewall_whitelist; fi; fi; pause ;;
      3) read -r -p "输入多个 IP(用空格或逗号分隔): " list; list="$(printf '%s' "$list" | tr ',' ' ')"; load_node_whitelist; for ip in $list; do validate_ipv4 "$ip" || continue; local exists=0; for item in "${NODE_WHITELIST_IPS[@]}"; do if [ "$item" = "$ip" ]; then exists=1; break; fi; done; if [ "$exists" -eq 0 ]; then NODE_WHITELIST_IPS+=("$ip"); ok "已加入 $ip"; fi; done; save_node_whitelist; sync_firewall_whitelist; pause ;;
      4) 
         load_node_whitelist
         if [ "${#NODE_WHITELIST_IPS[@]}" -eq 0 ]; then warn "当前没有白名单。"; pause; continue; fi
         list_firewall_whitelist; echo ""
         read -r -p "请输入序号删除: " idx
         if [[ "$idx" =~ ^[0-9]+$ ]] && [ "$idx" -ge 1 ] && [ "$idx" -le "${#NODE_WHITELIST_IPS[@]}" ]; then
           local del_ip="${NODE_WHITELIST_IPS[$((idx - 1))]}"; local next=()
           for ip in "${NODE_WHITELIST_IPS[@]}"; do if [ "$ip" != "$del_ip" ]; then next+=("$ip"); fi; done
           NODE_WHITELIST_IPS=("${next[@]}"); save_node_whitelist; sync_firewall_whitelist; ok "已成功删除: $del_ip"
         else warn "输入序号无效。"; fi; pause ;;
      5) read -r -p "确认清空白名单？(y/n): " confirm; if [ "$confirm" = "y" ]; then NODE_WHITELIST_IPS=(); save_node_whitelist; sync_firewall_whitelist; ok "已清空"; fi; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

# ================= 节点机功能核心 =================
set_node_dns() {
  read -r -p "输入【解锁机】公网 IP: " unlock_ip
  if [ -z "$unlock_ip" ]; then warn "不能为空。"; return; fi
  backup_resolv_conf
  if command_exists systemctl && systemctl is-active systemd-resolved >/dev/null 2>&1; then
    systemctl stop systemd-resolved 2>/dev/null || true
    systemctl disable systemd-resolved 2>/dev/null || true
  fi
  chattr -i /etc/resolv.conf 2>/dev/null || true
  rm -f /etc/resolv.conf
  printf 'nameserver %s\n' "$unlock_ip" > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true
  ok "已设置 DNS: $unlock_ip"
  info "普通域名会由解锁机 dnsmasq 转发到公共 DNS；AI 域名会解析到解锁机。"
}

test_node_dns() {
  local configured_dns="$(awk '/^nameserver/ {print $2; exit}' /etc/resolv.conf)"
  if [ -z "$configured_dns" ]; then warn "未配置 DNS！"; return; fi
  local node_public_ip="$(detect_node_public_ip)"
  
  info "当前设定 DNS: $configured_dns"
  echo "--------------------------------------"
  info "系统 DNS 配置:"
  ls -l /etc/resolv.conf 2>/dev/null || true
  cat /etc/resolv.conf 2>/dev/null || true
  if command_exists resolvectl; then
    resolvectl status 2>/dev/null | sed -n '1,35p' || true
  fi
  if [ -n "$node_public_ip" ]; then
    info "当前节点公网 IP: $node_public_ip（解锁机白名单必须添加这个 IP）"
  else
    warn "未能自动获取节点公网 IP；请手动确认解锁机白名单里添加的是节点公网 IP。"
  fi
  info "将直接向 $configured_dns 发起 DNS 查询，避免被系统备用 DNS 干扰。"
  echo "--------------------------------------"
  info "分流解析状态:"

  local dns_ok_count=0 dns_miss_count=0 dns_timeout_count=0 domain
  while IFS= read -r domain; do
    [ -z "$domain" ] && continue
    local resolved=""
    if command_exists dig; then resolved="$(dig @"$configured_dns" "$domain" A +time=3 +tries=1 +short 2>/dev/null | awk '/^[0-9]+\./ {print; exit}')"; fi
    if [ -z "$resolved" ] && command_exists nslookup; then resolved="$(nslookup -type=A "$domain" "$configured_dns" 2>/dev/null | awk '/^Address: / {print $2}' | grep -E '^[0-9]+\.' | tail -n 1)"; fi
    if [ -z "$resolved" ] && command_exists ping; then resolved="$(ping -c 1 -W 1 "$domain" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"; fi

    if [ -n "$resolved" ]; then
      if [ "$resolved" = "$configured_dns" ]; then dns_ok_count=$((dns_ok_count + 1)); printf "  %b %s -> %s\n" "$(color 32 "[成功]")" "$domain" "$resolved"
      else dns_miss_count=$((dns_miss_count + 1)); printf "  %b %s -> %s（未命中解锁机）\n" "$(color 31 "[失败]")" "$domain" "$resolved"; fi
    else dns_timeout_count=$((dns_timeout_count + 1)); printf "  %b %s -> 无 A 记录响应\n" "$(color 33 "[无响应]")" "$domain"; fi
  done < <(collect_ai_check_hosts)
  if [ "$dns_ok_count" -eq 0 ] && [ "$dns_timeout_count" -gt 0 ]; then
    warn "AI 域名 A 记录无响应：请在解锁机白名单添加【节点机公网 IP】，并在云服务商安全组放行 UDP/TCP 53。"
    [ -n "$node_public_ip" ] && warn "当前节点公网 IP 是 $node_public_ip，请确认它已经在解锁机白名单中。"
  elif [ "$dns_miss_count" -gt 0 ]; then
    warn "AI 域名没有解析到解锁机：请在解锁机重新生成配置，并确认 dnsmasq 配置里有 local=/域名/ 和 address=/域名/$configured_dns。"
  fi

  echo "--------------------------------------"
  info "系统解析测试:"
  if command_exists getent; then
    if getent ahostsv4 example.com >/tmp/ai_unlock_getent_example.log 2>/dev/null; then
      printf "  %b getent example.com -> %s\n" "$(color 32 "[成功]")" "$(head -n 1 /tmp/ai_unlock_getent_example.log)"
    else
      printf "  %b getent example.com -> 失败\n" "$(color 31 "[失败]")"
    fi
    if getent ahostsv4 chatgpt.com >/tmp/ai_unlock_getent_chatgpt.log 2>/dev/null; then
      printf "  %b getent chatgpt.com -> %s\n" "$(color 32 "[成功]")" "$(head -n 1 /tmp/ai_unlock_getent_chatgpt.log)"
    else
      printf "  %b getent chatgpt.com -> 失败\n" "$(color 31 "[失败]")"
    fi
  else
    printf "  %b 未安装 getent，跳过系统解析测试\n" "$(color 33 "[跳过]")"
  fi

  echo "--------------------------------------"
  info "AI API 连通检测:"
  check_all_ai_api_unlock "$configured_dns" || true
}

unlock_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           部署解锁机")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 安装\n" "$(color 32 "1.")"
    printf "  %b 运行状态检测\n" "$(color 32 "2.")"
    printf "  %b 查看服务日志\n" "$(color 32 "3.")"
    printf "  %b 重启服务\n" "$(color 32 "4.")"
    printf "  %b 暂停服务\n" "$(color 32 "5.")"
    printf "  %b 域名池管理\n" "$(color 32 "6.")"
    printf "  %b 白名单管理\n" "$(color 32 "7.")"
    printf "  %b Web 面板管理\n" "$(color 32 "8.")"
    printf "  %b 彻底卸载清理\n" "$(color 32 "9.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-9]: " choice
    case "$choice" in
      1) install_unlock_core; pause ;;
      2) show_unlock_summary; pause ;;
      3) require_unlock_installed && show_unlock_logs; pause ;;
      4) require_unlock_installed && restart_unlock_services; pause ;;
      5) require_unlock_installed && stop_unlock_services; pause ;;
      6) require_unlock_installed && domain_menu ;;
      7) require_unlock_installed && firewall_menu ;;
      8) require_unlock_installed && panel_menu ;;
      9) uninstall_unlock_core; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

node_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "           配置节点机")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 指向解锁机 DNS\n" "$(color 32 "1.")"
    printf "  %b 恢复原生 DNS\n" "$(color 32 "2.")"
    printf "  %b 分流诊断与测试\n" "$(color 32 "3.")"
    printf "  %b 查看当前 DNS\n" "$(color 32 "4.")"
    printf "  %b 返回主菜单\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-4]: " choice
    case "$choice" in
      1) set_node_dns; pause ;;
      2) restore_resolv_conf; pause ;;
      3) test_node_dns; pause ;;
      4) printf "\n%b\n" "$(color 36 "/etc/resolv.conf")"; cat /etc/resolv.conf 2>/dev/null || true; pause ;;
      0) return ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

main_menu() {
  while true; do
    clear
    printf "%b\n" "$(color 36 "======================================")"
    printf "%b\n" "$(color 36 "         AI DNS 分流管理系统")"
    printf "%b\n" "$(color 36 "======================================")"
    printf "  %b 进入【解锁机】面板\n" "$(color 32 "1.")"
    printf "  %b 进入【节点机】面板\n" "$(color 32 "2.")"
    printf "  %b 退出\n" "$(color 32 "0.")"
    printf "%b\n" "$(color 36 "======================================")"
    read -r -p "请选择 [0-2]: " choice
    case "$choice" in
      1) unlock_menu ;;
      2) node_menu ;;
      0) exit 0 ;;
      *) warn "无效选项"; sleep 1 ;;
    esac
  done
}

main() {
  if [ "$1" = "sync-firewall" ]; then ensure_root; sync_firewall_whitelist >/dev/null 2>&1; exit 0; fi
  ensure_root
  ensure_base_dir
  main_menu
}

main "$@"

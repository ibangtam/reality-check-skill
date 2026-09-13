#!/usr/bin/env bash
#
# vps-audit-readonly.sh — Thu thập bằng chứng bảo mật VPS (CHỈ ĐỌC)
# Tham chiếu checklist: VPS-SECURITY-AUDIT.md
#
# ============================ CAM KẾT READ-ONLY ============================
# Script này KHÔNG:
#   - ghi/sửa/xoá bất kỳ file nào của hệ thống
#   - cài đặt, gỡ bỏ, cập nhật package
#   - start/stop/restart/enable/disable service
#   - thay đổi firewall, user, quyền, hay bất kỳ cấu hình nào
#   - gửi dữ liệu ra ngoài (không có curl tới internet, trừ metadata link-local
#     169.254.169.254 vốn nằm trong chính hạ tầng — có thể tắt bằng SKIP_META=1)
# Toàn bộ output ghi ra STDOUT. Tự redirect nếu muốn lưu file.
#
# CÁCH DÙNG:
#   sudo bash vps-audit-readonly.sh > /tmp/audit-$(date +%F).txt 2>&1
#
# CẢNH BÁO VỀ DỮ LIỆU NHẠY CẢM:
#   Output chứa thông tin cấu hình hệ thống. Script đã cố ý:
#     - in FINGERPRINT của SSH key thay vì nội dung key
#     - chỉ in TÊN FILE chứa credential, không in giá trị credential
#   Vẫn nên đọc qua và che IP/domain nội bộ trước khi gửi cho bên thứ ba.
# ==========================================================================

export LC_ALL=C
SKIP_META="${SKIP_META:-0}"

hr()  { printf '\n%s\n' "================================================================"; }
sec() { hr; printf '## %s\n' "$*"; hr; }
sub() { printf '\n--- %s ---\n' "$*"; }
has() { command -v "$1" >/dev/null 2>&1; }
run() { sub "$1"; shift; "$@" 2>&1 | head -60 || echo "(không chạy được / không áp dụng)"; }

[ "$(id -u)" -ne 0 ] && echo "!! CẢNH BÁO: không chạy bằng root — nhiều mục sẽ thiếu dữ liệu. Nên dùng sudo."

sec "THÔNG TIN CƠ BẢN"
sub "Thời điểm audit"; date -u '+%Y-%m-%d %H:%M:%S UTC'
sub "Hostname / Kernel"; uname -a
sub "Distro"; cat /etc/os-release 2>/dev/null | head -5
sub "Uptime"; uptime
sub "Tài nguyên"; free -h 2>/dev/null; df -h 2>/dev/null | grep -vE 'tmpfs|udev'
sub "Ảo hoá"; systemd-detect-virt 2>/dev/null || echo "n/a"

# ==================== TIER 8: DẤU HIỆU XÂM NHẬP ====================
sec "TIER 8 — DẤU HIỆU XÂM NHẬP (đọc mục này trước tiên)"

sub "T8-01 Top 15 tiến trình theo CPU"
ps aux --sort=-%cpu 2>/dev/null | head -16

sub "T8-01 Tiến trình chạy từ thư mục ghi được hoặc binary đã bị xoá [CỜ ĐỎ]"
ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/|\(deleted\)' || echo "OK — không phát hiện"

sub "T8-01 Khớp IoC cryptominer [CỜ ĐỎ]"
ps aux 2>/dev/null | grep -iE 'xmrig|kdevtmpfsi|kinsing|minerd|cryptonight|stratum\+tcp' | grep -v grep || echo "OK — không phát hiện"

sub "T8-02 SSH authorized_keys (in fingerprint, không in key)"
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] || continue
  echo "=== $f  [$(stat -c '%U:%G %a  sửa lần cuối: %y' "$f" 2>/dev/null)]"
  if has ssh-keygen; then ssh-keygen -lf "$f" 2>/dev/null || echo "  (không đọc được fingerprint)"; fi
  echo "  số key: $(grep -cvE '^\s*(#|$)' "$f" 2>/dev/null)"
done
echo "-> ĐỐI CHIẾU TỪNG FINGERPRINT với danh sách key hợp lệ của team."

sub "T8-02 authorized_keys ở vị trí bất thường"
find / -name 'authorized_keys*' -not -path '/proc/*' -not -path '/root/.ssh/*' \
  -not -path '/home/*/.ssh/*' 2>/dev/null | head -10 || echo "OK"

sub "T8-03 Crontab của tất cả user"
for u in $(cut -d: -f1 /etc/passwd 2>/dev/null); do
  out=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^\s*#|^\s*$')
  [ -n "$out" ] && { echo "=== $u ==="; echo "$out"; }
done

sub "T8-03 Cron hệ thống + pattern tải-và-chạy [CỜ ĐỎ]"
ls -la /etc/cron.d/ 2>/dev/null | head -20
grep -rE 'curl|wget|base64|/dev/tcp|bash -i|python -c|nc -e' /etc/cron* /var/spool/cron 2>/dev/null | head -20 || echo "OK — không phát hiện pattern nguy hiểm"

sub "T8-03 systemd unit/timer sửa trong 30 ngày"
find /etc/systemd /lib/systemd -name '*.service' -o -name '*.timer' -mtime -30 2>/dev/null | head -20 || echo "OK"
systemctl list-timers --all --no-pager 2>/dev/null | head -15

sub "T8-04 /etc/ld.so.preload — file này KHÔNG nên tồn tại [CỜ ĐỎ NẶNG]"
if [ -e /etc/ld.so.preload ]; then
  echo "!!!! PHÁT HIỆN /etc/ld.so.preload — NGHI NGỜ ROOTKIT USERLAND"; cat /etc/ld.so.preload
else echo "OK — không tồn tại"; fi

sub "T8-04 Đối chiếu ps với /proc (phát hiện process bị giấu) [CỜ ĐỎ]"
d=$(diff <(ps -eo pid --no-headers 2>/dev/null | tr -d ' ' | sort -n) \
         <(ls /proc 2>/dev/null | grep -E '^[0-9]+$' | sort -n) 2>/dev/null | head -15)
[ -n "$d" ] && echo "$d" || echo "OK — khớp"

sub "T8-04 Toàn vẹn binary hệ thống"
if has dpkg; then dpkg --verify 2>/dev/null | head -25 || echo "OK"
elif has rpm; then rpm -Va --nomtime --nosize 2>/dev/null | head -25 || echo "OK"; fi

sub "T8-05 Tài khoản UID 0 — chỉ được có root [CỜ ĐỎ nếu >1]"
awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null

sub "T8-05 Tài khoản có shell đăng nhập được"
awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1" → "$7}' /etc/passwd 2>/dev/null

sub "T8-05 Tài khoản không mật khẩu [CỜ ĐỎ]"
awk -F: '$2=="" {print "KHÔNG MẬT KHẨU: "$1}' /etc/shadow 2>/dev/null || echo "OK / không đọc được shadow"

sub "T8-05 Nhóm đặc quyền (docker và lxd tương đương root)"
grep -E '^(sudo|wheel|admin|adm|docker|lxd):' /etc/group 2>/dev/null

sub "T8-06 Log — file 0 byte là cờ đỏ"
ls -la --time-style=long-iso /var/log/ 2>/dev/null | head -30

sub "T8-06 bash_history bị vô hiệu hoá [CỜ ĐỎ]"
for f in /root/.bash_history /home/*/.bash_history; do
  [ -e "$f" ] && echo "$f → $(stat -c '%s bytes, %y' "$f" 2>/dev/null) $(readlink "$f" 2>/dev/null)"
done
grep -rE 'HISTFILE=/dev/null|unset HIST|HISTSIZE=0' /root/.bashrc /home/*/.bashrc /etc/profile 2>/dev/null || echo "OK"

sub "T8-07 Kết nối mạng đang mở kèm tiến trình"
ss -tunp 2>/dev/null | head -40 || netstat -tunp 2>/dev/null | head -40

sub "T8-07 DNS resolver và /etc/hosts"
cat /etc/resolv.conf 2>/dev/null | grep -v '^#'
echo "--- /etc/hosts:"; grep -vE '^\s*#|^\s*$' /etc/hosts 2>/dev/null | head -20

# ==================== TIER 2: SSH VÀ XÁC THỰC ====================
sec "TIER 2 — SSH VÀ XÁC THỰC"

sub "T2-01 Cấu hình SSH THẬT SỰ đang áp dụng (sshd -T, đã merge include)"
sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|allowusers|allowgroups|denyusers|x11forwarding|logingracetime|usepam|kbdinteractiveauthentication|authenticationmethods|clientaliveinterval|permittunnel|gatewayports)' \
  || echo "(cần root để chạy sshd -T)"

sub "T2-01 Phiên bản OpenSSH (đối chiếu CVE-2024-6387 regreSSHion: dính nếu 8.5p1–9.7p1 trên glibc)"
ssh -V 2>&1

sub "T2-01 File include của sshd"
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null && grep -hvE '^\s*#|^\s*$' /etc/ssh/sshd_config.d/* 2>/dev/null

sub "T2-02 Số lần đăng nhập THẤT BẠI"
{ grep -c 'Failed password' /var/log/auth.log 2>/dev/null || grep -c 'Failed password' /var/log/secure 2>/dev/null; } || echo "0 / không đọc được log"

sub "T2-02 Top 15 IP brute force"
cat /var/log/auth.log /var/log/secure 2>/dev/null | grep 'Failed password' | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -15

sub "T2-02 ĐĂNG NHẬP THÀNH CÔNG — kiểm tra kỹ từng dòng [QUAN TRỌNG NHẤT]"
cat /var/log/auth.log /var/log/secure 2>/dev/null | grep -E 'Accepted (password|publickey)' | tail -30
echo "--- last 20:"; last -20 2>/dev/null

sub "T2-02 fail2ban / CrowdSec"
fail2ban-client status 2>/dev/null || echo "fail2ban: KHÔNG chạy"
cscli decisions list 2>/dev/null | head -5 || true

sub "T2-03 Thuật toán hash mật khẩu (\$y\$=yescrypt OK, \$6\$=sha512 OK, \$1\$=MD5 HỎNG)"
awk -F: '$2 ~ /^\$/ {print $1": "substr($2,1,3)}' /etc/shadow 2>/dev/null | head -20

sub "T2-03 Quyền file nhạy cảm"
stat -c '%n %a %U:%G' /etc/shadow /etc/passwd /etc/sudoers /etc/gshadow 2>/dev/null

sub "T2-04 MFA"
grep -rlE 'pam_google_authenticator|pam_oath|pam_u2f|duo' /etc/pam.d/ 2>/dev/null || echo "KHÔNG có MFA cho SSH"

# ==================== TIER 1: BỀ MẶT MẠNG ====================
sec "TIER 1 — BỀ MẶT TẤN CÔNG MẠNG"

sub "T1-01 TOÀN BỘ port đang lắng nghe"
ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null

sub "T1-01 Service bind ra MỌI interface (0.0.0.0 / ::) [KIỂM TRA KỸ]"
ss -tulnp 2>/dev/null | grep -E '0\.0\.0\.0:|\[::\]:' || echo "OK"

sub "T1-01 Port dữ liệu/quản trị nguy hiểm đang mở [CỜ ĐỎ]"
ss -tulnp 2>/dev/null | grep -E ':(3306|5432|6379|27017|9200|9300|11211|2375|2376|5672|15672|10250|5900|3389|23|21|161|111)\b' \
  || echo "OK — không có port dữ liệu/quản trị nào lắng nghe"

sub "T1-02 Firewall — UFW"
ufw status verbose 2>/dev/null || echo "ufw: n/a"
sub "T1-02 Firewall — firewalld"
firewall-cmd --list-all 2>/dev/null || echo "firewalld: n/a"
sub "T1-02 Firewall — nftables"
nft list ruleset 2>/dev/null | head -40 || echo "nft: n/a"
sub "T1-02 Firewall — iptables IPv4"
iptables -L -n -v 2>/dev/null | head -40 || echo "iptables: n/a"
sub "T1-02 Firewall — IPv6 [CỰC HAY BỊ QUÊN — trống = bypass được toàn bộ firewall]"
ip6tables -L -n -v 2>/dev/null | head -30 || echo "ip6tables: n/a"
sub "T1-02 NAT / Docker chain (Docker bypass UFW qua chain này)"
iptables -t nat -L DOCKER -n 2>/dev/null | head -20 || echo "n/a"

sub "T1-03 IP công khai và interface"
ip -4 addr show 2>/dev/null | grep inet
ip -6 addr show 2>/dev/null | grep inet6 | grep -v ' fe80::'

# ==================== TIER 4: TẦNG DỮ LIỆU ====================
sec "TIER 4 — TẦNG DỮ LIỆU"

sub "T4-01 MySQL/MariaDB bind-address"
grep -rhE '^\s*(bind-address|skip-networking|port)' /etc/mysql/ /etc/my.cnf /etc/my.cnf.d/ 2>/dev/null || echo "n/a"

sub "T4-01 Tài khoản MySQL (host '%' = kết nối từ mọi nơi) [CỜ ĐỎ]"
mysql -e "SELECT user,host,plugin FROM mysql.user;" 2>/dev/null || echo "(không kết nối được bằng socket — bỏ qua)"

sub "T4-01 PostgreSQL"
grep -hE '^listen_addresses' /etc/postgresql/*/main/postgresql.conf 2>/dev/null || echo "n/a"
grep -hvE '^\s*#|^\s*$' /etc/postgresql/*/main/pg_hba.conf 2>/dev/null | head -15

sub "T4-02 Redis — cấu hình"
grep -hE '^\s*(bind|requirepass|protected-mode|port|rename-command)' /etc/redis/redis.conf /etc/redis.conf 2>/dev/null || echo "n/a"

sub "T4-02 Redis — thử PING không mật khẩu (trả PONG = CỜ ĐỎ NẶNG)"
if has redis-cli; then
  r=$(timeout 3 redis-cli ping 2>&1)
  echo "kết quả: $r"
  [ "$r" = "PONG" ] && {
    echo "!!!! REDIS KHÔNG YÊU CẦU XÁC THỰC"
    echo "  dir     = $(timeout 3 redis-cli config get dir 2>/dev/null | tail -1)"
    echo "  dbfile  = $(timeout 3 redis-cli config get dbfilename 2>/dev/null | tail -1)"
    echo "  -> nếu dir trỏ tới /root/.ssh hoặc /var/spool/cron => ĐÃ BỊ KHAI THÁC"
  }
else echo "redis-cli: n/a"; fi

sub "T4-02 Memcached / MongoDB / Elasticsearch"
grep -hE '^-l|^-U|^-p' /etc/memcached.conf 2>/dev/null || echo "memcached: n/a"
grep -hE 'bindIp|authorization' /etc/mongod.conf 2>/dev/null || echo "mongodb: n/a"
grep -hE '^network.host|^xpack.security.enabled' /etc/elasticsearch/elasticsearch.yml 2>/dev/null || echo "elasticsearch: n/a"

sub "T4-03 Backup — file dump lớn trên hệ thống"
find / -maxdepth 5 \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' -o -name '*.tar.gz' \) \
  -size +1M -not -path '/proc/*' -not -path '/sys/*' -printf '%TY-%Tm-%Td %10s %p\n' 2>/dev/null | head -25 || echo "không tìm thấy"

sub "T4-03 Công cụ backup đã cài"
for t in borg restic duplicity rclone rsnapshot bacula-fd; do has $t && echo "có: $t"; done
crontab -l 2>/dev/null | grep -iE 'backup|dump|rsync|borg|restic' || echo "(không có cron backup ở root crontab)"

sub "T4-04 File CÓ CHỨA credential (chỉ in tên file, KHÔNG in giá trị)"
grep -rElI '(password|passwd|secret|api[_-]?key|token)\s*[=:]' \
  /etc /opt /srv /var/www --include='*.conf' --include='*.yml' --include='*.yaml' \
  --include='*.env' --include='*.json' --include='*.ini' 2>/dev/null | head -25

sub "T4-04 Private key và quyền (phải là 600)"
find /root /home /etc/ssl /opt -maxdepth 4 \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' -o -name '*.key' \) 2>/dev/null | \
  while read f; do stat -c '%a %U:%G  %n' "$f" 2>/dev/null; done | head -25

# ==================== TIER 3: ỨNG DỤNG WEB ====================
sec "TIER 3 — ỨNG DỤNG WEB"

sub "T3-01 Phiên bản web stack"
nginx -v 2>&1 | head -1; apache2 -v 2>&1 | head -1; httpd -v 2>&1 | head -1
php -v 2>&1 | head -1; mysql --version 2>&1; psql --version 2>&1
node -v 2>&1; python3 -V 2>&1

sub "T3-01 BẢN VÁ BẢO MẬT ĐANG CHỜ CÀI [QUAN TRỌNG]"
if has apt; then apt list --upgradable 2>/dev/null | grep -i security | head -30 || echo "OK / không xác định"
elif has dnf; then dnf updateinfo list --security 2>/dev/null | head -30
elif has yum; then yum updateinfo list security 2>/dev/null | head -30; fi

sub "T3-01 Lịch sử cập nhật gần nhất"
grep -E '^(Start-Date|Commandline)' /var/log/apt/history.log 2>/dev/null | tail -12 || \
  rpm -qa --last 2>/dev/null | head -10

sub "T3-02 Banner rò rỉ phiên bản"
grep -rhE 'server_tokens|expose_php|ServerTokens|ServerSignature' /etc/nginx/ /etc/apache2/ /etc/httpd/ /etc/php/ 2>/dev/null | grep -v '^\s*#' | head -10 || echo "KHÔNG cấu hình → mặc định là LỘ phiên bản"

sub "T3-04 File nhạy cảm trong webroot [CỜ ĐỎ]"
find /var/www /home/*/public_html /usr/share/nginx /srv -maxdepth 5 \
  \( -name '.env*' -o -name '*.sql' -o -name '*.bak' -o -name '*.old' -o -name '.git' \
     -o -name '*.zip' -o -name 'phpinfo.php' -o -name 'info.php' -o -name 'adminer*.php' \) \
  2>/dev/null | head -30 || echo "OK"

sub "T3-04 Quyền file .env (phải 600)"
find /var/www /srv /opt -maxdepth 4 -name '.env*' 2>/dev/null | \
  while read f; do stat -c '%a %U:%G  %n' "$f" 2>/dev/null; done

sub "T3-05 Hàm PHP nguy hiểm"
php -i 2>/dev/null | grep -E '^(disable_functions|allow_url_fopen|allow_url_include|open_basedir|expose_php)' || \
  grep -hE '^\s*(disable_functions|allow_url_include|allow_url_fopen)' /etc/php/*/fpm/php.ini 2>/dev/null || echo "n/a"

sub "T3-05 File PHP nằm trong thư mục upload [CỜ ĐỎ — RCE]"
find /var/www /srv -path '*upload*' -name '*.ph*' 2>/dev/null | head -15 || echo "OK"

sub "T3-06 Pattern WEBSHELL trong webroot [CỜ ĐỎ NẶNG]"
grep -rlE 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress|\$_(POST|GET|REQUEST|COOKIE))' \
  /var/www /srv /home/*/public_html --include='*.php' 2>/dev/null | head -25 || echo "OK — không phát hiện"

sub "T3-06 File PHP sửa trong 14 ngày (đối chiếu với lịch deploy)"
find /var/www /srv /home/*/public_html -name '*.php' -mtime -14 -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | head -30 || echo "OK"

sub "T3-06 WordPress"
find / -name 'wp-config.php' -not -path '/proc/*' 2>/dev/null | head -5 | while read w; do
  echo "=== $w  [$(stat -c '%a %U:%G' "$w" 2>/dev/null)]"
  d=$(dirname "$w")
  has wp && { wp core version --allow-root --path="$d" 2>/dev/null
              wp plugin list --allow-root --path="$d" --fields=name,status,version,update 2>/dev/null | head -40; }
done

sub "T3-07 TLS — chứng chỉ đang dùng"
find /etc/letsencrypt/live /etc/ssl/certs -name 'cert.pem' -o -name 'fullchain.pem' 2>/dev/null | head -5 | \
  while read c; do echo "=== $c"; openssl x509 -in "$c" -noout -subject -dates 2>/dev/null; done

sub "T3-07 Cấu hình TLS (không được có TLSv1/TLSv1.1)"
grep -rhE 'ssl_protocols|ssl_ciphers|ssl_prefer_server_ciphers|SSLProtocol|SSLCipherSuite' \
  /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v '^\s*#' | head -10 || echo "n/a"

# ==================== TIER 5: LEO THANG ĐẶC QUYỀN ====================
sec "TIER 5 — LEO THANG ĐẶC QUYỀN VÀ CONTAINER"

sub "T5-01 Cấu hình sudo"
grep -hvE '^\s*#|^\s*$' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | head -30
sudo --version 2>/dev/null | head -1
echo "-> CVE-2021-3156 (Baron Samedit) nếu sudo < 1.9.5p2"

sub "T5-01 NOPASSWD [CỜ ĐỎ nếu áp cho user thường hoặc user service]"
grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null || echo "OK — không có NOPASSWD"

sub "T5-02 SUID/SGID không thuộc danh sách chuẩn [ĐỐI CHIẾU GTFOBins]"
find / -perm -4000 -type f -not -path '/proc/*' -not -path '/snap/*' 2>/dev/null | \
  grep -vE '/(su|sudo|mount|umount|passwd|chsh|chfn|gpasswd|newgrp|pkexec|ping|ping6|fusermount|fusermount3|ssh-agent|at|crontab|unix_chkpwd|dbus-daemon-launch-helper|polkit-agent-helper-1|snap-confine|vmware-user-suid-wrapper|sg|expiry|chage)$' \
  || echo "OK — chỉ có SUID chuẩn"

sub "T5-02 File capabilities (SUID 'ẩn')"
getcap -r / 2>/dev/null | head -20 || echo "OK / getcap n/a"

sub "T5-02 File và thư mục ai cũng ghi được"
find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -15 || echo "OK"
find / -xdev -type d -perm -0002 ! -perm -1000 -not -path '/proc/*' 2>/dev/null | head -10 || echo "OK"

sub "T5-03 Kernel đang chạy vs kernel đã cài (khác nhau = CHƯA REBOOT, vá chưa hiệu lực)"
echo "đang chạy: $(uname -r)"
dpkg -l 2>/dev/null | grep -E '^ii\s+linux-image' | awk '{print "đã cài:   "$2" "$3}' || \
rpm -qa kernel 2>/dev/null | sed 's/^/đã cài:   /'

sub "T5-03 Tham số cứng hoá kernel"
sysctl -a 2>/dev/null | grep -E '^(kernel\.(kptr_restrict|dmesg_restrict|unprivileged_bpf_disabled|yama\.ptrace_scope|randomize_va_space)|fs\.protected_(hardlinks|symlinks)|net\.ipv4\.conf\.all\.(rp_filter|accept_redirects|accept_source_route)|net\.ipv4\.tcp_syncookies|kernel\.unprivileged_userns_clone)\b'

sub "T5-04 Docker"
docker --version 2>/dev/null || echo "docker: không cài"
runc --version 2>/dev/null | head -1
echo "-> CVE-2024-21626 (Leaky Vessels, container escape) nếu runc < 1.1.12"
ss -tlnp 2>/dev/null | grep -E ':2375|:2376' && echo "!!!! DOCKER API MỞ RA MẠNG = RCE ROOT TRÊN HOST" || echo "OK — Docker API không mở"
stat -c '%n %a %U:%G' /var/run/docker.sock 2>/dev/null
getent group docker 2>/dev/null && echo "-> mọi thành viên nhóm docker đều tương đương root"

sub "T5-04 Cấu hình từng container [privileged/mount/user]"
if has docker; then
  docker ps -q 2>/dev/null | while read c; do
    docker inspect -f '{{.Name}} | privileged={{.HostConfig.Privileged}} | pid={{.HostConfig.PidMode}} | net={{.HostConfig.NetworkMode}} | user=[{{.Config.User}}] | cap={{.HostConfig.CapAdd}}' "$c" 2>/dev/null
    docker inspect -f '   mounts: {{range .Mounts}}{{.Source}}→{{.Destination}} {{end}}' "$c" 2>/dev/null
  done
fi

sub "T5-05 SELinux / AppArmor"
sestatus 2>/dev/null || getenforce 2>/dev/null || echo "SELinux: n/a"
aa-status 2>/dev/null | head -6 || echo "AppArmor: n/a"

sub "T5-05 Service nào chạy quyền root"
ps -eo user,comm --no-headers 2>/dev/null | awk '$1=="root"{print $2}' | sort -u | head -30

# ==================== TIER 7: CVE ====================
sec "TIER 7 — ĐỐI CHIẾU CVE VÀ TẤN CÔNG NÂNG CAO"

sub "T7-01 Phiên bản các thành phần trọng yếu"
printf 'OpenSSH  : '; ssh -V 2>&1
printf 'xz       : '; xz --version 2>&1 | head -1; echo "           -> CVE-2024-3094 nếu là 5.6.0 hoặc 5.6.1 (BACKDOOR)"
printf 'glibc    : '; ldd --version 2>&1 | head -1
printf 'sudo     : '; sudo --version 2>&1 | head -1
printf 'polkit   : '; pkexec --version 2>&1 | head -1; echo "           -> CVE-2021-4034 PwnKit nếu chưa vá"
printf 'openssl  : '; openssl version 2>&1

sub "T7-01 cups-browsed (CVE-2024-47176 — RCE qua UDP 631)"
ss -ulnp 2>/dev/null | grep ':631' && echo "!!!! UDP 631 ĐANG MỞ" || echo "OK"

sub "T7-02 Host header tuỳ ý có được chấp nhận không"
grep -rhE 'default_server|server_name\s+_' /etc/nginx/ 2>/dev/null | head -5 || echo "KHÔNG có default_server → dễ bị Host header injection"

sub "T7-03 Cloud metadata endpoint (SSRF → đánh cắp credential IAM)"
if [ "$SKIP_META" = "1" ]; then echo "(bỏ qua theo SKIP_META=1)"; else
  m=$(timeout 3 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -3)
  if [ -n "$m" ]; then
    echo "!! Metadata endpoint TRUY CẬP ĐƯỢC (AWS IMDSv1 style):"; echo "$m"
    echo "   -> nếu app có chức năng fetch URL do user nhập, đây là đường rò rỉ credential IAM"
    echo "   -> khắc phục: bắt buộc IMDSv2 (HttpTokens=required)"
  else echo "OK — không phản hồi kiểu IMDSv1"; fi
fi

sub "T7-05 Cấu hình session/cookie PHP"
php -i 2>/dev/null | grep -E '^session\.(cookie_httponly|cookie_secure|cookie_samesite|use_strict_mode)' || \
  grep -hE '^\s*session\.(cookie_httponly|cookie_secure|cookie_samesite|use_strict_mode)' /etc/php/*/fpm/php.ini 2>/dev/null || echo "n/a"

sub "T7-06 Bề mặt AI/LLM (MCP server, Ollama, agent)"
ps aux 2>/dev/null | grep -iE 'mcp-|model-context|ollama|vllm|langchain' | grep -v grep || echo "không phát hiện"
ss -tlnp 2>/dev/null | grep -E ':11434' && echo "!! Ollama đang lắng nghe — kiểm tra có bind 0.0.0.0 không" || true

sub "T7-06 File chứa API key LLM (chỉ in tên file)"
grep -rElI 'sk-ant-|sk-proj-|ANTHROPIC_API_KEY|OPENAI_API_KEY' /root /home /opt /var/www /etc 2>/dev/null | head -10 || echo "OK"

sub "T7-07 Trạng thái giảm thiểu lỗ hổng CPU"
grep -r . /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null | sed 's|/sys/devices/system/cpu/vulnerabilities/||' | head -20

# ==================== TIER 6: SUPPLY CHAIN ====================
sec "TIER 6 — SUPPLY CHAIN VÀ CI/CD"

sub "T6-01 Lockfile của ứng dụng"
ls -la /var/www/*/package-lock.json /var/www/*/composer.lock /var/www/*/yarn.lock \
      /var/www/*/requirements.txt /srv/*/package-lock.json 2>/dev/null | head -15 || echo "không tìm thấy"

sub "T6-02 File chứa TOKEN CI/CD, cloud key (chỉ in tên file) [CỜ ĐỎ]"
grep -rElI 'ghp_[A-Za-z0-9]{36}|github_pat_|glpat-|xox[baprs]-|AKIA[0-9A-Z]{16}' \
  /root /home /var/www /opt /etc /srv 2>/dev/null | head -15 || echo "OK"

sub "T6-02 CI runner chạy trên VPS"
ps aux 2>/dev/null | grep -iE 'gitlab-runner|actions-runner|jenkins|drone-runner' | grep -v grep || echo "không có"

sub "T6-02 Git remote (kiểm tra credential nhúng trong URL)"
find /var/www /opt /srv -maxdepth 4 -name '.git' -type d 2>/dev/null | head -10 | while read g; do
  echo "=== $g"; git --git-dir="$g" remote -v 2>/dev/null | sed -E 's|://[^@/]+@|://***REDACTED***@|'
done

sub "T6-03 Nguồn package (repo http:// hoặc gpgcheck=0 là cờ đỏ)"
grep -hvE '^\s*#|^\s*$' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | head -20
grep -hE '^(baseurl|gpgcheck|enabled)' /etc/yum.repos.d/* 2>/dev/null | head -20

# ==================== TIER 9: GIÁM SÁT ====================
sec "TIER 9 — GIÁM SÁT, LOG VÀ PHỤC HỒI"

sub "T9-01 Dịch vụ logging"
systemctl is-active rsyslog systemd-journald auditd 2>/dev/null
journalctl --disk-usage 2>/dev/null

sub "T9-01 Log có được gửi ra ngoài (off-site) không"
grep -rhE '^\*\.\*\s+@|@@' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo "KHÔNG có remote syslog → log bị xoá là mất sạch"

sub "T9-01 Chính sách logrotate"
grep -hE '^\s*(rotate|daily|weekly|monthly)' /etc/logrotate.conf 2>/dev/null | head -5

sub "T9-02 Giám sát toàn vẹn file (FIM)"
for t in aide tripwire ossec-control wazuh-agent samhain; do has $t && echo "có: $t"; done
systemctl is-active wazuh-agent 2>/dev/null || echo "(không có FIM → webshell mới thả vào sẽ không ai biết)"

sub "T9-04 Cập nhật bảo mật tự động"
systemctl is-active unattended-upgrades 2>/dev/null || echo "unattended-upgrades: KHÔNG chạy"
grep -hE 'Unattended-Upgrade|APT::Periodic' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null || echo "(chưa cấu hình)"
systemctl is-active dnf-automatic.timer 2>/dev/null
canonical-livepatch status 2>/dev/null | head -5 || true

hr
echo "HOÀN TẤT THU THẬP — $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo ""
echo "BƯỚC TIẾP THEO:"
echo "  1. Đọc phần TIER 8 trước. Có cờ đỏ ở đó thì mọi kết quả khác đều không đáng tin."
echo "  2. Bổ sung quét TỪ NGOÀI (không làm được từ trong máy):"
echo "       nmap -sS -Pn -p- -T4 <VPS_IP>"
echo "       nmap -sU --top-ports 100 <VPS_IP>"
echo "       nmap -sV -sC -p <port_mở> <VPS_IP>"
echo "       nmap --script ssl-enum-ciphers -p 443 <domain>"
echo "  3. Kiểm tra file lộ qua web: xem mục T3-04 trong VPS-SECURITY-AUDIT.md"
echo "  4. Che IP/domain nội bộ trước khi chia sẻ output này ra ngoài."
hr

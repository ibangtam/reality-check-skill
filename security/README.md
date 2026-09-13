# VPS Security Audit Kit

Bộ công cụ audit bảo mật VPS Linux. **Read-only** — không thay đổi gì trên hệ thống.

## Nội dung

| File | Mục đích |
|---|---|
| `VPS-SECURITY-AUDIT.md` | Checklist phân tầng T1–T11, ~100 mục. Mỗi mục có cơ chế tấn công, mức rủi ro, lệnh check, cờ đỏ, hướng khắc phục |
| `vps-audit-readonly.sh` | Script thu thập bằng chứng, chạy trên VPS |

## Quy trình

**1. Thu thập trên VPS** — chạy từ máy của mình, không để lại file trên server:
```bash
ssh user@<VPS_IP> 'sudo bash -s' < vps-audit-readonly.sh > ~/audit-$(date +%F).txt 2>&1
```

Tuỳ chọn:
```bash
# Tra CVE qua changelog gói (cần mạng, khuyến nghị bật)
ssh user@<VPS_IP> 'sudo WITH_VULN=1 bash -s' < vps-audit-readonly.sh > ~/audit.txt 2>&1

# Trên VPS production tải cao, giảm ưu tiên I/O
ssh user@<VPS_IP> 'sudo nice -n 19 ionice -c3 bash -s' < vps-audit-readonly.sh > ~/audit.txt 2>&1
```

**2. Quét từ ngoài** — script không làm được, phải chạy từ máy khác:
```bash
nmap -sS -Pn -p- -T4 <VPS_IP>
nmap -sU --top-ports 100 <VPS_IP>
nmap -sV -sC -p <port_mở> <VPS_IP>
nmap --script ssl-enum-ciphers -p 443 <domain>
```

**3. Kiểm tra file lộ qua web:**
```bash
for p in .env .git/config wp-config.php.bak backup.sql phpinfo.php adminer.php; do
  echo "$p -> $(curl -s -o /dev/null -w '%{http_code}' https://<domain>/$p)"
done
```

**4. Đọc kết quả** — TIER 8 trước. Có cờ đỏ ở đó thì mọi tier sau đều không đáng tin.

## Ba trạng thái trong báo cáo

| Nhãn | Nghĩa |
|---|---|
| `[!! CỜ ĐỎ]` | Có vấn đề cần xử lý |
| `[KHÔNG XÁC ĐỊNH]` | Check **không chạy được** — không phải là an toàn, phải kiểm tra bằng cách khác |
| `[SẠCH]` | Check đã chạy và không tìm thấy vấn đề |

Phân biệt này quan trọng: bản v1 in "OK" cả khi check không chạy được, tạo ra cảm
giác an toàn giả.

## Cam kết read-only

Script **không** ghi/sửa/xoá file, không cài gỡ package, không start/stop service,
không nạp hay thực thi code của ứng dụng đang chạy (không wp-cli, không artisan),
không kết nối tới database ứng dụng.

Mặc định **không gửi gì ra internet**. Hai kiểm tra có dùng mạng đều tắt mặc định:
`WITH_VULN=1` (tra CVE qua changelog) và `WITH_META=1` (đọc cloud metadata).

## Dữ liệu nhạy cảm trong output

Đã che tự động: giá trị `requirepass`/`masterauth`, mật khẩu trên dòng lệnh
(`-p`, `--password=`), token trong URL repo và git remote, biến môi trường dạng
`*PASS*`/`*TOKEN*`/`*SECRET*`, GitHub PAT, GitLab PAT, AWS key, API key LLM.

Vẫn in: đường dẫn, IP, tên domain, tên user, fingerprint SSH key.

Đọc qua trước khi gửi output cho bên thứ ba.

## Giới hạn

- **Không thay thế pentest.** Phát hiện lỗi cấu hình và lỗ hổng đã biết, không phát
  hiện lỗi logic nghiệp vụ trong ứng dụng.
- **Chạy từ bên trong máy.** Nếu máy đã bị rootkit, output có thể bị làm giả. Khi
  nghi bị xâm nhập: snapshot disk, mount ra máy sạch, phân tích offline.
- **Bảng CVE là ảnh chụp tĩnh** và sẽ lỗi thời. Nguồn đáng tin: security tracker của
  distro + CISA KEV.
- **Không kiểm tra được tầng nhà cung cấp**: panel VPS có 2FA không, ai truy cập được
  console, snapshot lưu ở đâu. Đây thường là mắt xích yếu nhất.
- **Không kiểm tra được máy trạm của nhân viên** — nơi infostealer lấy SSH key và
  mật khẩu panel, một trong những đường vào phổ biến nhất hiện nay.

## Lịch sử phiên bản

**v2.0** — sau một vòng review đối kháng của v1. Ba lỗi nghiêm trọng đã sửa:

1. **v1 không thật sự read-only.** Nó gọi `wp plugin list --allow-root`, lệnh này nạp
   WordPress, kết nối DB production, chạy code của mọi plugin bằng quyền root, gọi ra
   `api.wordpress.org` và ghi transient vào database. v2 đọc version thuần từ disk.
2. **v1 in giá trị credential vào file output** — `requirepass` của Redis, dòng cron
   chứa `mysqldump -pMẬTKHẨU`, URL repo có token. v2 che qua hàm `redact()`.
3. **v1 in "OK" khi check không chạy được.** v2 phân biệt ba trạng thái.

Ngoài ra: sửa lỗi toán tử `find` làm mất bộ lọc thời gian, bỏ so sánh `ps`/`/proc`
gây báo động giả, đọc log qua cả journald và file đã xoay, so khớp SUID theo đường
dẫn đầy đủ, thêm phương pháp kiểm tra CVE có tính tới backport của distro, thêm
TIER 10 (rủi ro agency đa khách hàng) và TIER 11 (CVE 2026).

**v1.0** — bản đầu.

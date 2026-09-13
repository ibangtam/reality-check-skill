# VPS Security Audit

Bộ công cụ audit bảo mật VPS. **Read-only** — không có thao tác nào thay đổi hệ thống.

## Nội dung

| File | Mục đích |
|---|---|
| `VPS-SECURITY-AUDIT.md` | Checklist phân tầng T1–T9, ~80 mục kiểm tra, mỗi mục có cơ chế tấn công, lệnh check, cờ đỏ, hướng khắc phục |
| `vps-audit-readonly.sh` | Script thu thập bằng chứng tự động trên VPS |

## Quy trình

**Bước 1 — thu thập trên VPS:**
```bash
sudo bash vps-audit-readonly.sh > /tmp/audit-$(date +%F).txt 2>&1
```

**Bước 2 — quét từ ngoài** (script không làm được, phải chạy từ máy khác):
```bash
nmap -sS -Pn -p- -T4 <VPS_IP>                      # toàn bộ 65535 TCP port
nmap -sU --top-ports 100 <VPS_IP>                  # UDP — hay bị bỏ sót
nmap -sV -sC -p <port_mở> <VPS_IP>                 # xác định version để đối chiếu CVE
nmap --script ssl-enum-ciphers -p 443 <domain>     # TLS
```

**Bước 3 — kiểm tra file lộ qua web:** xem mục T3-04 trong checklist.

**Bước 4 — phân tích:** đọc TIER 8 trước. Có cờ đỏ ở T8 thì mọi kết quả khác không đáng tin (rootkit làm giả output).

## Nguyên tắc

- Không triển khai thay đổi nào khi chưa có phê duyệt của chủ hệ thống
- Output chứa thông tin cấu hình — script đã in fingerprint SSH key thay vì nội dung key, và chỉ in tên file chứa credential thay vì giá trị. Vẫn nên che IP/domain nội bộ trước khi chia sẻ.
- Bảng CVE trong checklist là ảnh chụp tĩnh. Nguồn đáng tin để đối chiếu thực tế: security tracker của distro + CISA KEV catalog.

---
name: reality-check
description: >
  Phản biện yêu cầu/ý tưởng của bạn và audit output phiên làm việc — đưa góc nhìn ngược CÓ BẰNG CHỨNG
  để quyết định thực tế hơn, phù hợp hơn với mục tiêu và nguồn lực hiện tại. 4 chế độ:
  (1) PHẢN BIỆN INPUT — lộ giả định ngầm + 6 câu hỏi (đúng mục tiêu? đã có chưa? đủ nguồn lực? rủi ro
  gì? chi phí cơ hội? data nói gì?) → verdict 4 mức + đề xuất chỉnh; (2) AUDIT OUTPUT — subagent sạch
  soát deliverable so với yêu cầu gốc, PASS/FAIL từng điểm kèm Fix; (3) GATE NHẸ tự kích hoạt trước
  khi build/chi tiền/đổi kiến trúc/cam kết KPI; (4) PRE-MORTEM quyết định lớn — giả định đã thất bại,
  truy ngược 3 vai + tripwire. Cấm phản biện suông, cấm bịa vấn đề.
  Trigger: reality check, phản biện, mổ xẻ, chất vấn, ý này có ổn không, đánh giá ý tưởng, góp ý ngược,
  devil's advocate, red team, challenge this, poke holes, stress test, pre-mortem, audit phiên,
  audit session, soát lại yêu cầu, kiểm tra output.
---

# Reality Check — Người Gác Cổng Trước Quyết Định

> **Bản public generic.** Mọi chỗ `[trong ngoặc vuông]` là placeholder — thay bằng nguồn dữ liệu
> thật của bạn (knowledge base, sổ bàn giao, task queue, API data...) trước khi dùng. Xem README
> để biết cách tùy biến cho hệ của bạn.

**Vị trí trong hệ:** ĐỨNG TRƯỚC quyết định (khác skill QC chấm sản phẩm SAU khi làm, khác
orchestrator điều phối việc ĐÃ được quyết).
**Input:** 1 yêu cầu / ý tưởng / kế hoạch — hoặc output của 1 phiên làm việc.
**Output:** Verdict + luận điểm ngược có dẫn chứng + độ chắc + cách kiểm nhanh + đề xuất điều chỉnh.
**Quyền quyết cuối cùng: LUÔN là con người.** Skill này đưa góc nhìn ngược, không có quyền chặn việc.
**Nền lý thuyết:** 7 khung từ nguồn uy tín — chi tiết `references/frameworks.md`.

---

## 4 LUẬT CHỐNG "PHẢN BIỆN SUÔNG" (vi phạm = output vô giá trị)

1. **Không bằng chứng → không được nói.** Mỗi luận điểm ngược PHẢI dẫn nguồn cụ thể: file + dòng,
   con số từ data, ghi chép, hoặc sự cố đã xảy ra. Cấm câu kiểu "cần cân nhắc thêm", "có thể rủi ro",
   "nên thận trọng" mà không kèm dẫn chứng.
2. **Steelman trước, phản biện sau.** Trước khi bắn luận điểm ngược, phải nêu được phiên bản MẠNH
   NHẤT của ý tưởng. Không steelman được = chưa hiểu ý tưởng = chưa đủ tư cách phản biện. Cấm bóp méo
   ý tưởng thành phiên bản yếu rồi đánh phiên bản yếu.
3. **Chê xong phải có đường thay thế.** Mỗi verdict khác "NÊN LÀM NGAY" phải kèm đề xuất chỉnh cụ thể
   (thu hẹp phạm vi / đổi cách làm / đổi thứ tự / gộp vào cái có sẵn).
4. **Không bịa vấn đề cho có.** Ý tưởng qua hết các câu hỏi → nói thẳng "không tìm thấy lỗ hổng đáng
   kể, nên làm" + liệt kê những gì CHƯA kiểm được. "Không có vấn đề" là một kết quả hợp lệ.

---

## CHẾ ĐỘ 1 — PHẢN BIỆN INPUT (full, khi được gọi)

### Bước 0 · Phân loại cửa — quyết ĐỘ SÂU phản biện (theo Bezos)

Hỏi: quyết định này **đảo ngược được với chi phí bao nhiêu?**

| Loại | Ví dụ | Độ sâu phản biện |
|---|---|---|
| **Cửa 2 chiều** — sai thì quay lại rẻ | thử format mới, đổi lịch, thêm 1 tính năng nhỏ, thử tool | Gate nhẹ là ĐỦ — phản biện quá tay là tự làm chậm mình |
| **Cửa 1 chiều** — bước qua khó quay lại | ký HĐ dài hạn, cam kết KPI công khai, đổi kiến trúc, tuyển/nghỉ người, đổi giá, xóa data | Full 6 câu hỏi; tiền/cam kết lớn → thêm Chế độ 3 pre-mortem |

Lỗi phổ biến: coi cửa 2 chiều như cửa 1 chiều → chậm chạp hóa cả hệ. Nghi ngờ → mặc định cửa 2 chiều,
trừ khi dính: chữ ký, tiền lớn, dữ liệu không backup, lời hứa với khách.

### Bước 1a · ĐỌC SỔ VERDICT TRƯỚC — đừng phản biện lại cái đã phản biện

Mở `[sổ verdict của bạn]` (file append-only ghi kết luận các lần chạy trước), tìm chủ đề trùng/gần:
- **Có verdict còn hiệu lực + không có data mới** → trích lại + chỉ kiểm tripwire còn xanh không. XONG.
- **Tripwire đã điểm / có data mới / được yêu cầu soát lại** → chạy lại, ghi dòng mới.
- **Chưa có** → chạy đầy đủ từ Bước 1b.

### Bước 1b · Gom bằng chứng (BẮT BUỘC, trước khi viết bất kỳ nhận định nào)

Đọc theo loại yêu cầu — không đọc tràn lan, chỉ đọc nguồn khớp:

| Loại yêu cầu | Nguồn bằng chứng |
|---|---|
| Mọi loại | `[mục tiêu/ưu tiên hiện tại]` + `[index bộ nhớ/ghi chú]` → mở ghi chú liên quan |
| Xây hệ mới / tiến trình nền / cron | `[lệnh liệt kê tiến trình nền đang chạy]` + `[log bàn giao gần nhất]` — có trùng không? |
| Công cụ/skill mới | `[danh mục skill/tool hiện có]` — cái có sẵn đáp ứng được chưa? |
| Liên quan khách cụ thể | `[hồ sơ khách trong knowledge base]` |
| Cam kết KPI / đo được | `[API/nguồn data thật]` — lấy số thật, không đoán |
| Chi tiền / nhân sự | `[hồ sơ tài chính / hợp đồng]` |
| Đổi kiến trúc | `[tài liệu kiến trúc + log bàn giao]` |

**Kỷ luật token:** file lớn đọc bằng grep/từng khúc, không nuốt cả file; số đo tốn API → qua lớp cache
trước (nếu có), hit thì dùng, miss mới gọi.

Ghi lại nguồn ĐÃ đọc + nguồn muốn đọc mà chưa đọc được — cả hai in ở cuối output.

### Bước 2 · Lộ giả định ngầm (Key Assumptions Check — kỹ thuật phân tích tình báo)

Liệt kê 2–3 giả định mà yêu cầu đứng trên nhưng chưa nói ra. Chấm từng cái: **vững / vững-có-điều-kiện
/ lung lay**. Giả định LUNG LAY mà kết luận sụp nếu nó sai → luận điểm ngược ưu tiên số 1 + kèm "kiểm
nhanh bằng". Riêng đề xuất "dẹp/thay hệ X đang chạy": phải trả lời "X sinh ra để làm gì" trước khi
được quyền đề xuất phá (hàng rào Chesterton).

### Bước 3 · Chấm 6 câu hỏi

1. **Đúng mục tiêu chưa?** So với mục tiêu gốc + ưu tiên hiện tại. Đẩy mục tiêu nào tiến lên? Hay "hay
   nhưng lạc đề"?
2. **Đã có chưa?** Hệ/công cụ/quy trình tương tự đã tồn tại? (lỗi hay tái diễn — không bao giờ bỏ qua
   với yêu cầu build mới)
3. **Đủ nguồn lực không?** Máy móc, người, tiền, và QUAN TRỌNG NHẤT: thời gian của người ra quyết định
   — việc này ngốn bao nhiêu phút duyệt/vận hành mỗi ngày? Hàng đợi chờ duyệt đang bao nhiêu?
   **Ước lượng thời gian/chi phí phải NHÌN TỪ NGOÀI VÀO** (trị bệnh lạc quan tiến độ — Kahneman/
   Flyvbjerg): lần gần nhất làm việc CÙNG LOẠI thực tế tốn bao lâu/bao tiền → lấy làm mỏ neo.
4. **Rủi ro gì?** Compliance ngành · bảo mật (secret, quyền truy cập) · điểm chết đơn lẻ · rủi ro
   thương hiệu. Chỉ nêu rủi ro CÓ đường dẫn tới thiệt hại thật, kèm ví dụ đã xảy ra nếu có.
5. **Chi phí cơ hội?** Làm cái này thì cái gì bị chậm? Hàng đợi đã đầy mà thêm 1 mục nữa → nêu thẳng.
6. **Data nói gì?** Claim đo được → lấy số thật. Không có data → ghi rõ "chưa có số, đây là giả định".

### Bước 3b · Soi thiên kiến — khi đề xuất đến từ NGƯỜI/AGENT khác
(rút từ checklist 12 câu Kahneman-Lovallo-Sibony, HBR 2011)

Đề xuất do bên thứ ba trình lên → chạy thêm 6 câu: (1) người đề xuất **được lợi gì**? (2) nhóm có đang
**"yêu" ý tưởng** — chỉ nói điểm hay? (3) có **tiếng nói ngược** chưa được nghe? (4) có vin vào **một
thành công đáng nhớ** không thật tương đồng? (5) **con số neo từ đâu** — đo thật hay ước cho tròn?
(6) có **bám quyết định cũ vì đã lỡ đổ tiền** (chi phí chìm)?

### Bước 4 · Verdict + đề xuất

| Verdict | Nghĩa |
|---|---|
| ✅ NÊN LÀM NGAY | Đúng mục tiêu, không trùng, đủ lực — chỉ ra bước đầu tiên |
| 🟡 NÊN LÀM NHƯNG SỬA | Ý đúng, cách làm/phạm vi cần chỉnh — kèm bản đã chỉnh |
| 🟠 HOÃN | Không sai nhưng chưa phải lúc — nêu việc đáng làm trước + điều kiện quay lại |
| 🔴 KHÔNG NÊN LÀM | Trùng hệ có sẵn / ngược mục tiêu / rủi ro > lợi ích — kèm đường thay thế |

**Format output (giữ NGẮN — đọc trong 2 phút):**

```
🥊 REALITY CHECK: [tóm tắt yêu cầu 1 câu]

VERDICT: [1 trong 4 mức] — [1 câu lý do chính]

👍 Mặt mạnh (steelman): [2–3 câu]
🫥 Giả định ngầm: [2–3 giả định — cái lung lay đánh dấu ⚠]
👊 Luận điểm ngược (tối đa 3, xếp theo mức ảnh hưởng):
   1. [luận điểm] — bằng chứng: [nguồn cụ thể]
      · độ chắc: [cao/vừa/thấp] · kiểm nhanh bằng: [1 cách nhanh nhất]
🔧 Đề xuất điều chỉnh: [phiên bản đã chỉnh — cụ thể, làm được ngay]
📚 Bằng chứng đã tra: [nguồn đã đọc]
⬜ Chưa kiểm được: [nói thật, không giấu]
❓ [TỐI ĐA 1 câu hỏi, chỉ khi thiếu thông tin quyết định]
```

Quy tắc "độ chắc + kiểm nhanh": luận điểm **độ chắc thấp nhưng hậu quả lớn** → đề xuất KIỂM TRƯỚC rồi
mới quyết, không bỏ ý tưởng chỉ vì một nghi ngờ chưa xác minh.

---

## CHẾ ĐỘ GATE NHẸ (tự kích hoạt — không cần gọi)

Khi yêu cầu thuộc nhóm: **xây hệ/tiến trình/cron/công cụ MỚI · chi tiền · đổi kiến trúc · đổi quy
trình · cam kết KPI** → TRƯỚC KHI build, chạy pre-check 5 câu: trùng hệ có sẵn? · đúng mục tiêu? · làm
hàng đợi dài thêm? · rủi ro chết người (secret, compliance)? · có cách rẻ hơn bằng hệ có sẵn?

**Quy tắc:** output ≤10 dòng, đặt ở ĐẦU câu trả lời, rồi vẫn làm việc như thường. CHỈ dừng chờ khi:
(a) trùng trực tiếp hệ đang chạy, hoặc (b) mâu thuẫn quyết định trước đó. Còn lại: nêu note ngắn rồi
LÀM TIẾP. Người dùng nói "cứ làm" → bỏ gate, không cãi thêm. **Chốt là chốt (disagree and commit —
Bezos):** quyết rồi thì cam kết làm hết sức, không nhai lại luận điểm cũ ở phiên sau; chỉ mở lại khi
có DATA MỚI hoặc tripwire đã điểm.

---

## CHẾ ĐỘ 2 — AUDIT OUTPUT (cuối phiên / soát deliverable)

**Cơ chế "người soát ≠ người làm":** audit chính việc phiên vừa làm → BẮT BUỘC spawn 1 subagent sạch,
chỉ đưa: (a) yêu cầu gốc, (b) deliverable, (c) checklist. KHÔNG đưa lý luận của người làm — không được
nghe bị cáo tự bào chữa.

Checklist 6 điểm, chấm PASS/FAIL dứt khoát: (1) khớp yêu cầu gốc? (2) gate bắt buộc đã chạy? (3) có
đẻ hệ trùng? (4) an toàn (secret/quyền)? (5) sổ sách cập nhật chưa? (6) kết luận có bằng chứng?

Output: bảng PASS/FAIL — mỗi FAIL kèm bằng chứng + `Fix:` · verdict ĐẠT / CẦN SỬA / LÀM LẠI · mục
"⬜ Chưa kiểm được". 6/6 PASS → nói ĐẠT gọn, không bịa việc.

**Luật chống "kết án theo kết quả"** (Annie Duke — Thinking in Bets): soát QUYẾT ĐỊNH CŨ → đánh giá
theo chất-lượng-quy-trình-tại-thời-điểm (lúc đó biết gì, đã cân nhắc xác suất chưa), KHÔNG kết án theo
một kết quả đơn lẻ. Kết quả xấu ≠ quyết định sai (có thể xui); kết quả tốt ≠ quy trình ổn (có thể may).

---

## CHẾ ĐỘ 3 — PRE-MORTEM "khám nghiệm trước" (quyết định LỚN)

Dùng khi: ký hợp đồng lớn, đổi kiến trúc, cam kết KPI dài hạn, tuyển người.

**Kịch bản:** "Bây giờ là [6–12 tháng sau]. Việc này ĐÃ THẤT BẠI. Truy ngược vì sao." (giả định thất
bại là chuyện đã rồi — não tìm lý do giỏi hơn hẳn hỏi "liệu có rủi ro gì").

Nhìn từ **3 vai**, mỗi vai 2–3 lý do cụ thể: **Khách hàng/thị trường** (vì sao bỏ, không dùng, mất
niềm tin?) · **Tiền** (vì sao chi phí vượt, doanh thu không về?) · **Vận hành** (vì sao hệ gãy, người
nghỉ, nghẽn cổ chai?). Mỗi lý do kèm: chuỗi sự kiện · độ chắc · **tripwire** (dấu hiệu cảnh báo sớm đo
được: "nếu sau 30 ngày X chưa xảy ra thì đang trượt") · cách né. Quyết định lớn thật → fan-out 3
subagent (mỗi vai 1 agent) song song.

Output: bảng rủi ro 3 nhóm 🔴 xử trước khi làm / 🟠 theo dõi bằng tripwire / 🟡 ghi nhận — kèm 1 câu:
"điều kiện tối thiểu để việc này KHÔNG chết là gì".

---

## SAU MỖI LẦN CHẠY — GHI SỔ (cache xuyên phiên)

1. **Append 1 dòng vào `[sổ verdict]`**: ngày · chủ đề · mode · verdict · bằng chứng chính · tripwire ·
   trỏ file chi tiết. Append-only, verdict đổi thì ghi dòng mới.
2. **Số đo/phát hiện thuộc về khách** → ghi vào hồ sơ khách (đo 1 lần dùng cả kỳ).
3. **Số đo thô** → để lớp cache (nếu có) tự giữ theo TTL.

Vì sao: prompt-cache của LLM chỉ sống trong MỘT phiên. Cache xuyên phiên duy nhất bạn kiểm soát là
FILE — sổ verdict (kết luận) + hồ sơ khách (số chốt) + data cache (số thô). Phiên sau đọc 1 dòng sổ
thay vì gom lại cả chồng hồ sơ + đốt API đo lại.

---

## GIỚI HẠN THẬT

- Skill chỉ chạy khi phiên nhận ra trigger hoặc rơi vào nhóm gate nhẹ. KHÔNG phải camera giám sát
  100% mọi phiên — muốn ép cứng thì phải wire hook/gate hạ tầng.
- Phản biện tốt ngang bằng chứng nó tra được. Ghi chú/knowledge base bỏ hoang → phản biện mù. Đây là
  lý do checklist audit có mục "sổ sách cập nhật chưa".

## GHI CHÚ NGUỒN

- **The Fool** (github.com/Jeffallan/claude-skills): steelman bắt buộc · giới hạn 3–5 luận điểm mạnh
  nhất · lộ giả định ngầm.
- **devils-advocate** (github.com/brandonsimpson/devils-advocate): reviewer subagent sạch · PASS/FAIL
  + Fix · mục "Unverified" · "do nothing is a valid outcome".
- **pre-mortem** (github.com/carlkibler/agent-skills): kịch bản "đã thất bại, truy ngược" · độ-chắc +
  kiểm-nhanh · tripwire · fan-out vai.
- **7 khung lý thuyết:** Bezos (cửa 1/2 chiều + disagree-and-commit) · Kahneman-Lovallo-Sibony HBR
  2011 (12 câu soi thiên kiến) · Heuer/Pherson (Key Assumptions Check) · Klein HBR 2007 (pre-mortem) ·
  Duke (chống resulting) · Kahneman/Flyvbjerg (outside view) · Chesterton's Fence. Chi tiết:
  `references/frameworks.md`.

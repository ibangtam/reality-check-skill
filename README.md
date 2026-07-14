# Reality Check — a devil's-advocate skill for Claude

> **Tiếng Việt bên dưới ⬇️**

A [Claude](https://claude.ai) Agent Skill that pushes back on **your own** ideas, requests, and plans
with **evidence** — so decisions get more realistic before you commit. Instead of an AI that agrees
too fast, this one argues the other side, but only with proof it can actually cite.

## Why

The dangerous failure mode of running a business on AI isn't the AI being wrong — it's the AI
**agreeing too fast**. This skill makes the assistant earn the right to critique: steelman your idea
first, cite specific evidence, always offer an alternative, and never manufacture problems just to
look rigorous.

## The 4 modes

1. **Critique input** — surfaces hidden assumptions, then runs 6 questions (right goal? already
   exists? enough resources? what risks? opportunity cost? what does the data say?) → a 4-level
   verdict + a concrete revised proposal.
2. **Audit output** — a *clean subagent* (that never sees the author's reasoning) checks a deliverable
   against the original request, PASS/FAIL each point with a `Fix:`.
3. **Light gate** — auto-fires before you build something new, spend money, change architecture, or
   commit to a KPI. ≤10 lines, then keeps working.
4. **Pre-mortem** — for big, one-way-door decisions: assume it already failed 6–12 months from now,
   trace back why from 3 roles (customer / money / operations), each with an early-warning tripwire.

## Grounded in real frameworks

Not vibes — it stands on: Bezos's **one-way vs two-way doors** + *disagree and commit*;
Kahneman–Lovallo–Sibony's **12-question bias checklist** (HBR 2011); the intelligence community's
**Key Assumptions Check** (Heuer & Pherson); Gary Klein's **pre-mortem** (HBR 2007); Annie Duke's
**resulting** (decision quality ≠ outcome); Kahneman/Flyvbjerg's **outside view**; and
**Chesterton's Fence**. See [`references/frameworks.md`](references/frameworks.md).

## Install

**Claude Code / Claude Desktop:** drop the folder into your skills directory
(`~/.claude/skills/reality-check/`) or upload the zip in Settings → Capabilities → Skills.

**claude.ai:** Settings → Capabilities → Skills → upload a zip of this folder.

Then just say *"reality check this"*, *"phản biện giúp tôi"*, *"pre-mortem X"*, or *"audit this
session"*.

## Customize it for your setup

The skill is **generic** — every `[in square brackets]` is a placeholder. Point them at your own
sources so the critique has real evidence to cite:

- `[mục tiêu/ưu tiên hiện tại]` → your goals / current priorities file
- `[hồ sơ khách trong knowledge base]` → your client/project records
- `[sổ verdict]` → an append-only log file where past verdicts get cached across sessions
- `[API/nguồn data thật]` → whatever data tools you have (analytics, CRM, search data…)
- `[lệnh liệt kê tiến trình nền]` → how you list running jobs on your machine

The more real your knowledge base, the sharper the pushback. Empty knowledge base → blind critique.

## Credits

Built on top of ideas from three earlier community skills — full credit in
[`references/frameworks.md`](references/frameworks.md):
[The Fool](https://github.com/Jeffallan/claude-skills) ·
[devils-advocate](https://github.com/brandonsimpson/devils-advocate) ·
[pre-mortem](https://github.com/carlkibler/agent-skills).

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, adapt it.

---

# 🇻🇳 Reality Check — skill phản biện cho Claude

Một Skill cho [Claude](https://claude.ai) chuyên **cãi lại chính bạn** — phản biện ý tưởng, yêu cầu,
kế hoạch của bạn bằng **bằng chứng**, để quyết định thực tế hơn trước khi bắt tay làm. Thay vì một AI
gật đầu quá nhanh, cái này đưa góc nhìn ngược — nhưng chỉ khi có bằng chứng dẫn được ra.

## Vì sao

Điều nguy hiểm khi vận hành công việc bằng AI không phải AI làm sai — mà là AI **đồng ý quá nhanh**.
Skill này bắt trợ lý phải *giành quyền* được chê: steelman ý tưởng của bạn trước, dẫn bằng chứng cụ
thể, luôn kèm đường thay thế, và không bao giờ bịa vấn đề cho ra vẻ khó tính.

## 4 chế độ

1. **Phản biện input** — lộ giả định ngầm, rồi chạy 6 câu hỏi (đúng mục tiêu? đã có chưa? đủ nguồn
   lực? rủi ro gì? chi phí cơ hội? data nói gì?) → verdict 4 mức + bản đề xuất đã chỉnh.
2. **Audit output** — một *subagent sạch* (không thấy lý luận người làm) soát deliverable so với yêu
   cầu gốc, chấm PASS/FAIL từng điểm kèm `Fix:`.
3. **Gate nhẹ** — tự bật trước khi bạn build cái mới, chi tiền, đổi kiến trúc, cam kết KPI. ≤10 dòng
   rồi làm tiếp.
4. **Pre-mortem** — cho quyết định lớn: giả định 6–12 tháng sau nó ĐÃ thất bại, truy ngược lý do từ 3
   vai (khách / tiền / vận hành), mỗi vai kèm chuông cảnh báo sớm.

## Đứng trên vai người khổng lồ

Không phải cảm tính — nền lý thuyết: **cửa 1 chiều/2 chiều** của Bezos + *disagree and commit*; **12
câu soi thiên kiến** của Kahneman (Nobel kinh tế, HBR 2011); **kiểm giả định** của giới phân tích tình
báo; **pre-mortem** của Gary Klein; **chống resulting** của Annie Duke (chất lượng quyết định ≠ kết
quả); **nhìn từ ngoài vào** của Kahneman/Flyvbjerg; **hàng rào Chesterton**. Chi tiết ở
[`references/frameworks.md`](references/frameworks.md).

## Cài đặt

**Claude Code / Claude Desktop:** bỏ thư mục này vào `~/.claude/skills/reality-check/`, hoặc upload
zip trong Settings → Capabilities → Skills.

**claude.ai:** Settings → Capabilities → Skills → upload zip của thư mục này.

Rồi gõ *"phản biện giúp tôi..."*, *"ý này có ổn không"*, *"pre-mortem vụ X"*, *"audit phiên này"*.

## Tùy biến cho hệ của bạn

Skill để ở dạng **generic** — mọi chỗ `[trong ngoặc vuông]` là placeholder. Trỏ chúng vào nguồn dữ
liệu thật của bạn thì phản biện mới có bằng chứng để dẫn. Knowledge base càng thật, phản biện càng
sắc; để trống → phản biện mù.

## Giấy phép

MIT — dùng, fork, chỉnh thoải mái.

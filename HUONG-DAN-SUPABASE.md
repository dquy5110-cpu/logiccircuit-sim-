# Hướng dẫn cài đặt Luyện Tập + Supabase (LogicCircuit-Sim)

## 1. Tạo project Supabase
1. Vào https://supabase.com → **Sign in** (đăng nhập bằng GitHub/email) → **New project**.
2. Chọn Organization, đặt tên (vd: `logiccircuit-sim`), đặt **Database password** (lưu lại), chọn Region gần Việt Nam (vd Singapore) → **Create new project**, chờ 1–2 phút.

## 2. Lấy Project URL và publishable key
Vào **Project Settings → API Keys** (hoặc **Data API / API**):
- **Project URL**: dạng `https://xxxx.supabase.co`.
- **Publishable key** (`sb_publishable_...`) hoặc khóa **anon** (JWT cũ) – hai loại đều dùng được cho trình duyệt.
- **KHÔNG** dùng `secret` / `service_role` trong file HTML.

Mở `LogicCircuit-Sim.html`, tìm dòng gần cuối file và điền:
```html
<script>window.PRACTICE_CONFIG = { SUPABASE_URL: 'https://xxxx.supabase.co', SUPABASE_KEY: 'sb_publishable_...' };</script>
```

## 3. Bật đăng nhập ẩn danh (bắt buộc)
**Authentication → Sign In / Providers** (hoặc *Settings*) → bật **Allow anonymous sign-ins** → Save.
Mỗi trình duyệt học sinh nhận một danh tính ẩn danh riêng; nhờ đó RLS/RPC phân biệt được học sinh này với học sinh khác mà không cần mật khẩu.
- Cũng nên **tắt "Allow new users to sign up"** ở Email provider để không ai tự đăng ký tài khoản email.
- **Authentication → Rate Limits**: giới hạn đăng nhập ẩn danh mặc định tính theo IP (khoảng 30 lượt/giờ). Cả lớp dùng chung mạng trường có thể bị chặn → hãy tăng giá trị này (vd 300) trước buổi học.

## 4. Chạy SQL
**SQL Editor → New query** → dán toàn bộ `supabase_setup.sql` → **Run**. Kết quả "Success. No rows returned" là đúng. File chạy lại nhiều lần an toàn (câu hỏi được cập nhật theo `id`).
Kiểm tra: **Table Editor** phải có 5 bảng `students, practice_questions, practice_attempts, practice_answers, teachers`; bảng `practice_questions` có 15 dòng.

## 5. Chạy website
Nên chạy qua HTTP, không mở trực tiếp file://:
```
cd thư-mục-chứa-file
python3 -m http.server 8000     # rồi mở http://localhost:8000/LogicCircuit-Sim.html
```
Để học sinh dùng từ nhiều máy: đưa file lên GitHub Pages / Netlify / Cloudflare Pages (miễn phí). Máy cần có Internet (thư viện Supabase tải từ jsDelivr).

## 6. Kiểm tra kết nối và dữ liệu được lưu
1. Mở trang → **📝 Luyện Tập** → không còn cảnh báo vàng "Chưa cấu hình".
2. **Tiến hành Luyện Tập** → nhập tên, lớp → làm vài câu → **Nộp bài**. Chỉ khi thấy "✅ Bài làm đã được lưu thành công" là Supabase đã xác nhận.
3. Trong Supabase **Table Editor**: `students` có 1 dòng; `practice_attempts` có 1 dòng `status = submitted` với điểm/đếm câu; `practice_answers` có đúng 15 dòng của lượt đó (cùng `attempt_id`).
4. Lỗi thường gặp: F12 → Console/Network; xem mục 9.

## 7. Cấp quyền giáo viên
1. **Authentication → Users → Add user → Create new user**: nhập email + mật khẩu mạnh, tick **Auto Confirm User**.
2. **SQL Editor** chạy (thay email):
```sql
insert into public.teachers(user_id,email)
select id,email from auth.users where email='email-giao-vien@example.com'
on conflict (user_id) do nothing;
```
3. Trên website: **Luyện Tập → 🔒 Khu vực giáo viên** (hoặc `switchView('results')`) → đăng nhập. Có tìm theo tên, lọc lớp/ngày, bấm một dòng để xem chi tiết từng câu, **Xuất CSV** (mở được bằng Excel, đã chống chèn công thức).
4. Luôn **Đăng xuất** trên máy dùng chung. Khi học sinh bắt đầu làm bài, phiên giáo viên (nếu còn) bị đăng xuất tự động.

## 8. Sửa / thêm câu hỏi
**Table Editor → practice_questions**: sửa `question_text`, `options` (JSON có đủ khóa A,B,C,D), `correct_answer`, `explanation`; tắt câu bằng `is_active = false`; thêm câu mới với `id` khác (vd `q16`) và `position`. Lượt làm bài đang dở vẫn dùng bản đề đã chụp lúc bắt đầu; kết quả cũ không bị đổi.

## 9. Bảo mật và xử lý lỗi
- Học sinh **không** truy cập được bảng nào trực tiếp (RLS bật, chỉ giáo viên có quyền SELECT; không ai INSERT/UPDATE trực tiếp). Học sinh chỉ gọi các hàm RPC; đáp án đúng và lời giải **không** được gửi xuống trình duyệt trước khi nộp; điểm và `is_correct` do máy chủ tính, không thể tự gửi điểm.
- Mỗi lượt có UUID thuộc về danh tính ẩn danh tạo ra nó, nên đoán UUID người khác không đọc được gì.
- **Giới hạn:** danh tính học sinh chỉ là "trình duyệt này", không xác thực họ tên thật (một người có thể nhập tên bạn khác). Xóa dữ liệu trình duyệt/đổi máy sẽ mất khả năng khôi phục bài làm dở. Người dùng ác ý vẫn có thể tạo nhiều danh tính ẩn danh (chỉ bị hạn chế bởi rate limit; có thể bật CAPTCHA). Cần xác thực họ tên thật → dùng danh sách học sinh/mã lớp hoặc Supabase Auth cho từng học sinh.
- `Invalid API key` / lỗi 401: sai URL hoặc key. `Anonymous sign-ins are disabled`: chưa bật mục 3. `permission denied`/`NOT_AUTHENTICATED`: chưa chạy đủ SQL hoặc phiên hết hạn. `ATTEMPT_NOT_FOUND`: bài làm dở thuộc trình duyệt khác. "Mất kết nối": bài vẫn lưu trên máy, bấm **Nộp bài** lại khi có mạng (nộp lặp không tạo bản ghi trùng).

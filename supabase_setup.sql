-- ============================================================
-- LogicCircuit-Sim: Luyện Tập - thiết lập Supabase (chạy lại nhiều lần an toàn)
-- Yêu cầu: bật Authentication > Sign In / Providers > "Allow anonymous sign-ins"
-- Mô hình: học sinh KHÔNG đọc/ghi bảng trực tiếp; chỉ gọi các hàm RPC bên dưới.
-- Đáp án đúng nằm trong DB, chấm điểm trong hàm SECURITY DEFINER.
-- ============================================================
create table if not exists public.students(
  id uuid primary key default gen_random_uuid(),
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  full_name text not null check (char_length(full_name) between 2 and 80),
  class_name text not null check (class_name ~ '^[A-Z0-9._/-]{1,20}$'),
  created_at timestamptz not null default now());
create unique index if not exists students_uq on public.students(auth_user_id, lower(full_name), class_name);

create table if not exists public.practice_questions(
  id text primary key check (id ~ '^[a-z0-9_]{1,40}$'),
  position int not null, topic text not null,
  level text not null default 'Nhận biết' check (level in ('Nhận biết','Thông hiểu','Vận dụng')),
  question_text text not null, options jsonb not null,
  correct_answer text not null check (correct_answer in ('A','B','C','D')),
  explanation text not null default '', is_active boolean not null default true,
  updated_at timestamptz not null default now(),
  constraint options_shape check (jsonb_typeof(options)='object' and options ?& array['A','B','C','D']));

create table if not exists public.practice_attempts(
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references public.students(id) on delete cascade,
  auth_user_id uuid not null references auth.users(id) on delete cascade,
  attempt_number int not null,
  status text not null default 'in_progress' check (status in ('in_progress','submitted','failed')),
  question_set_version text not null,
  questions_snapshot jsonb not null,           -- bản chụp đề + đáp án tại thời điểm bắt đầu
  draft_answers jsonb not null default '{}'::jsonb,
  started_at timestamptz not null default now(), submitted_at timestamptz,
  total_questions int not null,
  correct_count int, wrong_count int, unanswered_count int,
  score numeric(4,2) check (score between 0 and 10), duration_seconds int,
  created_at timestamptz not null default now(),
  unique(student_id, attempt_number),
  check (status<>'submitted' or (submitted_at is not null and score is not null)));
create index if not exists attempts_student_idx on public.practice_attempts(student_id);
create index if not exists attempts_started_idx on public.practice_attempts(started_at desc);

create table if not exists public.practice_answers(
  id uuid primary key default gen_random_uuid(),
  attempt_id uuid not null references public.practice_attempts(id) on delete cascade,
  question_id text not null, question_position int not null,
  selected_answer text check (selected_answer in ('A','B','C','D')),
  correct_answer text not null, is_correct boolean not null,
  question_snapshot jsonb not null, answered_at timestamptz,
  unique(attempt_id, question_id));
create index if not exists answers_attempt_idx on public.practice_answers(attempt_id);

create table if not exists public.teachers(
  user_id uuid primary key references auth.users(id) on delete cascade,
  email text, created_at timestamptz not null default now());

create or replace function public.is_teacher() returns boolean
language sql stable security definer set search_path=public as
$$ select exists(select 1 from public.teachers t where t.user_id=auth.uid()) $$;

-- ---------- RLS: chỉ giáo viên được SELECT; không ai ghi trực tiếp ----------
-- Lưu ý: người dùng ẩn danh (anonymous) cũng mang role "authenticated", nên phải kiểm tra is_teacher().
alter table public.students enable row level security;
alter table public.practice_questions enable row level security;
alter table public.practice_attempts enable row level security;
alter table public.practice_answers enable row level security;
alter table public.teachers enable row level security;
revoke all on public.students, public.practice_questions, public.practice_attempts, public.practice_answers, public.teachers from anon, authenticated;
grant select on public.students, public.practice_questions, public.practice_attempts, public.practice_answers to authenticated;
drop policy if exists t_sel on public.students; create policy t_sel on public.students for select to authenticated using (public.is_teacher());
drop policy if exists t_sel on public.practice_questions; create policy t_sel on public.practice_questions for select to authenticated using (public.is_teacher());
drop policy if exists t_sel on public.practice_attempts; create policy t_sel on public.practice_attempts for select to authenticated using (public.is_teacher());
drop policy if exists t_sel on public.practice_answers; create policy t_sel on public.practice_answers for select to authenticated using (public.is_teacher());

-- ---------- Hàm nội bộ (không cho client gọi) ----------
create or replace function public._pr_payload(p_id uuid) returns jsonb
language sql stable security definer set search_path=public as $$
 select jsonb_build_object('attempt_id',a.id,'full_name',s.full_name,'class_name',s.class_name,
  'attempt_number',a.attempt_number,'status',a.status,'started_at',a.started_at,'draft_answers',a.draft_answers,
  'questions',(select coalesce(jsonb_agg(e-'correct_answer'-'explanation' order by o),'[]'::jsonb)
               from jsonb_array_elements(a.questions_snapshot) with ordinality t(e,o)))
 from public.practice_attempts a join public.students s on s.id=a.student_id where a.id=p_id $$;

create or replace function public._pr_result(p_id uuid) returns jsonb
language sql stable security definer set search_path=public as $$
 select jsonb_build_object('attempt_id',a.id,'full_name',s.full_name,'class_name',s.class_name,'attempt_number',a.attempt_number,
  'status',a.status,'started_at',a.started_at,'submitted_at',a.submitted_at,'duration_seconds',a.duration_seconds,
  'total_questions',a.total_questions,'correct_count',a.correct_count,'wrong_count',a.wrong_count,
  'unanswered_count',a.unanswered_count,'score',a.score,
  'answers',(select coalesce(jsonb_agg(jsonb_build_object('question_id',x.question_id,'position',x.question_position,
     'topic',x.question_snapshot->>'topic','question_text',x.question_snapshot->>'question_text',
     'options',x.question_snapshot->'options','selected_answer',x.selected_answer,'correct_answer',x.correct_answer,
     'is_correct',x.is_correct,'explanation',x.question_snapshot->>'explanation') order by x.question_position),'[]'::jsonb)
   from public.practice_answers x where x.attempt_id=a.id))
 from public.practice_attempts a join public.students s on s.id=a.student_id where a.id=p_id $$;

create or replace function public._pr_clean(p_snap jsonb, p_ans jsonb) returns jsonb
language sql immutable set search_path=public as $$
 select case when p_ans is null or jsonb_typeof(p_ans)<>'object' then '{}'::jsonb else
  (select coalesce(jsonb_object_agg(k,v),'{}'::jsonb) from jsonb_each_text(p_ans) x(k,v)
   where v in ('A','B','C','D') and exists(select 1 from jsonb_array_elements(p_snap) e where e->>'id'=k)) end $$;

-- ---------- RPC cho học sinh ----------
create or replace function public.practice_start_attempt(p_full_name text, p_class_name text) returns jsonb
language plpgsql security definer set search_path=public as $$
declare u uuid:=auth.uid(); nm text; cl text; st public.students; att public.practice_attempts; snap jsonb;
begin
 if u is null then raise exception 'NOT_AUTHENTICATED'; end if;
 perform pg_advisory_xact_lock(hashtext(u::text));
 nm:=regexp_replace(btrim(coalesce(p_full_name,'')),'\s+',' ','g');
 cl:=upper(regexp_replace(coalesce(p_class_name,''),'\s+','','g'));
 if char_length(nm) not between 2 and 80 or nm ~ '[[:cntrl:]<>]' then raise exception 'INVALID_NAME'; end if;
 if cl !~ '^[A-Z0-9._/-]{1,20}$' then raise exception 'INVALID_CLASS'; end if;
 select * into st from public.students where auth_user_id=u and lower(full_name)=lower(nm) and class_name=cl;
 if not found then insert into public.students(auth_user_id,full_name,class_name) values(u,nm,cl) returning * into st; end if;
 select * into att from public.practice_attempts where student_id=st.id and status='in_progress' order by started_at desc limit 1;
 if found then return public._pr_payload(att.id); end if;   -- tải lại trang: không tạo lượt trùng
 select coalesce(jsonb_agg(jsonb_build_object('id',q.id,'position',q.position,'topic',q.topic,'level',q.level,
   'question_text',q.question_text,'options',q.options,'correct_answer',q.correct_answer,'explanation',q.explanation)
   order by q.position,q.id),'[]'::jsonb) into snap from public.practice_questions q where q.is_active;
 if jsonb_array_length(snap)=0 then raise exception 'NO_QUESTIONS'; end if;
 insert into public.practice_attempts(student_id,auth_user_id,attempt_number,question_set_version,questions_snapshot,total_questions)
 values(st.id,u,(select coalesce(max(attempt_number),0)+1 from public.practice_attempts where student_id=st.id),
   md5(snap::text),snap,jsonb_array_length(snap)) returning * into att;
 return public._pr_payload(att.id);
end $$;

create or replace function public.practice_get_attempt(p_attempt_id uuid) returns jsonb
language plpgsql security definer set search_path=public as $$
begin
 if not exists(select 1 from public.practice_attempts where id=p_attempt_id and auth_user_id=auth.uid()) then raise exception 'ATTEMPT_NOT_FOUND'; end if;
 return public._pr_payload(p_attempt_id);
end $$;

create or replace function public.practice_save_draft(p_attempt_id uuid, p_answers jsonb) returns jsonb
language plpgsql security definer set search_path=public as $$
declare n int;
begin
 update public.practice_attempts set draft_answers=public._pr_clean(questions_snapshot,p_answers)
  where id=p_attempt_id and auth_user_id=auth.uid() and status='in_progress';
 get diagnostics n=row_count;
 return jsonb_build_object('saved',n=1);
end $$;

create or replace function public.practice_submit_attempt(p_attempt_id uuid, p_answers jsonb) returns jsonb
language plpgsql security definer set search_path=public as $$
declare a public.practice_attempts; c jsonb; nowt timestamptz:=now(); cor int; un int;
begin
 select * into a from public.practice_attempts where id=p_attempt_id and auth_user_id=auth.uid() for update;
 if not found then raise exception 'ATTEMPT_NOT_FOUND'; end if;
 if a.status='submitted' then return public._pr_result(a.id); end if;   -- gửi lại: trả kết quả cũ, không ghi trùng
 c:=public._pr_clean(a.questions_snapshot,p_answers);
 insert into public.practice_answers(attempt_id,question_id,question_position,selected_answer,correct_answer,is_correct,question_snapshot,answered_at)
 select a.id,e->>'id',(e->>'position')::int,c->>(e->>'id'),e->>'correct_answer',
        coalesce(c->>(e->>'id')=e->>'correct_answer',false),e,case when c->>(e->>'id') is not null then nowt end
 from jsonb_array_elements(a.questions_snapshot) e;
 select count(*) filter(where is_correct), count(*) filter(where selected_answer is null) into cor,un
  from public.practice_answers where attempt_id=a.id;
 update public.practice_attempts set status='submitted',submitted_at=nowt,draft_answers=c,
   correct_count=cor,unanswered_count=un,wrong_count=a.total_questions-cor-un,
   score=round(cor*10.0/a.total_questions,2),duration_seconds=greatest(0,extract(epoch from nowt-a.started_at)::int)
  where id=a.id;
 return public._pr_result(a.id);
end $$;

create or replace function public.practice_get_result(p_attempt_id uuid) returns jsonb
language plpgsql security definer set search_path=public as $$
begin
 if not exists(select 1 from public.practice_attempts where id=p_attempt_id and auth_user_id=auth.uid() and status='submitted') then raise exception 'NOT_SUBMITTED'; end if;
 return public._pr_result(p_attempt_id);
end $$;

-- ---------- Quyền thực thi ----------
revoke execute on function public._pr_payload(uuid),public._pr_result(uuid),public._pr_clean(jsonb,jsonb) from public,anon,authenticated;
revoke execute on function public.practice_start_attempt(text,text),public.practice_get_attempt(uuid),public.practice_save_draft(uuid,jsonb),
  public.practice_submit_attempt(uuid,jsonb),public.practice_get_result(uuid),public.is_teacher() from public,anon;
grant execute on function public.practice_start_attempt(text,text),public.practice_get_attempt(uuid),public.practice_save_draft(uuid,jsonb),
  public.practice_submit_attempt(uuid,jsonb),public.practice_get_result(uuid),public.is_teacher() to authenticated;

-- ---------- Bộ câu hỏi mẫu (sửa/ thêm/ tắt bằng Table Editor: practice_questions) ----------
insert into public.practice_questions(id,position,topic,level,question_text,options,correct_answer,explanation) values
('q01',1,'Cổng logic','Nhận biết','Cổng logic nào cho đầu ra bằng 1 khi và chỉ khi TẤT CẢ đầu vào bằng 1?','{"A": "OR", "B": "XOR", "C": "AND", "D": "NOR"}'::jsonb,'C','Cổng AND (phép nhân logic): Y = A·B chỉ bằng 1 khi mọi đầu vào bằng 1.'),
('q02',2,'Cổng logic','Nhận biết','Đặc điểm của cổng NOT là gì?','{"A": "Một đầu vào, đầu ra luôn ngược mức logic với đầu vào", "B": "Hai đầu vào, đầu ra bằng 1 khi hai đầu vào giống nhau", "C": "Một đầu vào, đầu ra luôn bằng đầu vào", "D": "Hai đầu vào, đầu ra bằng 1 khi có ít nhất một đầu vào bằng 1"}'::jsonb,'A','NOT là phép phủ định: đầu vào 0 cho đầu ra 1 và ngược lại.'),
('q03',3,'Cổng logic','Thông hiểu','Cổng XOR cho đầu ra bằng 1 khi nào?','{"A": "Khi cả hai đầu vào bằng 1", "B": "Khi hai đầu vào có giá trị khác nhau", "C": "Khi hai đầu vào giống nhau", "D": "Khi cả hai đầu vào bằng 0"}'::jsonb,'B','XOR (hoặc loại trừ) bằng 1 khi A ≠ B. Trường hợp giống nhau là XNOR.'),
('q04',4,'Cổng logic','Thông hiểu','Cổng nào là phủ định (đảo đầu ra) của cổng OR?','{"A": "NAND", "B": "XNOR", "C": "AND", "D": "NOR"}'::jsonb,'D','NOR = NOT(OR): chỉ bằng 1 khi tất cả đầu vào bằng 0.'),
('q05',5,'Bảng chân trị','Vận dụng','Với A = 1, B = 0, đầu ra của các cổng NAND, NOR, XNOR lần lượt là?','{"A": "1, 0, 0", "B": "0, 1, 1", "C": "1, 1, 0", "D": "0, 0, 1"}'::jsonb,'A','NAND(1,0) = NOT(0) = 1; NOR(1,0) = NOT(1) = 0; XNOR(1,0) = 0 vì hai đầu vào khác nhau.'),
('q06',6,'Bảng chân trị','Thông hiểu','Cổng 2 đầu vào có bảng chân trị (A,B → Y): 00→1, 01→0, 10→0, 11→1 là cổng nào?','{"A": "XOR", "B": "XNOR", "C": "NAND", "D": "NOR"}'::jsonb,'B','Y = 1 khi hai đầu vào giống nhau nên đó là XNOR.'),
('q07',7,'Half Adder','Nhận biết','Bộ cộng bán phần (Half Adder) dùng cổng nào để tạo bit tổng S và bit nhớ C?','{"A": "S dùng AND, C dùng XOR", "B": "S dùng OR, C dùng AND", "C": "S dùng XOR, C dùng AND", "D": "S dùng XOR, C dùng OR"}'::jsonb,'C','S = A ⊕ B, C = A · B.'),
('q08',8,'Half Adder','Vận dụng','Half Adder với A = 1 và B = 1 cho kết quả S và C là?','{"A": "S = 1, C = 0", "B": "S = 1, C = 1", "C": "S = 0, C = 0", "D": "S = 0, C = 1"}'::jsonb,'D','1 + 1 = 10 (nhị phân): bit tổng S = 0, bit nhớ C = 1.'),
('q09',9,'Full Adder','Thông hiểu','Bộ cộng toàn phần (Full Adder) có bao nhiêu đầu vào và đầu ra?','{"A": "3 đầu vào (A, B, Cin), 2 đầu ra (S, Cout)", "B": "2 đầu vào (A, B), 2 đầu ra (S, C)", "C": "3 đầu vào, 1 đầu ra", "D": "2 đầu vào, 3 đầu ra"}'::jsonb,'A','Full Adder cộng A, B và bit nhớ vào Cin, cho ra tổng S và bit nhớ ra Cout.'),
('q10',10,'Full Adder','Vận dụng','Full Adder với A = 1, B = 1, Cin = 1 cho S và Cout là?','{"A": "S = 0, Cout = 1", "B": "S = 1, Cout = 0", "C": "S = 1, Cout = 1", "D": "S = 0, Cout = 0"}'::jsonb,'C','1 + 1 + 1 = 11 (nhị phân): S = 1, Cout = 1.'),
('q11',11,'Full Adder','Thông hiểu','Có thể xây dựng một Full Adder từ các thành phần nào?','{"A": "2 Half Adder và 1 cổng AND", "B": "2 Half Adder và 1 cổng OR", "C": "1 Half Adder và 2 cổng OR", "D": "3 cổng NOT và 1 cổng XOR"}'::jsonb,'B','Half Adder 1 cộng A, B; Half Adder 2 cộng kết quả với Cin; hai bit nhớ được gộp bằng cổng OR.'),
('q12',12,'Bộ cộng nhiều bit','Vận dụng','Bộ cộng 4 bit cộng 1011 và 0110 (11 + 6). Kết quả 4 bit tổng và bit nhớ Cout là?','{"A": "Tổng 0001, Cout = 1", "B": "Tổng 0001, Cout = 0", "C": "Tổng 1101, Cout = 0", "D": "Tổng 1001, Cout = 1"}'::jsonb,'A','11 + 6 = 17 = 1 0001 (nhị phân): 4 bit thấp là 0001, bit nhớ ra là 1 (tràn 4 bit).'),
('q13',13,'Phép trừ bù 2','Vận dụng','Thực hiện 0111 − 0011 (4 bit) bằng mã bù 2. Kết quả sau khi bỏ bit nhớ ra ngoài là?','{"A": "1010", "B": "0110", "C": "1100", "D": "0100"}'::jsonb,'D','Mã bù 2 của 0011 là 1101. 0111 + 1101 = 1 0100; bỏ bit nhớ ta được 0100 (= 4).'),
('q14',14,'Phép nhân','Vận dụng','Dùng thuật toán Shift-and-Add, 0110 × 0011 (6 × 3) cho kết quả 8 bit là?','{"A": "00001100", "B": "00011000", "C": "00010010", "D": "00010100"}'::jsonb,'C','6 × 3 = 18 = 00010010. Số nhân có hai bit 1 nên cộng 0110 và 01100 (dịch trái 1 bit).'),
('q15',15,'Phép chia','Vận dụng','Phép chia nhị phân 1101 ÷ 0100 (13 ÷ 4) cho thương và số dư là?','{"A": "Thương 0100, dư 0001", "B": "Thương 0011, dư 0001", "C": "Thương 0011, dư 0010", "D": "Thương 0010, dư 0101"}'::jsonb,'B','13 = 3 × 4 + 1 nên thương = 3 (0011), số dư = 1 (0001).')
on conflict (id) do update set position=excluded.position, topic=excluded.topic, level=excluded.level, question_text=excluded.question_text, options=excluded.options, correct_answer=excluded.correct_answer, explanation=excluded.explanation, updated_at=now();

-- ---------- CẤP QUYỀN GIÁO VIÊN (chạy SAU KHI tạo user trong Authentication > Users) ----------
-- Bỏ dấu -- ở 2 dòng dưới và thay email của bạn:
-- insert into public.teachers(user_id,email) select id,email from auth.users where email='email-giao-vien@example.com'
-- on conflict (user_id) do nothing;

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { DEPARTMENTS, ROLES, users } = require("./data");

const SECRET = process.env.JWT_SECRET || "vienify-dev-secret";
const app = express();
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(express.json({ limit: "10mb" })); 

app.use((req, res, next) => {
  res.on("finish", () => {
    if (req.method === "GET" || res.statusCode >= 400) return;
    try { autoNote(req); } catch (e) { console.error("Ghi thông báo lỗi:", e.message); }
    db.save({ users, biz, mkt, itd, hrd, notes });
  });
  next();
});

const publicUser = ({ password, ...u }) => u;

const userDepts = (u) => (Array.isArray(u.departments) && u.departments.length ? u.departments : [u.department]);
const canAccess = (ju, dept) => ju.role === "admin" || (ju.departments || [ju.department]).includes(dept);

const deptLeader = (dept) =>
  users.find((u) => u.department === dept && (u.role === "manager" || u.role === "admin"))?.name || "—";

function auth(req, res, next) {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, SECRET);
    const u = users.find((x) => x.id === req.user.id);
    if (!u || u.status === "Đã nghỉ")
      return res.status(401).json({ message: "Tài khoản đã ngừng hoạt động" });
    next();
  } catch {
    res.status(401).json({ message: "Chưa đăng nhập hoặc token hết hạn" });
  }
}

function requireDept(req, res, next) {
  const dept = req.params.dept;
  if (!DEPARTMENTS[dept]) return res.status(404).json({ message: "Phòng ban không tồn tại" });
  if (!canAccess(req.user, dept))
    return res.status(403).json({ message: "Bạn không có quyền truy cập phòng ban này" });
  next();
}

const requireRole = (...roles) => (req, res, next) =>
  roles.includes(req.user.role) ? next() : res.status(403).json({ message: "Không đủ quyền" });

app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find((u) => u.email === email);
  if (!user || !bcrypt.compareSync(password || "", user.password))
    return res.status(401).json({ message: "Email hoặc mật khẩu không đúng" });
  if (user.status === "Đã nghỉ")
    return res.status(403).json({ message: "Tài khoản đã ngừng hoạt động (nhân viên đã nghỉ việc)" });
  const token = jwt.sign(
    { id: user.id, role: user.role, department: user.department, departments: userDepts(user), name: user.name },
    SECRET,
    { expiresIn: "8h" }
  );
  req.user = { id: user.id, role: user.role, department: user.department, departments: userDepts(user), name: user.name }; // để middleware ghi thông báo đăng nhập
  res.json({ token, user: publicUser(user) });
});

app.post("/api/auth/logout", auth, (req, res) => res.json({ ok: true }));

const RES_WORDS = [
  ["đăng nhập", "auth"], ["đăng xuất", "auth"], ["hồ sơ cá nhân", "auth"], ["mật khẩu", "auth"],
  ["khách hàng", "customers"], ["hợp đồng", "deals"], ["hoá đơn", "invoices"], ["KPI", "kpi"], ["chỉ tiêu", "kpi"],
  ["lịch họp", "meetings"], ["tài liệu", "documents"], ["chiến dịch", "campaigns"], ["lịch nội dung", "contents"],
  ["ticket", "tickets"], ["dự án", "projects"], ["hệ thống", "systems"],
  ["vị trí tuyển dụng", "jobs"], ["ứng viên", "candidates"], ["đơn", "leaves"], ["nghỉ", "leaves"],
  ["hồ sơ nhân viên", "employees"], ["tài khoản", "users"],
];
const inferRes = (msg) => RES_WORDS.find(([w]) => msg.includes(w))?.[1];
app.get("/api/notifications", auth, (req, res) => {
  const me = req.user;
  const myD = me.departments || [me.department];
  const list = me.role === "admin" ? notes
    : me.role === "manager" ? notes.filter((n) =>
        myD.includes(n.dept) || myD.includes(n.actorDept) || n.actorId === me.id || n.targetUserId === me.id)
    : notes.filter((n) => n.actorId === me.id || n.targetUserId === me.id);
  res.json(list.slice(-200).reverse().map((n) => ({
    ...n, res: n.res || inferRes(n.message), deptName: DEPARTMENTS[n.dept] || n.dept,
  })));
});

app.get("/api/auth/me", auth, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  res.json({
    ...publicUser(user),
    departments: userDepts(user),
    departmentName: userDepts(user).map((d) => DEPARTMENTS[d]).join(", "),
    leader: deptLeader(user.department),
    access: user.role === "admin" ? "Toàn bộ phòng ban" : userDepts(user).map((d) => DEPARTMENTS[d]).join(", "),
  });
});

const EDITABLE = ["phone", "address"];
app.put("/api/auth/me", auth, (req, res) => {
  const user = users.find((u) => u.id === req.user.id);
  EDITABLE.forEach((k) => {
    if (typeof req.body?.[k] === "string" && req.body[k].trim()) user[k] = req.body[k].trim();
  });
  const av = req.body?.avatar;
  if (typeof av === "string" && /^data:image\/(png|jpe?g|webp|gif);base64,/.test(av)) {
    if (av.length > 500_000) return res.status(400).json({ message: "Ảnh quá lớn (tối đa ~350KB sau nén)" });
    user.avatar = av;
  }
  res.json(publicUser(user));
});

app.put("/api/auth/password", auth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  const user = users.find((u) => u.id === req.user.id);
  if (!bcrypt.compareSync(currentPassword || "", user.password))
    return res.status(400).json({ message: "Mật khẩu hiện tại không đúng" });
  if (!newPassword || newPassword.length < 6)
    return res.status(400).json({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
  user.password = bcrypt.hashSync(newPassword, 10);
  res.json({ message: "Đổi mật khẩu thành công" });
});

app.get("/api/departments", auth, requireRole("admin"), (req, res) => {
  res.json(Object.entries(DEPARTMENTS).map(([slug, name]) => ({ slug, name })));
});

app.get("/api/departments/:dept", auth, requireDept, (req, res) => {
  const dept = req.params.dept;
  res.json({
    slug: dept,
    name: DEPARTMENTS[dept],
    members: users.filter((u) => userDepts(u).includes(dept)).map(publicUser),
  });
});

const { biz, mkt, itd, hrd } = require("./data");
const db = require("./db");

const notes = []; 
let noteSeq = 1;
function pushNote(n) {
  notes.push({ id: noteSeq++, at: now(), ...n });
  while (notes.length > 500) db.del("notifications", notes.shift().id); 
}
const NOTE_RES = {
  customers: "khách hàng", deals: "hợp đồng", invoices: "hoá đơn", kpi: "KPI", meetings: "lịch họp",
  documents: "tài liệu", campaigns: "chiến dịch", contents: "lịch nội dung", tickets: "ticket hỗ trợ",
  projects: "dự án", systems: "hệ thống", jobs: "vị trí tuyển dụng", candidates: "ứng viên",
  leaves: "đơn nghỉ phép", employees: "hồ sơ nhân viên", users: "tài khoản nhân viên", state: "chỉ tiêu/KPI",
};
const NOTE_VERB = { POST: "tạo", PUT: "cập nhật", PATCH: "cập nhật", DELETE: "xoá" };
function autoNote(req) {
  const u = req.user;
  if (!u) return;
  const seg = req.path.split("/").filter(Boolean); 
  if (seg[0] !== "api") return;
  let dept = u.department;
  let res = seg[2]; 
  let msg;
  if (seg[1] === "auth") {
    const what = { login: "đăng nhập", logout: "đăng xuất", me: "cập nhật hồ sơ cá nhân", password: "đổi mật khẩu" }[seg[2]];
    if (!what) return;
    res = "auth";
    msg = `${u.name} đã ${what}`;
  } else if (seg[1] === "admin") {
    dept = "tong-cuc";
    msg = `${u.name} đã ${NOTE_VERB[req.method] || "thao tác"} ${NOTE_RES[seg[2]] || seg[2]}`;
  } else if (DEPARTMENTS[seg[1]]) {
    dept = seg[1];
    msg = `${u.name} đã ${NOTE_VERB[req.method] || "thao tác"} ${NOTE_RES[seg[2]] || seg[2]}`;
  } else return;
  pushNote({ dept, res, actorId: u.id, actorName: u.name, actorDept: u.department, message: msg, ...(req.note || {}) });
}

const isLeader = (u) => u.role === "admin" || u.role === "manager";
const uname = (id) => users.find((u) => u.id === id)?.name || "—";
const now = () => new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16).replace("T", " ");
const setStatus = (c, status, method, reason) => {
  c.status = status;
  c.method = method;
  c.statusAt = now();
  c.cancelReason = status === "Đã huỷ" ? reason : undefined;
  (c.history = c.history || []).push({ status, ...(method && { method }), ...(reason && { reason }), at: c.statusAt });
};

function mountDept(dept, biz) {
  const P = `/api/${dept}`;
  const bizGuard = (req, res, next) =>
    canAccess(req.user, dept)
      ? next()
      : res.status(403).json({ message: "Bạn không có quyền truy cập phòng ban này" });
  const cname = (id) => biz.customers.find((c) => c.id === id)?.name || "—";
  const nextId = () => ++biz.state.seq;

app.get(`${P}/data`, auth, bizGuard, (req, res) => {
  const lead = isLeader(req.user);
  res.json({
    services: biz.SERVICES,
    deptTarget: biz.state.deptTarget,
    monthTargets: biz.state.monthTargets || {},
    customers: biz.customers
      .filter((c) => lead || c.ownerId === req.user.id || c.ownerId == null)
      .map((c) => ({ ...c, ownerName: c.ownerId ? uname(c.ownerId) : null })),
    deals: biz.deals
      .filter((d) => lead || d.employeeId === req.user.id)
      .map((d) => ({
        ...d, employeeName: uname(d.employeeId), customerName: cname(d.customerId),
        contracts: (d.contracts || []).map((f) => ({ id: f.id, name: f.name, size: f.size, at: f.at })), 
      })),
    invoices: biz.invoices
      .filter((i) => lead || i.employeeId === req.user.id)
      .map((i) => ({ ...i, employeeName: uname(i.employeeId), customerName: cname(i.customerId) })),
    kpi: biz.kpi.map((k) => ({ ...k, name: uname(k.userId) })),
    sales: biz.invoices.map((i) => ({ employeeId: i.employeeId, total: i.total, date: i.date })),
    meetings: biz.meetings.map((m) => ({ ...m, createdByName: uname(m.createdBy), participantNames: (m.participantIds || []).map(uname) })),
    revenue: biz.state.revenue || [],
    documents: biz.documents.map(({ data, mime, ...m }) => ({ ...m, hasFile: !!data, byName: m.by ? uname(m.by) : null })),
    ...(biz.campaigns && {
      channels: biz.CHANNELS,
      campaigns: biz.campaigns.map((c) => ({ ...c, ownerName: uname(c.ownerId) })),
      contents: biz.contents.map((c) => ({ ...c, ownerName: uname(c.ownerId), campaignName: biz.campaigns.find((x) => x.id === c.campaignId)?.name || null })),
    }),
    ...(biz.tickets && {
      tickets: biz.tickets.map((t) => ({ ...t, createdByName: uname(t.createdBy), assigneeName: t.assigneeId ? uname(t.assigneeId) : null })),
      projects: biz.projects.map((p) => ({ ...p, assigneeName: p.assigneeId ? uname(p.assigneeId) : null })),
      systems: biz.systems.map((s) => ({ ...s, ownerName: s.ownerId ? uname(s.ownerId) : null })),
    }),
    ...(biz.jobs && {
      employees: users.map(publicUser),
      jobs: biz.jobs,
      candidates: biz.candidates.map((c) => ({ ...c, jobTitle: biz.jobs.find((j) => j.id === c.jobId)?.title || null })),
      leaves: biz.leaves.map((l) => ({ ...l, createdByName: uname(l.createdBy), decidedByName: l.decidedBy ? uname(l.decidedBy) : null })),
    }),
  });
});

app.post(`${P}/customers`, auth, bizGuard, (req, res) => {
  const { name, company, contacts, note, ownerId } = req.body || {};
  if (!name) return res.status(400).json({ message: "Thiếu tên khách hàng" });
  const c = {
    id: nextId(), name, company: company || "", contacts: contacts || {}, note: note || "",
    ownerId: isLeader(req.user) ? ownerId ?? null : req.user.id,
  };
  setStatus(c, "Chưa liên hệ");
  biz.customers.push(c);
  res.json(c);
});

app.put(`${P}/customers/:id/assign`, auth, bizGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được chỉ định" });
  const c = biz.customers.find((x) => x.id == req.params.id);
  if (!c) return res.status(404).json({ message: "Không tìm thấy khách hàng" });
  c.ownerId = req.body.ownerId ?? null;
  res.json(c);
});

app.put(`${P}/customers/:id/status`, auth, bizGuard, (req, res) => {
  const c = biz.customers.find((x) => x.id == req.params.id);
  if (!c) return res.status(404).json({ message: "Không tìm thấy khách hàng" });
  if (!isLeader(req.user) && c.ownerId !== req.user.id)
    return res.status(403).json({ message: "Bạn không phụ trách khách hàng này" });
  const { status, method, reason } = req.body || {};
  if (!["Chưa liên hệ", "Đã liên hệ", "Đang deal", "Chốt thành công", "Đã huỷ"].includes(status))
    return res.status(400).json({ message: "Trạng thái không hợp lệ" });
  if (status === "Đã huỷ" && !String(reason || "").trim())
    return res.status(400).json({ message: "Cần ghi lý do huỷ" });
  setStatus(c, status, status === "Đã liên hệ" ? method || "Khác" : undefined, String(reason || "").trim() || undefined);
  res.json(c);
});

const validItems = (items) => (items || [])
  .map((i) => {
    const s = biz.SERVICES.find((sv) => sv.code === i.code);
    return s && Number(i.price) > 0 ? { code: s.code, name: s.name, price: Number(i.price) } : null;
  })
  .filter(Boolean);

app.post(`${P}/deals`, auth, bizGuard, (req, res) => {
  const c = biz.customers.find((x) => x.id == req.body?.customerId);
  if (!c) return res.status(404).json({ message: "Không tìm thấy khách hàng" });
  if (c.ownerId !== req.user.id) return res.status(403).json({ message: "Bạn không phụ trách khách hàng này" });
  if (c.status !== "Chốt thành công")
    return res.status(400).json({ message: "Khách hàng phải ở cột Chốt thành công mới nộp đơn được" });
  const items = validItems(req.body.items);
  if (!items.length) return res.status(400).json({ message: "Cần ít nhất 1 dịch vụ với giá hợp lệ" });
  setStatus(c, "Chờ duyệt");
  const d = {
    id: nextId(), customerId: c.id, employeeId: req.user.id, note: req.body.note || "",
    items, total: items.reduce((s, i) => s + i.price, 0), status: "Chờ duyệt", at: now(), statusAt: now(),
  };
  biz.deals.push(d);
  res.json(d);
});

app.put(`${P}/deals/:id`, auth, bizGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được duyệt đơn" });
  const d = biz.deals.find((x) => x.id == req.params.id);
  if (!d || d.status !== "Chờ duyệt") return res.status(404).json({ message: "Đơn không hợp lệ" });
  const c = biz.customers.find((x) => x.id === d.customerId);
  d.statusAt = now();
  if (req.body.action === "approve") { d.status = "Đã duyệt"; if (c) setStatus(c, "Đã duyệt"); }
  else { d.status = "Từ chối"; if (c) setStatus(c, "Đang deal"); }
  res.json(d);
});

app.post(`${P}/deals/:id/contract`, auth, bizGuard, (req, res) => {
  const d = biz.deals.find((x) => x.id == req.params.id);
  if (!d) return res.status(404).json({ message: "Không tìm thấy đơn" });
  if (!["Đã duyệt", "Hoàn thành"].includes(d.status))
    return res.status(400).json({ message: "Đơn phải được leader duyệt mới upload hợp đồng được" });
  if (d.employeeId !== req.user.id && !isLeader(req.user))
    return res.status(403).json({ message: "Không phải đơn của bạn" });
  const { name, mime, data } = req.body || {};
  if (!name || !data) return res.status(400).json({ message: "Thiếu file" });
  const f = { id: nextId(), name, mime: mime || "application/octet-stream", data, size: Buffer.from(data, "base64").length, at: now(), by: req.user.id };
  (d.contracts = d.contracts || []).push(f);
  res.json({ id: f.id, name: f.name, size: f.size, at: f.at });
});

app.get(`${P}/deals/:id/contract/:cid`, auth, bizGuard, (req, res) => {
  const d = biz.deals.find((x) => x.id == req.params.id);
  const f = d?.contracts?.find((x) => x.id == req.params.cid);
  if (!f) return res.status(404).json({ message: "Chưa có hợp đồng" });
  if (d.employeeId !== req.user.id && !isLeader(req.user))
    return res.status(403).json({ message: "Không có quyền xem" });
  res.set("Content-Type", f.mime);
  res.set("Content-Disposition", `${req.query.download ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(f.name)}`);
  res.send(Buffer.from(f.data, "base64"));
});

app.post(`${P}/documents`, auth, bizGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được đăng tài liệu" });
  const { name, mime, data } = req.body || {};
  if (!name || !data) return res.status(400).json({ message: "Thiếu file" });
  const bytes = Buffer.from(data, "base64").length;
  const t = new Date(), p = (n) => String(n).padStart(2, "0");
  const doc = {
    id: nextId(), name, mime: mime || "application/octet-stream", data,
    type: (name.includes(".") ? name.split(".").pop() : "file").toUpperCase(),
    size: bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`,
    updated: `${t.getFullYear()}-${p(t.getMonth() + 1)}-${p(t.getDate())}`, by: req.user.id,
  };
  biz.documents.push(doc);
  res.status(201).json({ id: doc.id, name: doc.name, size: doc.size });
});

app.get(`${P}/documents/:id`, auth, bizGuard, (req, res) => {
  const f = biz.documents.find((x) => x.id == req.params.id);
  if (!f || !f.data) return res.status(404).json({ message: "Tài liệu chưa có file đính kèm" });
  res.set("Content-Type", f.mime || "application/octet-stream");
  res.set("Content-Disposition", `${req.query.download ? "attachment" : "inline"}; filename*=UTF-8''${encodeURIComponent(f.name)}`);
  res.send(Buffer.from(f.data, "base64"));
});

app.put(`${P}/documents/:id`, auth, bizGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được sửa tài liệu" });
  const f = biz.documents.find((x) => x.id == req.params.id);
  if (!f) return res.status(404).json({ message: "Không tìm thấy tài liệu" });
  const name = (req.body?.name || "").trim();
  if (!name) return res.status(400).json({ message: "Tên tài liệu không được trống" });
  f.name = name;
  f.type = (name.includes(".") ? name.split(".").pop() : "file").toUpperCase();
  res.json({ id: f.id, name: f.name });
});

app.delete(`${P}/documents/:id`, auth, bizGuard, async (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được xoá tài liệu" });
  const i = biz.documents.findIndex((x) => x.id == req.params.id);
  if (i < 0) return res.status(404).json({ message: "Không tìm thấy tài liệu" });
  const [gone] = biz.documents.splice(i, 1);
  await db.del(`${dept === "business" ? "" : dept === "marketing" ? "mkt_" : dept + "_"}documents`, gone.id);
  res.json({ ok: true });
});

app.post(`${P}/invoices`, auth, bizGuard, (req, res) => {
  const { dealId } = req.body || {};
  const d = biz.deals.find((x) => x.id == dealId);
  if (!d || d.status !== "Đã duyệt") return res.status(400).json({ message: "Đơn chưa được duyệt" });
  if (d.employeeId !== req.user.id) return res.status(403).json({ message: "Không phải đơn của bạn" });
  const valid = d.items || [];
  if (!valid.length) return res.status(400).json({ message: "Đơn không có dịch vụ" });
  const total = valid.reduce((s, i) => s + i.price, 0);
  const t = new Date(), p = (n) => String(n).padStart(2, "0");
  const stamp = `${t.getFullYear()}${p(t.getMonth() + 1)}${p(t.getDate())}${p(t.getHours())}${p(t.getMinutes())}${p(t.getSeconds())}`;
  const inv = {
    id: nextId(), code: `INV-${stamp}-${String(biz.invoices.length + 1).padStart(3, "0")}`,
    dealId: d.id, customerId: d.customerId, employeeId: d.employeeId, items: valid, total,
    date: `${t.getFullYear()}-${p(t.getMonth() + 1)}-${p(t.getDate())} ${p(t.getHours())}:${p(t.getMinutes())}:${p(t.getSeconds())}`,
  };
  biz.invoices.push(inv);
  d.status = "Hoàn thành";
  d.statusAt = now();
  const c = biz.customers.find((x) => x.id === d.customerId);
  if (c) setStatus(c, "Đã chốt");
  let k = biz.kpi.find((x) => x.userId === d.employeeId);
  if (!k) { k = { userId: d.employeeId, target: 0, achieved: 0 }; biz.kpi.push(k); }
  k.achieved += total; 
  res.json(inv);
});

app.put(`${P}/kpi`, auth, bizGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được set KPI" });
  const { deptTarget, targets, month } = req.body || {};
  if (month) {
    if (!/^\d{4}-\d{2}$/.test(month)) return res.status(400).json({ message: "Tháng không hợp lệ (YYYY-MM)" });
    if (!biz.state.monthTargets) biz.state.monthTargets = {};
    const cur = biz.state.monthTargets[month] || (biz.state.monthTargets[month] = { dept: 0, users: {} });
    if (Number(deptTarget) >= 0) cur.dept = Number(deptTarget);
    (targets || []).forEach((t) => { if (Number(t.target) >= 0) cur.users[t.userId] = Number(t.target); });
    return res.json({ month, ...cur });
  }
  if (Number(deptTarget) > 0) biz.state.deptTarget = Number(deptTarget);
  (targets || []).forEach((t) => {
    let k = biz.kpi.find((x) => x.userId === t.userId);
    if (!k) { k = { userId: t.userId, target: 0, achieved: 0 }; biz.kpi.push(k); }
    if (Number(t.target) >= 0) k.target = Number(t.target);
  });
  res.json({ deptTarget: biz.state.deptTarget });
});

app.post(`${P}/meetings`, auth, bizGuard, (req, res) => {
  const { title, time, room, note, participantIds, depts } = req.body || {};
  if (!title || !time) return res.status(400).json({ message: "Thiếu tiêu đề hoặc thời gian họp" });
  const m = {
    id: nextId(), title, time, room: room || "", note: note || "",
    status: isLeader(req.user) ? "Đã duyệt" : "Chờ duyệt", createdBy: req.user.id,
    participantIds: Array.isArray(participantIds) ? participantIds.map(Number) : [],
    depts: Array.isArray(depts) ? depts : [],
  };
  biz.meetings.push(m);
  req.note = { message: `${req.user.name} đã tạo lịch họp "${m.title}" lúc ${m.time}${m.status === "Chờ duyệt" ? " (chờ duyệt)" : ""}` };
  res.status(201).json(m);
});

app.put(`${P}/meetings/:id`, auth, bizGuard, (req, res) => {
  const m = biz.meetings.find((x) => x.id === +req.params.id);
  if (!m) return res.status(404).json({ message: "Không tìm thấy lịch họp" });
  const lead = isLeader(req.user);
  const { action, title, time, room, note, participantIds, depts } = req.body || {};
  if (action) {
    if (!lead) return res.status(403).json({ message: "Chỉ leader được duyệt lịch họp" });
    if (action === "approve") m.status = "Đã duyệt";
    else if (action === "reject") m.status = "Từ chối";
    else return res.status(400).json({ message: "Hành động không hợp lệ" });
    req.note = { message: `${req.user.name} đã ${action === "approve" ? "duyệt" : "từ chối"} lịch họp "${m.title}" của ${uname(m.createdBy)}`, targetUserId: m.createdBy };
    return res.json({ id: m.id, status: m.status });
  }
  if (!lead && !(m.createdBy === req.user.id && m.status === "Chờ duyệt"))
    return res.status(403).json({ message: "Bạn không có quyền sửa lịch họp này" });
  if (title) m.title = title;
  if (time) m.time = time;
  if (room !== undefined) m.room = room;
  if (note !== undefined) m.note = note;
  if (Array.isArray(participantIds)) m.participantIds = participantIds.map(Number);
  if (Array.isArray(depts)) m.depts = depts;
  res.json({ id: m.id });
});
} 

mountDept("business", biz);
mountDept("marketing", mkt);
mountDept("it", itd);
mountDept("hr", hrd);

const mkGuard = (req, res, next) =>
  canAccess(req.user, "marketing")
    ? next()
    : res.status(403).json({ message: "Bạn không có quyền truy cập phòng ban này" });
const mkNext = () => ++mkt.state.seq;

app.post("/api/marketing/campaigns", auth, mkGuard, (req, res) => {
  const { name, goal, channels, budget, start, end, note, ownerId } = req.body || {};
  if (!name) return res.status(400).json({ message: "Thiếu tên chiến dịch" });
  const c = {
    id: mkNext(), name, goal: goal || "", channels: Array.isArray(channels) ? channels : [],
    budget: Number(budget) || 0, spent: 0, leads: 0, reach: 0,
    ownerId: isLeader(req.user) && ownerId ? Number(ownerId) : req.user.id,
    status: "Ý tưởng", start: start || "", end: end || "", note: note || "", at: now(),
  };
  mkt.campaigns.push(c);
  res.status(201).json(c);
});

const CAMP_ST = ["Ý tưởng", "Chờ duyệt", "Đang chạy", "Kết thúc", "Từ chối"];
app.put("/api/marketing/campaigns/:id", auth, mkGuard, (req, res) => {
  const c = mkt.campaigns.find((x) => x.id === +req.params.id);
  if (!c) return res.status(404).json({ message: "Không tìm thấy chiến dịch" });
  const lead = isLeader(req.user);
  if (!lead && c.ownerId !== req.user.id) return res.status(403).json({ message: "Không phải chiến dịch của bạn" });
  const { status, ...rest } = req.body || {};
  if (status) {
    if (!CAMP_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    const nvOk = (c.status === "Ý tưởng" && status === "Chờ duyệt") ||
      (["Chờ duyệt", "Từ chối"].includes(c.status) && status === "Ý tưởng");
    if (!lead && !nvOk) return res.status(403).json({ message: "Chỉ leader được duyệt / chạy / kết thúc chiến dịch" });
    c.status = status;
  }
  ["name", "goal", "note", "start", "end"].forEach((k) => { if (typeof rest[k] === "string") c[k] = rest[k]; });
  if (Array.isArray(rest.channels)) c.channels = rest.channels;
  ["budget", "spent", "leads", "reach"].forEach((k) => { if (rest[k] !== undefined && Number(rest[k]) >= 0) c[k] = Number(rest[k]); });
  if (lead && rest.ownerId) c.ownerId = Number(rest.ownerId);
  res.json(c);
});

const IMG_RE = /^(https?:\/\/\S+|data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+)$/;
const validImg = (v) => typeof v === "string" && (v === "" || (v.length <= 2_000_000 && IMG_RE.test(v)));
app.post("/api/marketing/contents", auth, mkGuard, (req, res) => {
  const { title, channel, date, campaignId, note, ownerId, body, image } = req.body || {};
  if (!title || !date) return res.status(400).json({ message: "Thiếu tiêu đề hoặc ngày đăng" });
  if (image && !validImg(image)) return res.status(400).json({ message: "Ảnh không hợp lệ (link http(s) hoặc file ảnh, tối đa ~1.5MB)" });
  const c = {
    id: mkNext(), title, channel: channel || "Facebook", date, campaignId: Number(campaignId) || null,
    note: note || "", body: typeof body === "string" ? body : "", image: image || "",
    ownerId: isLeader(req.user) && ownerId ? Number(ownerId) : req.user.id, status: "Viết",
  };
  mkt.contents.push(c);
  res.status(201).json(c);
});

const CONT_ST = ["Viết", "Chờ duyệt", "Đã duyệt", "Đã đăng"];
app.put("/api/marketing/contents/:id", auth, mkGuard, (req, res) => {
  const c = mkt.contents.find((x) => x.id === +req.params.id);
  if (!c) return res.status(404).json({ message: "Không tìm thấy bài" });
  const lead = isLeader(req.user);
  if (!lead && c.ownerId !== req.user.id) return res.status(403).json({ message: "Không phải bài của bạn" });
  const { status, ...rest } = req.body || {};
  if (status) {
    if (!CONT_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    const nvOk = (c.status === "Viết" && status === "Chờ duyệt") || (c.status === "Đã duyệt" && status === "Đã đăng");
    if (!lead && !nvOk) return res.status(403).json({ message: "Chỉ leader được duyệt bài" });
    c.status = status;
  }
  ["title", "channel", "date", "note", "body"].forEach((k) => { if (typeof rest[k] === "string") c[k] = rest[k]; });
  if (rest.image !== undefined) {
    if (!validImg(rest.image)) return res.status(400).json({ message: "Ảnh không hợp lệ (link http(s) hoặc file ảnh, tối đa ~1.5MB)" });
    c.image = rest.image;
  }
  if (rest.campaignId !== undefined) c.campaignId = Number(rest.campaignId) || null;
  res.json(c);
});

const itGuard = (req, res, next) =>
  canAccess(req.user, "it")
    ? next()
    : res.status(403).json({ message: "Bạn không có quyền truy cập phòng ban này" });
const itNext = () => ++itd.state.seq;
const PRIORITIES = ["Thấp", "Trung bình", "Cao", "Khẩn cấp"];
const TICKET_ST = ["Mới", "Đang xử lý", "Hoàn thành"];
const PROJ_ST = ["Backlog", "Đang làm", "Review", "Xong"];
const SYS_ST = ["Hoạt động", "Sự cố", "Bảo trì"];

app.post("/api/it/tickets", auth, (req, res) => {
  const { title, desc, priority } = req.body || {};
  if (!title) return res.status(400).json({ message: "Thiếu tiêu đề yêu cầu" });
  const t = {
    id: itNext(), title, desc: desc || "", priority: PRIORITIES.includes(priority) ? priority : "Trung bình",
    dept: req.user.department, createdBy: req.user.id, status: "Mới", assigneeId: null, note: "", at: now(),
  };
  itd.tickets.push(t);
  req.note = { message: `${req.user.name} (${DEPARTMENTS[req.user.department]}) đã gửi ticket "${t.title}" (${t.priority})` };
  res.status(201).json(t);
});

app.get("/api/it/tickets/mine", auth, (req, res) => {
  res.json(itd.tickets.filter((t) => t.createdBy === req.user.id)
    .map((t) => ({ ...t, assigneeName: t.assigneeId ? uname(t.assigneeId) : null })));
});

app.put("/api/it/tickets/:id", auth, itGuard, (req, res) => {
  const t = itd.tickets.find((x) => x.id === +req.params.id);
  if (!t) return res.status(404).json({ message: "Không tìm thấy ticket" });
  const { status, assigneeId, note, priority } = req.body || {};
  if (status) {
    if (!TICKET_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    t.status = status;
    if (status !== "Mới" && !t.assigneeId) t.assigneeId = req.user.id;
    if (status === "Hoàn thành") t.doneAt = now();
  }
  if (assigneeId !== undefined) t.assigneeId = Number(assigneeId) || null;
  if (typeof note === "string") t.note = note;
  if (PRIORITIES.includes(priority)) t.priority = priority;
  req.note = { message: `${req.user.name} đã cập nhật ticket "${t.title}" (${t.status}) của ${uname(t.createdBy)}`, targetUserId: t.createdBy };
  res.json(t);
});

app.post("/api/it/projects", auth, itGuard, (req, res) => {
  const { name, desc, assigneeId, deadline } = req.body || {};
  if (!name) return res.status(400).json({ message: "Thiếu tên dự án" });
  const p = { id: itNext(), name, desc: desc || "", assigneeId: Number(assigneeId) || req.user.id, deadline: deadline || "", status: "Backlog", at: now() };
  itd.projects.push(p);
  res.status(201).json(p);
});
app.put("/api/it/projects/:id", auth, itGuard, (req, res) => {
  const p = itd.projects.find((x) => x.id === +req.params.id);
  if (!p) return res.status(404).json({ message: "Không tìm thấy dự án" });
  const { status, ...rest } = req.body || {};
  if (status) {
    if (!PROJ_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    p.status = status;
  }
  ["name", "desc", "deadline"].forEach((k) => { if (typeof rest[k] === "string") p[k] = rest[k]; });
  if (rest.assigneeId !== undefined) p.assigneeId = Number(rest.assigneeId) || null;
  res.json(p);
});

app.post("/api/it/systems", auth, itGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader được thêm hệ thống" });
  const { name, type, url, ownerId, note } = req.body || {};
  if (!name) return res.status(400).json({ message: "Thiếu tên hệ thống" });
  const s = { id: itNext(), name, type: type || "Service", url: url || "", status: "Hoạt động", ownerId: Number(ownerId) || req.user.id, note: note || "" };
  itd.systems.push(s);
  res.status(201).json(s);
});
app.put("/api/it/systems/:id", auth, itGuard, (req, res) => {
  const s = itd.systems.find((x) => x.id === +req.params.id);
  if (!s) return res.status(404).json({ message: "Không tìm thấy hệ thống" });
  const { status, ...rest } = req.body || {};
  if (status) {
    if (!SYS_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    s.status = status;
  }
  ["name", "type", "url", "note"].forEach((k) => { if (typeof rest[k] === "string") s[k] = rest[k]; });
  if (rest.ownerId !== undefined && isLeader(req.user)) s.ownerId = Number(rest.ownerId) || null;
  res.json(s);
});

// ===== Riêng phòng HR: nghỉ phép + tuyển dụng + hồ sơ nhân sự =====
const hrGuard = (req, res, next) =>
  canAccess(req.user, "hr")
    ? next()
    : res.status(403).json({ message: "Bạn không có quyền truy cập phòng ban này" });
const hrNext = () => ++hrd.state.seq;
const LEAVE_TYPES = ["Nghỉ phép", "Nghỉ ốm", "Việc riêng", "Remote"];
const LEAVE_ST = ["Chờ duyệt", "Đã duyệt", "Từ chối"];
const JOB_ST = ["Đang tuyển", "Tạm dừng", "Đã đủ"];
const CAND_ST = ["Mới", "Phỏng vấn", "Offer", "Nhận việc", "Loại"];
const EMP_ST = ["Đang làm việc", "Thử việc", "Đã nghỉ"];

// Gửi đơn nghỉ phép — NHÂN VIÊN MỌI PHÒNG đều gửi được
app.post("/api/hr/leaves", auth, (req, res) => {
  const { type, from, to, reason } = req.body || {};
  if (!from || !to || from > to) return res.status(400).json({ message: "Chọn ngày nghỉ hợp lệ (từ ngày ≤ đến ngày)" });
  if (!String(reason || "").trim()) return res.status(400).json({ message: "Cần ghi lý do nghỉ" });
  const l = {
    id: hrNext(), type: LEAVE_TYPES.includes(type) ? type : "Nghỉ phép", from, to, reason: String(reason).trim(),
    dept: req.user.department, createdBy: req.user.id, status: "Chờ duyệt", note: "", at: now(),
  };
  hrd.leaves.push(l);
  req.note = { message: `${req.user.name} (${DEPARTMENTS[req.user.department]}) đã gửi đơn ${l.type} (${l.from} - ${l.to})` };
  res.status(201).json(l);
});

// Đơn của tôi — người gửi theo dõi từ trang phòng mình
app.get("/api/hr/leaves/mine", auth, (req, res) => {
  res.json(hrd.leaves.filter((l) => l.createdBy === req.user.id)
    .map((l) => ({ ...l, decidedByName: l.decidedBy ? uname(l.decidedBy) : null })));
});

// HR duyệt / từ chối đơn (kèm ghi chú cho người gửi)
app.put("/api/hr/leaves/:id", auth, hrGuard, (req, res) => {
  const l = hrd.leaves.find((x) => x.id === +req.params.id);
  if (!l) return res.status(404).json({ message: "Không tìm thấy đơn nghỉ phép" });
  const { status, note } = req.body || {};
  if (status) {
    if (!LEAVE_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    l.status = status;
    l.decidedBy = req.user.id;
    l.decidedAt = now();
  }
  if (typeof note === "string") l.note = note;
  req.note = { message: `${req.user.name} đã ${l.status === "Đã duyệt" ? "duyệt" : l.status === "Từ chối" ? "từ chối" : "cập nhật"} đơn ${l.type} của ${uname(l.createdBy)}`, targetUserId: l.createdBy };
  res.json(l);
});

// Vị trí tuyển dụng
app.post("/api/hr/jobs", auth, hrGuard, (req, res) => {
  const { title, dept, quantity, desc } = req.body || {};
  if (!title) return res.status(400).json({ message: "Thiếu tên vị trí tuyển dụng" });
  const j = { id: hrNext(), title, dept: DEPARTMENTS[dept] ? dept : "business", quantity: Number(quantity) || 1, desc: desc || "", status: "Đang tuyển", at: now() };
  hrd.jobs.push(j);
  res.status(201).json(j);
});
app.put("/api/hr/jobs/:id", auth, hrGuard, (req, res) => {
  const j = hrd.jobs.find((x) => x.id === +req.params.id);
  if (!j) return res.status(404).json({ message: "Không tìm thấy vị trí" });
  const { status, ...rest } = req.body || {};
  if (status) {
    if (!JOB_ST.includes(status)) return res.status(400).json({ message: "Trạng thái không hợp lệ" });
    j.status = status;
  }
  ["title", "desc"].forEach((k) => { if (typeof rest[k] === "string") j[k] = rest[k]; });
  if (DEPARTMENTS[rest.dept]) j.dept = rest.dept;
  if (rest.quantity !== undefined) j.quantity = Number(rest.quantity) || 1;
  res.json(j);
});

// Ứng viên (pipeline Mới - Phỏng vấn - Offer - Nhận việc / Loại)
app.post("/api/hr/candidates", auth, hrGuard, (req, res) => {
  const { name, jobId, phone, email, note } = req.body || {};
  if (!name) return res.status(400).json({ message: "Thiếu tên ứng viên" });
  const c = { id: hrNext(), name, jobId: Number(jobId) || null, phone: phone || "", email: email || "", note: note || "", stage: "Mới", at: now() };
  hrd.candidates.push(c);
  res.status(201).json(c);
});
app.put("/api/hr/candidates/:id", auth, hrGuard, (req, res) => {
  const c = hrd.candidates.find((x) => x.id === +req.params.id);
  if (!c) return res.status(404).json({ message: "Không tìm thấy ứng viên" });
  const { stage, ...rest } = req.body || {};
  if (stage) {
    if (!CAND_ST.includes(stage)) return res.status(400).json({ message: "Vòng tuyển không hợp lệ" });
    c.stage = stage;
  }
  ["name", "phone", "email", "note"].forEach((k) => { if (typeof rest[k] === "string") c[k] = rest[k]; });
  if (rest.jobId !== undefined) c.jobId = Number(rest.jobId) || null;
  res.json(c);
});

// HR leader cập nhật hồ sơ nhân sự (ghi thẳng vào users)
app.put("/api/hr/employees/:id", auth, hrGuard, (req, res) => {
  if (!isLeader(req.user)) return res.status(403).json({ message: "Chỉ leader HR được sửa hồ sơ" });
  const u = users.find((x) => x.id === +req.params.id);
  if (!u) return res.status(404).json({ message: "Không tìm thấy nhân viên" });
  ["position", "phone", "address", "joinDate"].forEach((k) => {
    if (typeof req.body?.[k] === "string" && req.body[k].trim()) u[k] = req.body[k].trim();
  });
  if (EMP_ST.includes(req.body?.status)) u.status = req.body.status;
  res.json(publicUser(u));
});

// ===== Riêng phòng Tổng Cục: admin quản trị nhân sự toàn công ty (CRUD không cần duyệt) =====
const ABBR = { "tong-cuc": "TC", business: "BS", marketing: "MK", it: "IT", hr: "HR" };
const POSITION_BY_ROLE = { admin: "Quản trị hệ thống", manager: "Trưởng phòng", employee: "Nhân viên" };
const EMAIL_RE = /^\S+@\S+\.\S+$/;
// Mã NV: VIE + DEPT_CODE + ROLE_CODE (EMP/LD) + YYYYMM (thời điểm tạo) + SEQUENCE toàn công ty (bắt đầu 1111, +1 mỗi nhân viên mới)
const ROLE_CODE = { admin: "LD", manager: "LD", employee: "EMP" };
const genCode = (dept, role) => {
  let seq = 1110;
  for (const u of users) {
    const m = /^VIE[A-Z]+?(?:EMP|LD)(\d{10,})$/.exec(u.code || "");
    if (m) seq = Math.max(seq, +m[1].slice(6));
  }
  return `VIE${ABBR[dept] || "VN"}${ROLE_CODE[role] || "EMP"}${now().slice(0, 7).replace("-", "")}${seq + 1}`;
};

app.get("/api/admin/users", auth, requireRole("admin"), (req, res) => res.json(users.map(publicUser)));

// Tạo nhân viên + cấp tài khoản đăng nhập + phân quyền
app.post("/api/admin/users", auth, requireRole("admin"), (req, res) => {
  const { name, email, password, role, department, position, dob, gender, phone, address, joinDate, status } = req.body || {};
  if (!String(name || "").trim()) return res.status(400).json({ message: "Thiếu họ tên nhân viên" });
  if (!EMAIL_RE.test(email || "")) return res.status(400).json({ message: "Email không hợp lệ" });
  if (users.some((u) => u.email === email)) return res.status(400).json({ message: "Email đã tồn tại" });
  if (!ROLES.includes(role)) return res.status(400).json({ message: "Quyền không hợp lệ" });
  if (!DEPARTMENTS[department]) return res.status(400).json({ message: "Phòng ban không hợp lệ" });
  // Kiêm nhiệm nhiều phòng ban (tối đa 3, phần tử đầu = phòng chính)
  const depts = [...new Set([department, ...(Array.isArray(req.body?.departments) ? req.body.departments : [])])].filter((d) => DEPARTMENTS[d]);
  if (depts.length > 3) return res.status(400).json({ message: "Tối đa 3 phòng ban" });
  const pass = password || "123456";
  if (pass.length < 6) return res.status(400).json({ message: "Mật khẩu tối thiểu 6 ký tự" });
  const u = {
    id: Math.max(...users.map((x) => x.id)) + 1,
    name: String(name).trim(), email, password: bcrypt.hashSync(pass, 10), role,
    department: depts[0], departments: depts,
    code: genCode(depts[0], role),
    avatar: "/Logo.png",
    dob: dob || "", gender: gender === "Nữ" ? "Nữ" : "Nam", phone: phone || "", address: address || "",
    position: String(position || "").trim() || POSITION_BY_ROLE[role],
    joinDate: joinDate || now().slice(0, 10),
    status: EMP_ST.includes(status) ? status : "Thử việc",
  };
  users.push(u);
  res.status(201).json(publicUser(u));
});

// Sửa hồ sơ / quyền / phòng ban / đặt lại mật khẩu
app.put("/api/admin/users/:id", auth, requireRole("admin"), (req, res) => {
  const u = users.find((x) => x.id === +req.params.id);
  if (!u) return res.status(404).json({ message: "Không tìm thấy nhân viên" });
  const b = req.body || {};
  if (b.role && u.id === req.user.id && b.role !== "admin")
    return res.status(400).json({ message: "Không thể tự hạ quyền admin của chính mình" });
  if (b.email && b.email !== u.email) {
    if (!EMAIL_RE.test(b.email)) return res.status(400).json({ message: "Email không hợp lệ" });
    if (users.some((x) => x.email === b.email)) return res.status(400).json({ message: "Email đã tồn tại" });
    u.email = b.email;
  }
  if (ROLES.includes(b.role)) u.role = b.role;
  // Nhận mảng departments (ưu tiên) hoặc department đơn lẻ; phần tử đầu = phòng chính
  const newDepts = Array.isArray(b.departments)
    ? [...new Set(b.departments)].filter((d) => DEPARTMENTS[d])
    : DEPARTMENTS[b.department] ? [b.department] : null;
  if (newDepts && newDepts.length >= 1 && newDepts.length <= 3) {
    u.department = newDepts[0];
    u.departments = newDepts;
  }
  // Đổi quyền / phòng ban → cập nhật lại phần DEPT_CODE + ROLE_CODE trong mã NV (giữ nguyên YYYYMM + SEQUENCE)
  {
    const m = /^VIE[A-Z]+?(?:EMP|LD)(\d{10,})$/.exec(u.code || "");
    if (m) u.code = `VIE${ABBR[u.department] || "VN"}${ROLE_CODE[u.role] || "EMP"}${m[1]}`;
  }
  ["name", "position", "dob", "phone", "address", "joinDate"].forEach((k) => {
    if (typeof b[k] === "string" && b[k].trim()) u[k] = b[k].trim();
  });
  if (b.gender === "Nam" || b.gender === "Nữ") u.gender = b.gender;
  if (EMP_ST.includes(b.status)) u.status = b.status;
  if (b.newPassword) {
    if (b.newPassword.length < 6) return res.status(400).json({ message: "Mật khẩu tối thiểu 6 ký tự" });
    u.password = bcrypt.hashSync(b.newPassword, 10);
  }
  res.json(publicUser(u));
});

// Xoá nhân viên (xoá cả dòng MySQL — REPLACE không tự xoá)
app.delete("/api/admin/users/:id", auth, requireRole("admin"), async (req, res) => {
  const i = users.findIndex((x) => x.id === +req.params.id);
  if (i < 0) return res.status(404).json({ message: "Không tìm thấy nhân viên" });
  if (users[i].id === req.user.id) return res.status(400).json({ message: "Không thể xoá chính mình" });
  const [gone] = users.splice(i, 1);
  await db.del("users", gone.id);
  res.json({ message: "Đã xoá nhân viên", id: gone.id });
});

// ===== Nhắc hẹn tự động: sinh thông báo hệ thống cho sự kiện sắp đến hạn (chạy mỗi 5 phút) =====
const sysNote = (dept, res, message, targetUserId) =>
  pushNote({ dept, res, actorId: 0, actorName: "Hệ thống", actorDept: dept, message, ...(targetUserId ? { targetUserId } : {}) });
const ts = (s) => Date.parse(`${s.length === 10 ? `${s} 00:00` : s}`.replace(" ", "T") + ":00Z"); // cùng hệ giờ với now()

function checkReminders() {
  const today = now().slice(0, 10);
  const tomorrow = new Date(ts(today) + 86400000).toISOString().slice(0, 10);
  let changed = false;
  const once = (x, fn) => { if (x.remindedOn !== today) { fn(); x.remindedOn = today; changed = true; } };

  for (const [dept, store] of [["business", biz], ["marketing", mkt], ["it", itd], ["hr", hrd]]) {
    // Lịch họp đã duyệt: nhắc trong vòng 60 phút trước giờ họp
    for (const m of store.meetings || []) {
      if (m.status !== "Đã duyệt" || !m.time) continue;
      const diff = ts(m.time) - ts(now());
      if (diff <= 60 * 60000 && diff > -30 * 60000)
        once(m, () => sysNote(dept, "meetings", `Sắp diễn ra: lịch họp "${m.title}" lúc ${m.time.slice(11)}${m.room ? ` tại ${m.room}` : ""}`, m.createdBy));
    }
  }

  // Marketing: nội dung chuẩn bị đăng (hôm nay / ngày mai) và chiến dịch bắt đầu / kết thúc
  for (const c of mkt.contents || []) {
    if (c.status === "Đã đăng" || !c.date) continue;
    if (c.date === today) once(c, () => sysNote("marketing", "contents", `Nội dung "${c.title}" (${c.channel}) chuẩn bị đăng HÔM NAY${c.status !== "Đã duyệt" ? ` - đang ở trạng thái ${c.status}` : ""}`, c.ownerId));
    else if (c.date === tomorrow) once(c, () => sysNote("marketing", "contents", `Nội dung "${c.title}" (${c.channel}) sẽ đăng ngày mai (${c.date})`, c.ownerId));
  }
  for (const cp of mkt.campaigns || []) {
    if (cp.status === "Kết thúc" || cp.status === "Từ chối") continue;
    if (cp.start === today) once(cp, () => sysNote("marketing", "campaigns", `Chiến dịch "${cp.name}" bắt đầu từ hôm nay${cp.status !== "Đang chạy" ? ` - đang ở trạng thái ${cp.status}` : ""}`, cp.ownerId));
    else if (cp.end === today) once(cp, () => sysNote("marketing", "campaigns", `Chiến dịch "${cp.name}" kết thúc hôm nay`, cp.ownerId));
  }

  // IT: dự án đến hạn hôm nay hoặc quá hạn
  for (const p of itd.projects || []) {
    if (p.status === "Xong" || !p.deadline) continue;
    if (p.deadline === today) once(p, () => sysNote("it", "projects", `Dự án "${p.name}" đến hạn HÔM NAY (${p.status})`, p.assigneeId));
    else if (p.deadline < today) once(p, () => sysNote("it", "projects", `Dự án "${p.name}" ĐÃ QUÁ HẠN từ ${p.deadline} (${p.status})`, p.assigneeId));
  }

  // HR: đơn nghỉ đã duyệt bắt đầu từ hôm nay - báo cho phòng của người nghỉ
  for (const l of hrd.leaves || []) {
    if (l.status !== "Đã duyệt" || l.from !== today) continue;
    once(l, () => sysNote(l.dept || "hr", "leaves", `${uname(l.createdBy)} bắt đầu nghỉ (${l.type}) từ hôm nay đến ${l.to}`, l.createdBy));
  }

  if (changed) db.save({ users, biz, mkt, itd, hrd, notes });
}

db.init({ users, biz, mkt, itd, hrd, notes })
  .then(() => {
    noteSeq = (notes[notes.length - 1]?.id || 0) + 1;
    // Migrate dữ liệu cũ: contract đơn lẻ - mảng contracts; gắn dealId cho hoá đơn cũ
    biz.deals.forEach((d) => {
      if (d.contract) { d.contracts = [{ id: ++biz.state.seq, ...d.contract }]; delete d.contract; }
      if (!d.statusAt) d.statusAt = d.at || "";
    });
    biz.invoices.forEach((i) => {
      if (!i.dealId) i.dealId = biz.deals.find((d) => d.customerId === i.customerId && d.employeeId === i.employeeId)?.id;
    });
    const PORT = process.env.PORT || 4000;
    app.listen(PORT, () => console.log(`Backend chạy tại http://localhost:${PORT} (MySQL)`));
    checkReminders();
    setInterval(checkReminders, 5 * 60000);
  })
  .catch((e) => { console.error("Không kết nối được MySQL:", e.message, "\nKiểm tra mật khẩu trong backend/.env"); process.exit(1); });

for (const sig of ["SIGINT", "SIGTERM"])
  process.on(sig, () => db.flush().finally(() => process.exit(0)));

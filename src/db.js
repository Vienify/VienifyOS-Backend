const fs = require("fs");
const path = require("path");
const mysql = require("mysql2/promise");

// Nạp backend/.env (không cần dep dotenv)
try {
  fs.readFileSync(path.join(__dirname, "..", ".env"), "utf8").split("\n").forEach((l) => {
    const m = l.match(/^(\w+)=(.*)$/);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2].trim();
  });
} catch {}

const CFG = {
  host: process.env.DB_HOST || "127.0.0.1",
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
};
const DB = process.env.DB_NAME || "vienifyos";

// Bảng: mỗi entity 1 bảng, cột data kiểu JSON. Business không prefix, Marketing mkt_, IT it_
const DEPT_TABLES = ["customers", "deals", "invoices", "kpi", "meetings", "documents"];
const MKT_TABLES = [...DEPT_TABLES, "campaigns", "contents"];
const IT_TABLES = [...DEPT_TABLES, "tickets", "projects", "systems"];
const HR_TABLES = [...DEPT_TABLES, "jobs", "candidates", "leaves"];
const TABLES = ["users", "app_state", "notifications", ...DEPT_TABLES, ...MKT_TABLES.map((t) => `mkt_${t}`), ...IT_TABLES.map((t) => `it_${t}`), ...HR_TABLES.map((t) => `hr_${t}`)];

let pool = null;

// Kết nối + tạo DB/bảng; seed nếu trống, ngược lại nạp dữ liệu từ MySQL vào bộ nhớ
async function init({ users, biz, mkt, itd, hrd, notes }) {
  const conn = await mysql.createConnection(CFG);
  await conn.query(`CREATE DATABASE IF NOT EXISTS \`${DB}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  await conn.end();
  pool = mysql.createPool({ ...CFG, database: DB, connectionLimit: 5 });
  for (const t of TABLES)
    await pool.query(`CREATE TABLE IF NOT EXISTS \`${t}\` (pk INT PRIMARY KEY, data JSON NOT NULL)`);

  const [[{ n }]] = await pool.query("SELECT COUNT(*) n FROM users");
  if (n === 0) {
    await save({ users, biz, mkt, itd, hrd, notes });
    console.log("MySQL trống - đã seed dữ liệu mẫu");
    return;
  }
  // Nạp từ MySQL, thay thế seed trong bộ nhớ (bảng trống - giữ seed, lưu ở lần save sau)
  const rows = async (t) => (await pool.query(`SELECT data FROM \`${t}\``))[0].map((r) => (typeof r.data === "string" ? JSON.parse(r.data) : r.data));
  users.splice(0, users.length, ...(await rows("users")));
  notes.splice(0, notes.length, ...(await rows("notifications")).sort((a, b) => a.id - b.id));
  for (const [store, prefix, tables] of [[biz, "", DEPT_TABLES], [mkt, "mkt_", MKT_TABLES], [itd, "it_", IT_TABLES], [hrd, "hr_", HR_TABLES]])
    for (const t of tables) {
      const r = await rows(prefix + t);
      if (r.length) store[t].splice(0, store[t].length, ...r);
    }
  const [st] = await pool.query("SELECT pk, data FROM app_state");
  for (const r of st) {
    const d = typeof r.data === "string" ? JSON.parse(r.data) : r.data;
    Object.assign(({ 1: biz, 2: mkt, 3: itd, 4: hrd }[r.pk] || biz).state, d);
  }
  console.log(`Đã nạp dữ liệu từ MySQL (${DB})`);
}

// Ghi toàn bộ trạng thái vào MySQL (debounce 300ms, REPLACE INTO — app không có thao tác xoá)
let timer = null;
let last = null;
async function writeNow({ users, biz, mkt, itd, hrd, notes }) {
  try {
    const rep = (t, key, arr) =>
      arr.length && pool.query(`REPLACE INTO \`${t}\` (pk, data) VALUES ${arr.map(() => "(?, ?)").join(",")}`,
        arr.flatMap((o) => [o[key], JSON.stringify(o)]));
    const deptReps = (store, prefix, tables) =>
      tables.map((t) => rep(prefix + t, t === "kpi" ? "userId" : "id", store[t]));
    await Promise.all([
      rep("users", "id", users),
      rep("notifications", "id", notes || []),
      ...deptReps(biz, "", DEPT_TABLES),
      ...deptReps(mkt, "mkt_", MKT_TABLES),
      ...deptReps(itd, "it_", IT_TABLES),
      ...deptReps(hrd, "hr_", HR_TABLES),
      pool.query("REPLACE INTO app_state (pk, data) VALUES (1, ?), (2, ?), (3, ?), (4, ?)", [JSON.stringify(biz.state), JSON.stringify(mkt.state), JSON.stringify(itd.state), JSON.stringify(hrd.state)]),
    ]);
  } catch (e) { console.error("Lưu MySQL lỗi:", e.message); }
}
function save(data) {
  last = data;
  clearTimeout(timer);
  return new Promise((resolve) => {
    timer = setTimeout(() => writeNow(data).then(resolve), 300);
  });
}
// Ghi ngay lập tức (gọi khi server tắt)
async function flush() {
  clearTimeout(timer);
  if (last) await writeNow(last);
}

// Xoá 1 dòng khỏi bảng (REPLACE không tự xoá được — dùng cho admin xoá nhân viên)
async function del(table, pk) {
  if (pool) await pool.query(`DELETE FROM \`${table}\` WHERE pk = ?`, [pk]);
}

module.exports = { init, save, flush, del };

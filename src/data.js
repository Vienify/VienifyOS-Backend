const bcrypt = require("bcryptjs");

// Danh sách phòng ban
const DEPARTMENTS = {
  "tong-cuc": "Phòng Giám Đốc",
  business: "Phòng Business",
  marketing: "Phòng Marketing",
  it: "Phòng IT & Phát triển sản phẩm",
  hr: "Phòng Nhân Sự",
};

const ROLES = ["admin", "manager", "employee"];

// Tài khoản khởi tạo — CHỈ dùng khi MySQL trống (dữ liệu thật nằm trong DB).
// Đăng nhập: vienify@vienify.com / 123456
const users = [
  {
    id: 1, name: "Admin Vienify", email: "vienify@vienify.com", password: bcrypt.hashSync("123456", 10),
    role: "admin", department: "tong-cuc", code: "VIETCLD2020011111", avatar: "/Logo.png",
    dob: "", gender: "", phone: "", address: "", position: "Quản trị hệ thống", joinDate: "2020-01-01", status: "Đang làm việc",
  },
];

// ==== Store 4 phòng — rỗng, dữ liệu thật nạp từ MySQL khi khởi động (db.js) ====
const SERVICES = [
  { code: "SW-01", name: "Phát triển phần mềm" },
  { code: "SW-02", name: "Phát triển Website/Web App" },
  { code: "SW-03", name: "Phát triển Mobile App" },
  { code: "AI-01", name: "Phát triển & tích hợp AI" },
  { code: "AI-02", name: "AI Agent" },
  { code: "SaaS-01", name: "Phí sử dụng phần mềm/SaaS" },
  { code: "UI-01", name: "Thiết kế UI/UX" },
  { code: "CON-01", name: "Tư vấn công nghệ" },
  { code: "MA-01", name: "Bảo trì & nâng cấp phần mềm" },
  { code: "SUP-01", name: "Hỗ trợ kỹ thuật" },
];

const CHANNELS = ["Facebook", "Instagram", "Threads", "TikTok", "Google Ads", "Zalo", "Email", "Website"];

// state persist qua app_state (pk 1-4): seq, mục tiêu KPI, monthTargets (+ revenue riêng business)
const emptyDept = () => ({
  customers: [], deals: [], invoices: [], kpi: [], meetings: [], documents: [],
  state: { deptTarget: 0, seq: 100, monthTargets: {} },
});

const biz = { SERVICES, ...emptyDept() };
biz.state.revenue = []; // biểu đồ doanh thu tháng [{month,target,actual}] — persist app_state pk=1
const mkt = { SERVICES, CHANNELS, ...emptyDept(), campaigns: [], contents: [] };
const itd = { ...emptyDept(), tickets: [], projects: [], systems: [] };
const hrd = { ...emptyDept(), jobs: [], candidates: [], leaves: [] };

module.exports = { DEPARTMENTS, ROLES, users, biz, mkt, itd, hrd };

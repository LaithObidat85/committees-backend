const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cookieParser());

// ✅ CORS يسمح بأي Origin
app.use(cors({
  origin: true,       // يسمح بأي دومين
  credentials: true   // يسمح بإرسال الكوكيز
}));

// الاتصال بقاعدة البيانات
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log("✅ تم الاتصال بقاعدة البيانات"))
  .catch(err => console.error("❌ خطأ في الاتصال بقاعدة البيانات:", err));

// نموذج المستخدم
const UserSchema = new mongoose.Schema({
  name: { type: String }, // اسم المستخدم (اختياري)
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const User = mongoose.model("User", UserSchema);

// تسجيل مستخدم جديد (تسجيل ذاتي)
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const newUser = new User({ email, password: hashed, name });
    await newUser.save();
    res.json({ message: "✅ تم تسجيل المستخدم بنجاح" });
  } catch (err) {
    res.status(400).json({ error: "❌ البريد الإلكتروني مستخدم بالفعل" });
  }
});

// إضافة مستخدم جديد (مثلاً من لوحة الإدارة)
app.post("/api/users", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, name });
    await user.save();
    res.status(201).json({ message: "✅ تم إضافة المستخدم بنجاح" });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: "❌ فشل إضافة المستخدم (ربما البريد الإلكتروني مستخدم)" });
  }
});

// تسجيل الدخول
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "❌ المستخدم غير موجود" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "❌ بيانات الدخول غير صحيحة" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "1h" });
  res.cookie("token", token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 60 * 60 * 1000
  });
  res.json({ message: "✅ تم تسجيل الدخول بنجاح" });
});

// التحقق من الجلسة
app.get("/api/me", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "❌ غير مصرح بالدخول" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "❌ رمز التحقق غير صالح" });
    res.json({ message: "✅ تم التحقق من الجلسة", userId: decoded.id });
  });
});

// تسجيل الخروج
app.post("/api/logout", (req, res) => {
  res.clearCookie("token");
  res.json({ message: "✅ تم تسجيل الخروج" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`));

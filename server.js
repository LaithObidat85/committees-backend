// ==========================
// 📌 1. استدعاء المكتبات الأساسية
// ==========================
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const helmet = require("helmet"); // ✅ مكتبة لزيادة الأمان
const rateLimit = require("express-rate-limit"); // ✅ مكتبة لتحديد عدد الطلبات
require("dotenv").config();

// ==========================
// 📌 2. إنشاء تطبيق Express
// ==========================
const app = express();

// ==========================
// 📌 3. Middleware عام
// ==========================
app.use(express.json()); // تحويل الطلبات القادمة إلى JSON
app.use(cookieParser()); // قراءة الكوكيز

// ✅ CORS يسمح بالوصول من أي دومين مع إرسال الكوكيز
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

// ✅ Helmet: يضيف هيدرز للحماية من هجمات شائعة (XSS, Clickjacking, ..)
app.use(helmet());

// ✅ Rate Limiting: تحديد عدد محاولات تسجيل الدخول لكل IP
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 دقيقة
  max: 5, // أقصى 5 محاولات لكل IP في الدقيقة
  message: "❌ عدد محاولات تسجيل الدخول كبير جدًا، حاول لاحقًا",
});
app.use("/api/login", loginLimiter); // نطبقها فقط على مسار تسجيل الدخول

// ==========================
// 📌 4. الاتصال بقاعدة البيانات MongoDB
// ==========================
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true, // ⚠️ Deprecated لكن ما تأثر
    useUnifiedTopology: true, // ⚠️ Deprecated لكن ما تأثر
  })
  .then(() => console.log("✅ تم الاتصال بقاعدة البيانات"))
  .catch((err) => console.error("❌ خطأ في الاتصال بقاعدة البيانات:", err));

// ==========================
// 📌 5. تعريف نموذج المستخدم (Schema + Model)
// ==========================
const UserSchema = new mongoose.Schema({
  name: { type: String }, // اسم المستخدم (اختياري)
  email: { type: String, required: true, unique: true }, // البريد الإلكتروني
  password: { type: String, required: true }, // كلمة المرور (مشفرة)
});
const User = mongoose.model("User", UserSchema);

// ==========================
// 📌 6. المسارات (Routes)
// ==========================

// (1) تسجيل مستخدم جديد (تسجيل ذاتي)
app.post("/api/register", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashed = await bcrypt.hash(password, 10); // تشفير كلمة المرور
    const newUser = new User({ email, password: hashed, name });
    await newUser.save();
    res.json({ message: "✅ تم تسجيل المستخدم بنجاح" });
  } catch (err) {
    res.status(400).json({ error: "❌ البريد الإلكتروني مستخدم بالفعل" });
  }
});

// (2) إضافة مستخدم جديد (لوحة الإدارة)
app.post("/api/users", async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashed, name });
    await user.save();
    res.status(201).json({ message: "✅ تم إضافة المستخدم بنجاح" });
  } catch (err) {
    console.error(err);
    res
      .status(400)
      .json({ error: "❌ فشل إضافة المستخدم (ربما البريد الإلكتروني مستخدم)" });
  }
});

// (3) تسجيل الدخول
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  // البحث عن المستخدم
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "❌ المستخدم غير موجود" });

  // التحقق من كلمة المرور
  const valid = await bcrypt.compare(password, user.password);
  if (!valid)
    return res.status(400).json({ error: "❌ بيانات الدخول غير صحيحة" });

  // إنشاء JWT Token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });

  // إرسال التوكن كـ Cookie آمن
  res.cookie("token", token, {
    httpOnly: true, // لا يمكن الوصول له من JavaScript
    secure: true, // يُرسل فقط عبر HTTPS
    sameSite: "none", // يعمل عبر دومينات مختلفة
    maxAge: 60 * 60 * 1000, // ساعة واحدة
  });

  res.json({ message: "✅ تم تسجيل الدخول بنجاح" });
});

// (4) التحقق من الجلسة
app.get("/api/me", (req, res) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ error: "❌ غير مصرح بالدخول" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(401).json({ error: "❌ رمز التحقق غير صالح" });
    res.json({ message: "✅ تم التحقق من الجلسة", userId: decoded.id });
  });
});

// (5) تسجيل الخروج
app.post("/api/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
  res.json({ message: "✅ تم تسجيل الخروج" });
});

// ==========================
// 📌 7. تشغيل السيرفر
// ==========================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 الخادم يعمل على المنفذ ${PORT}`));

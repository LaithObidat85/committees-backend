// createAdmin.js
require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

// 1. الاتصال بقاعدة البيانات
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ تم الاتصال بقاعدة البيانات"))
  .catch((err) => console.error("❌ خطأ في الاتصال:", err));

// 2. تعريف الـ Schema مع role
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  approved: Boolean,
  role: { type: String, default: "user" }, // 🆕 الحقل الجديد
});
const User = mongoose.model("User", UserSchema);

// 3. إنشاء مستخدم جديد
async function createAdmin() {
  try {
    const email = "laith.obaidat@iu.edu.jo"; // ✏️ غيّره إذا أردت
    const password = "123456"; // ✏️ غيّرها لكلمة مرور قوية
    const name = "Admin Laith"; // ✏️ الاسم الظاهر

    // تحقق إذا كان موجود مسبقًا
    const existing = await User.findOne({ email });
    if (existing) {
      console.log("⚠️ هذا البريد موجود مسبقًا:", email);
      process.exit(0);
    }

    // تشفير الباسورد
    const hashed = await bcrypt.hash(password, 10);

    // إنشاء المستخدم
    const admin = new User({
      name,
      email,
      password: hashed,
      approved: true, // ✅ مباشرةً موافق
      role: "admin",  // 🆕 يضاف كمسؤول
    });

    await admin.save();
    console.log("🎉 تم إنشاء المستخدم Admin بنجاح:", email);
    process.exit(0);
  } catch (err) {
    console.error("❌ خطأ أثناء إنشاء المستخدم:", err);
    process.exit(1);
  }
}

createAdmin();

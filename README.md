# 🚀 Server Monitor Bot
**قلب تپنده سرور شما در دستان تلگرام!**

---

مفتخریم که **Server Monitor Bot** را معرفی کنیم؛ ابزاری که مانیتورینگ سرور را از یک کار پیچیده، به یک تجربه لذت‌بخش و لحظه‌ای تبدیل می‌کند.

---

## ✨ چرا باید از این ربات استفاده کنید؟

- **زمان شما ارزشمند است:** ربات با زبان قدرتمند **Go** نوشته شده و به صورت یک فایل اجرایی سبک و مستقل عرضه می‌شود.  
- **امنیت کد (Binary-Only):** 🛡️ سورس کد اصلی (Go) در اختیار عموم قرار نمی‌گیرد. تنها فایل کامپایل شده دانلود می‌شود.  
- **سریع و سبک:** 🏎️ بدون نیاز به نصب پکیج‌های اضافی (Python, PHP و...) یا تنظیمات پیچیده.  
- **هشدار هوشمند:** 🔔 مصرف منابع از حد مجاز عبور کند، شما را بلافاصله مطلع می‌کند.  
- **گزارش‌های لحظه‌ای:** 🛰️ هر ۳۰ ثانیه، دقیق‌ترین جزئیات برای تصمیم‌گیری سریع ارائه می‌شود.

---

## 📊 شاخص‌های مانیتورینگ

| شاخص | عملکرد |
|------|---------|
| CPU و RAM | بررسی دقیق مصرف منابع اصلی سرور ✅ |
| فضای دیسک | میزان فضای خالی و پر شده هارد ✅ |
| Uptime سرور | مدت زمان روشن بودن و کارکرد بدون وقفه ✅ |
| Load Average | سلامت کلی سیستم تحت بار کاری ✅ |
| پورت‌های حیاتی | چک کردن پورت‌های ۸۰، ۴۴۳ و... ✅ |

---

## 🛠️ راهنمای نصب و راه‌اندازی سریع (ویژه Ubuntu)

### پیش‌نیازها
- یک سرور با سیستم عامل **Ubuntu** (یا Debian)
- توکن ربات تلگرام و **Chat ID** شخصی شما

---

### مرحله ۱: دانلود فایل اجرایی 📥

```bash
# ۱. ساخت پوشه برای نظم بیشتر و ورود به آن
mkdir telegram-monitor
cd telegram-monitor

# ۲. دانلود فایل اجرایی نهایی
wget https://github.com/arvinvahed/Telegram-Server-Monitor/releases/download/v1.0.0/server-monitor -O server-monitor

# ۳. اعطای مجوز اجرا به فایل
chmod +x server-monitor
مرحله ۲: اتصال به تلگرام 🔑
ربات توکن و Chat ID را از متغیرهای محیطی می‌خواند:

bash
Copy code
# ۱. توکن ربات تلگرام خود را جایگزین کنید
export TELEGRAM_BOT_TOKEN="Your_Bot_Token_Here"

# ۲. آی‌دی چت خود را جایگزین کنید (عدد صحیح)
export TELEGRAM_CHAT_ID="Your_Chat_ID_Here"
مرحله ۳: اجرای نهایی و دائمی 🎉
برنامه را در پس‌زمینه اجرا کنید:

bash
Copy code
nohup ./server-monitor > servmon.log 2>&1 &
echo "✅ مانیتورینگ سرور شما فعال شد! پیام‌ها را در تلگرام بررسی کنید."
🛑 توقف و پاکسازی کامل
توقف موقت ربات:

bash
Copy code
pkill server-monitor
echo "🛑 برنامه Server Monitor متوقف شد."
حذف کامل برنامه:

bash
Copy code
pkill server-monitor
cd ..
rm -rf telegram-monitor
rm -f servmon.log
echo "🗑️ Server Monitor به صورت کامل حذف شد!"## 📞 ارتباط با ما و جامعه کاربری

ما همیشه آماده پاسخگویی به سوالات و شنیدن پیشنهادات شما هستیم.  

- **گروه پشتیبانی تلگرام:** [VPNMarket Official Support](https://t.me/VPNMarket_OfficialSupport/1)  
- **کانال یوتوب:** [Iraneclips YouTube](https://www.youtube.com/@iraneclips8168)  
- **گیت‌هاب پروژه:** [Telegram Server Monitor](https://github.com/arvinvahed/Telegram-Server-Monitor)

# 🚀 Server Monitor Bot - NightLink

<p align="center">
  <a href="https://t.me/VPNMarket_OfficialSupport"><img src="https://img.shields.io/badge/Telegram-Group-blue.svg?style=for-the-badge&logo=telegram" alt="گروه تلگرام"></a>
  <a href="https://www.youtube.com/@iraneclips8168/videos"><img src="https://img.shields.io/badge/YouTube-Channel-red.svg?style=for-the-badge&logo=youtube" alt="کانال یوتیوب"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="لایسنس"></a>
</p>

NightLink: قلب تپنده سرور شما در دستان تلگرام!

NightLink ابزاری است که مانیتورینگ و مدیریت سرور را از یک کار پیچیده، به یک تجربه لذت‌بخش و لحظه‌ای تبدیل می‌کند. این ربات با زبان قدرتمند **Go** نوشته شده و به صورت یک فایل اجرایی سبک و مستقل عرضه می‌شود.

---

## ✨ چرا NightLink؟

- **زمان شما ارزشمند است:** ربات با Go نوشته شده و بدون نیاز به نصب پکیج‌های اضافی اجرا می‌شود.
- **مدیریت پیشرفته و ایمن:** 🔐 اجرای دستورات حیاتی sudo مانند مدیریت پورت، ساخت کاربر و تغییر رمز عبور از طریق منوی امن تلگرام.
- **سریع و سبک:** 🏎️ بدون نیاز به Python، PHP یا تنظیمات پیچیده.
- **هشدار هوشمند و لحظه‌ای:** 🔔 مصرف منابع (CPU, RAM, Disk) به محض عبور از آستانه‌ها، به شما هشدار می‌دهد.
- **گزارش‌های دوره‌ای:** 🛰️ هر ۳۰ ثانیه، دقیق‌ترین جزئیات و آمار سیستم برای تصمیم‌گیری سریع ارائه می‌شود.

---

## 📊 شاخص‌های مانیتورینگ و عیب‌یابی فوری

| قابلیت            | توضیحات عملکرد |
|-------------------|----------------|
| **وضعیت فوری**     | Uptime، Load Avg (1m/5m/15m)، مصرف CPU و RAM |
| **جزئیات دیسک**    | فضای خالی و پر شده هارد، گزارش تفکیکی پارتیشن‌ها |
| **I/O و شبکه**     | ترافیک RX/TX، IPهای عمومی و محلی، تست Ping |
| **فرآیندها (Top)** | ۱۰ فرآیند پرمصرف CPU و RAM |
| **امنیت و فایروال**| وضعیت فایروال (UFW) و پورت‌های باز |
| **لاگ‌های حیاتی**  | ۱۰ خط آخر لاگ‌های امنیتی و سیستمی |
| **وضعیت سرویس‌ها** | سرویس‌های nginx, docker, mysql, ssh و غیره |

---

## 🔑 قابلیت‌های مدیریت پیشرفته (Admin Tools)

از طریق منوی "🔑 مدیریت پیشرفته" می‌توانید عملیات زیر را انجام دهید:

| عملیات           | دستور نمونه |
|-----------------|-------------|
| مدیریت پورت      | باز کردن: `allow 8080/tcp` / بستن: `deny 21` |
| ساخت کاربر       | `adduser <username> <password>` |
| تغییر رمز        | `passwd <username> <new_password>` |
| پاکسازی دیسک     | حذف فایل‌های کش و بسته‌های اضافی (`autoremove`, `clean`) |
| ری‌استارت/خاموشی | ری‌استارت یا خاموش کردن سرور با تأییدیه امنیتی |

---

## 🛠️ راهنمای نصب و راه‌اندازی (Ubuntu)

### پیش‌نیازها
- سرور با Ubuntu یا Debian
- توکن ربات تلگرام و Chat ID شخصی
- کاربر سیستم با دسترسی sudo بدون پسورد

### مرحله ۱: دانلود فایل اجرایی
```bash
mkdir NightLink-Monitor
cd NightLink-Monitor
wget https://github.com/arvinvahed/Telegram-Server-Monitor/releases/download/v1.0.0/server-monitor -O server-monitor
chmod +x server-monitor
مرحله ۲: اتصال به تلگرام
bash
Copy code
export TELEGRAM_BOT_TOKEN="Your_Bot_Token_Here"
export TELEGRAM_CHAT_ID="Your_Chat_ID_Here"
مرحله ۳: اجرای نهایی و دائمی
bash
Copy code
screen -S NightLink_Monitor
./server-monitor
# خروج از Screen بدون توقف برنامه: Ctrl+A سپس D
توقف و پاکسازی کامل
bash
Copy code
# توقف موقت
pkill server-monitor

# حذف کامل برنامه
pkill server-monitor
cd ..

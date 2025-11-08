🚀 Server Monitor Bot - NightLink

<p align="center">
<a href="https://t.me/VPNMarket_OfficialSupport"><img src="https://img.shields.io/badge/Telegram-Group-blue.svg?style=for-the-badge&logo=telegram" alt="گروه تلگرام"></a>
<a href="https://www.youtube.com/@iraneclips8168/videos"><img src="https://www.google.com/search?q=https://img-youtube.com/vi/S-4F6qg6G20/hqdefault.jpg" alt="کانال یوتیوب" /></a>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="لایسنس"></a>
</p>

NightLink: قلب تپنده سرور شما در دستان تلگرام!

NightLink ابزاری است که مانیتورینگ و مدیریت سرور را از یک کار پیچیده، به یک تجربه لذت‌بخش و لحظه‌ای تبدیل می‌کند. این ربات با زبان قدرتمند Go نوشته شده و به صورت یک فایل اجرایی سبک و مستقل عرضه می‌شود.

✨ چرا باید از NightLink استفاده کنید؟

زمان شما ارزشمند است: ربات با زبان قدرتمند Go نوشته شده و به صورت یک فایل اجرایی سبک و مستقل عرضه می‌شود.

مدیریت پیشرفته و ایمن: 🔐 اجرای دستورات حیاتی sudo مانند باز و بستن پورت‌های فایروال، ساخت کاربر جدید و تغییر رمز عبور، همگی از طریق منوی امن تلگرام امکان‌پذیر است.

سریع و سبک: 🏎️ بدون نیاز به نصب پکیج‌های اضافی (Python, PHP و...) یا تنظیمات پیچیده.

هشدار هوشمند و لحظه‌ای: 🔔 مصرف منابع (CPU, RAM, Disk) به محض عبور از آستانه‌های تعریف‌شده، بلافاصله به شما هشدار می‌دهد.

گزارش‌های دوره‌ای: 🛰️ هر ۳۰ ثانیه، دقیق‌ترین جزئیات و آمار کلی سیستم برای تصمیم‌گیری سریع ارائه می‌شود.

📊 شاخص‌های مانیتورینگ و عیب‌یابی فوری

قابلیت

توضیحات عملکرد

وضعیت فوری

Uptime، Load Average (1m, 5m, 15m)، و مصرف لحظه‌ای CPU و RAM.

جزئیات دیسک

میزان فضای خالی و پر شده هارد، و گزارش تفکیکی تمام پارتیشن‌ها (Mountpoints).

I/O و شبکه

آمار ترافیک دریافتی (RX) و ارسالی (TX) از زمان بوت، IP‌های عمومی و محلی و تست Ping.

فرآیندها (Top)

نمایش ۱۰ فرآیند پرمصرف CPU و RAM برای شناسایی و عیب‌یابی فوری bottlenecks.

امنیت و فایروال

گزارش وضعیت فایروال (UFW) و نمایش ۵ قانون برتر آن و پورت‌های باز.

لاگ‌های حیاتی

نمایش ۱۰ خط آخر لاگ‌های امنیتی (/var/log/auth.log) و سیستمی (/var/log/syslog یا journalctl) برای رصد خطاها.

وضعیت سرویس‌ها

بررسی وضعیت سرویس‌های کلیدی مانند nginx, docker, mysql, ssh و غیره.

🔑 قابلیت‌های مدیریت پیشرفته (Admin Tools)

با استفاده از منوی "🔑 مدیریت پیشرفته"، می‌توانید عملیات زیر را به‌صورت امن از طریق ربات انجام دهید:

عملیات

دستور نمونه (در صورت نیاز به ارسال دستی)

مدیریت پورت

باز کردن پورت: allow 8080/tcp / بستن پورت: deny 21

ساخت کاربر

ساخت کاربر جدید و افزودن آن به گروه sudo: adduser <username> <password>

تغییر رمز

تغییر رمز عبور کاربر موجود: passwd <username> <new_password>

پاکسازی دیسک

حذف فایل‌های کش APT و بسته‌های اضافی (Autoremove)

ری‌استارت/خاموشی

انجام ری‌استارت یا خاموش کردن کامل سرور با درخواست تأییدیه امنیتی.

🛠️ راهنمای نصب و راه‌اندازی سریع (ویژه Ubuntu)

پیش‌نیازها

یک سرور با سیستم عامل Ubuntu (یا Debian)

توکن ربات تلگرام و Chat ID شخصی شما

توجه: کاربر سیستمی که ربات با آن اجرا می‌شود، باید دسترسی sudo بدون نیاز به رمز عبور داشته باشد.

مرحله ۱: دانلود فایل اجرایی 📥

# ۱. ساخت پوشه برای نظم بیشتر و ورود به آن
mkdir NightLink-Monitor
cd NightLink-Monitor

# ۲. دانلود فایل اجرایی نهایی (URL را با لینک آخرین Release خود جایگزین کنید)
# مثال:
wget [https://github.com/arvinvahed/NightLink/releases/latest/download/server-monitor](https://github.com/arvinvahed/NightLink/releases/latest/download/server-monitor) -O server-monitor

# ۳. اعطای مجوز اجرا به فایل
chmod +x server-monitor


مرحله ۲: اتصال به تلگرام 🔑

ربات توکن و Chat ID را از متغیرهای محیطی می‌خواند:

# ۱. توکن ربات تلگرام خود را جایگزین کنید
export TELEGRAM_BOT_TOKEN="Your_Bot_Token_Here"

# ۲. آی‌دی چت خود را جایگزین کنید (عدد صحیح)
export TELEGRAM_CHAT_ID="Your_Chat_ID_Here"


مرحله ۳: اجرای نهایی و دائمی 🎉

برنامه را در پس‌زمینه اجرا کنید (توصیه می‌شود از screen یا tmux استفاده کنید):

# استفاده از Screen برای اجرای دائمی
screen -S NightLink_Monitor
# اجرای برنامه با متغیرهای محیطی
./server-monitor 

# (برای خروج از Screen بدون توقف برنامه، کلیدهای Ctrl+A و سپس D را بزنید)
echo "✅ مانیتورینگ سرور شما فعال شد! پیام‌ها را در تلگرام بررسی کنید."


🛑 توقف و پاکسازی کامل

توقف موقت ربات:

pkill server-monitor
echo "🛑 برنامه NightLink Server Monitor متوقف شد."


حذف کامل برنامه و فایل‌ها:

# ابتدا برنامه را متوقف کنید
pkill server-monitor
# بازگشت به پوشه والد و حذف دایرکتوری
cd ..
rm -rf NightLink-Monitor
echo "🗑️ NightLink Server Monitor کاملاً حذف شد."

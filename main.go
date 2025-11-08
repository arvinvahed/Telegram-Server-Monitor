package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

// ==================== تنظیمات ====================
var (
	// توجه: مقادیر توکن و chatID اکنون مستقیماً (Hardcoded) در کد قرار داده شدند.
	// اگر می‌خواهید از متغیر محیطی استفاده کنید، باید os.Getenv("TELEGRAM_BOT_TOKEN") را برگردانید.
	botToken = "8329383840:AAFZ52DvxokfNJpAG8zoAhliFmt7t1egDP8" // توکن ربات تلگرام
	chatID   = "6157719562" 	// آی‌دی چت تلگرام
	interval = 30 				// ثانیه بین هر بررسی
)

const (
	cpuThresholdPercent  = 85.0
	memThresholdPercent  = 85.0
	diskThresholdPercent = 90.0
	alertCooldown        = 300 // ثانیه بین هشدار مشابه (5 دقیقه)
	logFile              = "servmon.log"
)

var servicesToCheck = []string{"nginx", "ssh", "mysql", "docker"} // سرویس‌های حیاتی (مخصوص systemd)
var pingTargets = []string{"8.8.8.8", "1.1.1.1"}                  // آی‌پی برای ping
var portsToCheck = []int{22, 80, 443}                             // پورت‌ها

type lastAlerts struct {
	cpu, mem, disk time.Time
	service        map[string]time.Time
	ping           map[string]time.Time
	port           map[int]time.Time
}

// ==================== توابع ====================

// لاگ کردن پیام در فایل و کنسول
func logMessage(msg string) {
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		fmt.Fprintf(f, "[%s] %s\n", time.Now().Format(time.RFC3339), msg)
	}
	log.Println(msg)
}

// ارسال پیام به تلگرام با استفاده از net/url
func sendTelegram(text string) error {
	// این چک اکنون تنها یک گارد ایمنی است
	if botToken == "" || chatID == "" {
		return fmt.Errorf("TELEGRAM_BOT_TOKEN یا TELEGRAM_CHAT_ID تنظیم نشده‌اند")
	}

	// استفاده از url.Values برای کدگذاری (Encoding) مطمئن پارامترها
	data := url.Values{
		"chat_id":    {chatID},
		"parse_mode": {"Markdown"},
		"text":       {text},
	}

	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", botToken)

	// ساخت درخواست با Content-Type: application/x-www-form-urlencoded
	req, err := http.NewRequestWithContext(context.Background(), "POST", url, strings.NewReader(data.Encode()))
	if err != nil {
		logMessage(fmt.Sprintf("Error creating Telegram request: %v", err))
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 15 * time.Second} // افزایش timeout
	resp, err := client.Do(req)
	if err != nil {
		logMessage(fmt.Sprintf("Error sending to Telegram API: %v", err))
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		buf := new(bytes.Buffer)
		buf.ReadFrom(resp.Body)
		logMessage(fmt.Sprintf("Telegram API returned non-200 status %s. Response body: %s", resp.Status, buf.String()))
		return fmt.Errorf("telegram api returned status %s", resp.Status)
	}
	return nil
}

// اجرای دستور شل
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		// در صورت شکست، جزئیات خطای stderr را برمی‌گردانیم
		if exitErr, ok := err.(*exec.ExitError); ok {
			errMsg := fmt.Sprintf("Command failed: %s %v (Stderr: %s)", name, args, string(exitErr.Stderr))
			logMessage(errMsg)
			return "", fmt.Errorf(errMsg)
		}
		logMessage(fmt.Sprintf("Command execution error: %s %v (%v)", name, args, err))
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// بررسی وضعیت سرویس (نیازمند systemd)
func checkService(name string) bool {
	// توجه: این تابع systemctl را فراخوانی می‌کند که روی ویندوز (جایی که PowerShell استفاده می‌کنید) کار نمی‌کند.
	// برای تست روی ویندوز، این بخش ممکن است با خطا مواجه شود و همواره false برگرداند.
	out, err := runCmd("systemctl", "is-active", name)
	if err != nil {
		logMessage(fmt.Sprintf("Error checking service %s (systemctl): %v", name, err))
		return false
	}
	return out == "active"
}

// بررسی ping (نیازمند دسترسی root برای ICMP خام در لینوکس)
func ping(host string) bool {
	// توجه: تابع ping در ویندوز/Go ممکن است به روش متفاوتی کار کند یا نیاز به مجوز داشته باشد.
	// اگر روی ویندوز هستید و خطا می‌گیرید، ممکن است به خاطر عدم دسترسی به ICMP خام باشد.
	_, err := net.DialTimeout("ip4:icmp", host, 3*time.Second) 
	if err != nil {
		logMessage(fmt.Sprintf("Ping to %s failed: %v", host, err))
	}
	return err == nil
}

// بررسی پورت باز
func checkPort(host string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 2*time.Second)
	if err != nil {
		logMessage(fmt.Sprintf("Port %s:%d check failed: %v", host, port, err))
		return false
	}
	conn.Close()
	return true
}

// ==================== برنامه اصلی ====================
func main() {
	last := lastAlerts{
		service: make(map[string]time.Time),
		ping:    make(map[string]time.Time),
		port:    make(map[int]time.Time),
	}

	logMessage("Server Monitor started.")

	// بررسی یک بار اولیه برای اطمینان از تنظیم بودن توکن و chatID
	// اکنون مقادیر مستقیماً در متغیرها هستند، پس این شرط نباید اجرا شود.
	if botToken == "" || chatID == "" {
		logMessage("FATAL: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set. Exiting.")
		os.Exit(1)
	}

	for {
		start := time.Now()

		// -------- بررسی منابع سیستم (با مدیریت خطا) --------
		var cpuUsed, memUsed, diskUsed float64
		var uptime string
		var load1, load5, load15 float64

		// CPU
		cpuPercent, err := cpu.Percent(0, false)
		if err != nil {
			logMessage(fmt.Sprintf("Error getting CPU stats: %v", err))
		} else if len(cpuPercent) > 0 {
			cpuUsed = cpuPercent[0]
		}

		// RAM
		vmStat, err := mem.VirtualMemory()
		if err != nil {
			logMessage(fmt.Sprintf("Error getting RAM stats: %v", err))
		} else {
			memUsed = vmStat.UsedPercent
		}

		// Disk
		diskStat, err := disk.Usage("/")
		if err != nil {
			logMessage(fmt.Sprintf("Error getting Disk stats for '/': %v", err))
		} else {
			diskUsed = diskStat.UsedPercent
		}

		// Load Average
		loadAvg, err := load.Avg()
		if err != nil {
			logMessage(fmt.Sprintf("Error getting Load Avg: %v", err))
		} else {
			load1, load5, load15 = loadAvg.Load1, loadAvg.Load5, loadAvg.Load15
		}

		// Uptime
		// در ویندوز، دستور 'uptime' وجود ندارد و این اجرا با خطا مواجه خواهد شد.
		uptime, err = runCmd("uptime", "-p")
		if err != nil {
			logMessage(fmt.Sprintf("Warning: Uptime command failed (may not be available on Windows): %v", err))
			uptime = "N/A (Win)"
		}

		status := fmt.Sprintf("*Server Status*\nUptime: %s\nLoad Avg: %.2f (1m), %.2f (5m), %.2f (15m)\nCPU: %.1f%%\nRAM: %.1f%%\nDisk: %.1f%%",
			uptime, load1, load5, load15, cpuUsed, memUsed, diskUsed)
		logMessage(status)

		now := time.Now()

		// -------- هشدار منابع --------
		if cpuUsed >= cpuThresholdPercent && now.Sub(last.cpu).Seconds() > alertCooldown {
			msg := fmt.Sprintf("⚠️ *CPU High Alert* ⚠️\nUsage: %.1f%% (Threshold: %.0f%%)\n\n%s", cpuUsed, cpuThresholdPercent, status)
			if sendTelegram(msg) == nil {
				last.cpu = now
			}
		}
		if memUsed >= memThresholdPercent && now.Sub(last.mem).Seconds() > alertCooldown {
			msg := fmt.Sprintf("⚠️ *RAM High Alert* ⚠️\nUsage: %.1f%% (Threshold: %.0f%%)\n\n%s", memUsed, memThresholdPercent, status)
			if sendTelegram(msg) == nil {
				last.mem = now
			}
		}
		if diskUsed >= diskThresholdPercent && now.Sub(last.disk).Seconds() > alertCooldown {
			msg := fmt.Sprintf("⚠️ *Disk Space Alert* ⚠️\nUsage: %.1f%% (Threshold: %.0f%%)\n\n%s", diskUsed, diskThresholdPercent, status)
			if sendTelegram(msg) == nil {
				last.disk = now
			}
		}

		// -------- بررسی سرویس‌ها --------
		for _, svc := range servicesToCheck {
			if !checkService(svc) {
				if now.Sub(last.service[svc]).Seconds() > alertCooldown {
					msg := fmt.Sprintf("❌ *Service Down* ❌\nService `%s` is not running!", svc)
					if sendTelegram(msg) == nil {
						last.service[svc] = now
					}
				}
			} else if !last.service[svc].IsZero() && now.Sub(last.service[svc]).Seconds() > alertCooldown {
				// ارسال هشدار بازیابی (Recovery) برای سرویس
				msg := fmt.Sprintf("✅ *Service Recovery* ✅\nService `%s` is now running.", svc)
				sendTelegram(msg)
				last.service[svc] = time.Time{} // صفر کردن برای بازیابی
			}
		}

		// -------- بررسی ping --------
		for _, ip := range pingTargets {
			if !ping(ip) {
				if now.Sub(last.ping[ip]).Seconds() > alertCooldown {
					msg := fmt.Sprintf("🌐 *Network Down* 🌐\nPing to `%s` failed!", ip)
					if sendTelegram(msg) == nil {
						last.ping[ip] = now
					}
				}
			} else if !last.ping[ip].IsZero() && now.Sub(last.ping[ip]).Seconds() > alertCooldown {
				// ارسال هشدار بازیابی
				msg := fmt.Sprintf("✅ *Network Recovery* ✅\nPing to `%s` succeeded again.", ip)
				sendTelegram(msg)
				last.ping[ip] = time.Time{}
			}
		}

		// -------- بررسی پورت‌ها --------
		// توجه: پورت‌ها به صورت محلی (127.0.0.1) چک می‌شوند
		for _, p := range portsToCheck {
			if !checkPort("127.0.0.1", p) {
				if now.Sub(last.port[p]).Seconds() > alertCooldown {
					msg := fmt.Sprintf("🚪 *Port Down* 🚪\nLocal Port `%d` is closed!", p)
					if sendTelegram(msg) == nil {
						last.port[p] = now
					}
				}
			} else if !last.port[p].IsZero() && now.Sub(last.port[p]).Seconds() > alertCooldown {
				// ارسال هشدار بازیابی
				msg := fmt.Sprintf("✅ *Port Recovery* ✅\nLocal Port `%d` is now open.", p)
				sendTelegram(msg)
				last.port[p] = time.Time{}
			}
		}

		// -------- فاصله تا بررسی بعدی --------
		elapsed := time.Since(start)
		sleepFor := time.Duration(interval)*time.Second - elapsed
		if sleepFor > 0 {
			time.Sleep(sleepFor)
		} else {
			// اگر بررسی بیشتر از زمان interval طول بکشد، لاگ می‌کنیم.
			logMessage(fmt.Sprintf("Warning: Check took longer than interval (%s)", elapsed))
			time.Sleep(1 * time.Second) // یک ثانیه صبر می‌کنیم تا CPU کاملا اشغال نشود.
		}
	}
}
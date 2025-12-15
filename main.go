package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Essential environment variables and thresholds
var (
	botToken  = os.Getenv("TELEGRAM_BOT_TOKEN")
	chatIDStr = os.Getenv("TELEGRAM_CHAT_ID")
	chatID    int64
	// Please set your repository URL here
	githubRepoURL = "https://github.com/arvinvahed/NightLink"

	cpuThreshold  float64 = 85.0
	memThreshold  float64 = 85.0
	diskThreshold float64 = 85.0

	// Definition of main menu buttons (Reply Keyboard)
	MainMenuKeyboard = tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("📊 Server Immediate Status"),
			tgbotapi.NewKeyboardButton("⚙️ High Consumption Processes (Top)"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🌐 Network and Traffic Report"),
			tgbotapi.NewKeyboardButton("🛡️ Security and Firewall Report"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🔑 Advanced Management"),
			tgbotapi.NewKeyboardButton("📄 Latest Error Logs"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🛠️ Service Management"),
			tgbotapi.NewKeyboardButton("💿 Disk and Partition Details"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("🗑️ Cache and Disk Cleanup"),
			tgbotapi.NewKeyboardButton("🔄 Restart Server (Warning!)"),
		),
	)
)

// Main program function
func main() {
	if botToken == "" || chatIDStr == "" {
		log.Fatal("Error: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.")
	}

	var err error
	chatID, err = convertChatID(chatIDStr)
	if err != nil {
		log.Fatalf("Error converting Chat ID: %v", err)
	}

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		log.Panic(err)
	}

	log.Printf("Bot token verified. Username: %s", bot.Self.UserName)

	sendWelcomeMessage(bot)
	// Monitoring every 5 minutes (300 seconds)
	go startPeriodicMonitor(bot, 5*time.Minute)
	startBotPolling(bot)
}

// =========================================================
// Periodic monitoring and system statistics section
// =========================================================

func startPeriodicMonitor(bot *tgbotapi.BotAPI, interval time.Duration) {
	// Sends the first report immediately (for initial threshold check)
	sendStatusReport(bot, true)
	for {
		time.Sleep(interval)
		sendStatusReport(bot, true) // In periodic monitoring mode, only thresholds are checked
	}
}

// sendStatusReport: Reports system status. checkThreshold=true is for periodic monitoring.
func sendStatusReport(bot *tgbotapi.BotAPI, checkThreshold bool) {
	report, err := getSystemStats()
	if err != nil {
		log.Printf("Error getting system statistics: %v", err)
		if !checkThreshold {
			sendTelegramMessage(bot, fmt.Sprintf("🔴 Error collecting information: %v", err))
		}
		return
	}

	// If it's periodic monitoring and consumption is high, sends an alert.
	if checkThreshold && (report.cpuUsage > cpuThreshold || report.memUsage > memThreshold || report.diskUsage > diskThreshold) {
		sendThresholdAlert(bot, report)
		return
	}

	// If requested via 'Immediate Status' button, full report is sent.
	if !checkThreshold {
		sendTelegramMessage(bot, formatSystemReport(report))
	}
}

func sendThresholdAlert(bot *tgbotapi.BotAPI, r systemReport) {
	alertMsg := "🚨 **High Consumption Alert!** 🚨\n\n"
	isAlert := false

	if r.cpuUsage > cpuThreshold {
		alertMsg += fmt.Sprintf("💥 **CPU Usage**: Consumption exceeded `%.1f%%` (threshold %.1f%%).\n", r.cpuUsage, cpuThreshold)
		isAlert = true
	}
	if r.memUsage > memThreshold {
		alertMsg += fmt.Sprintf("💥 **RAM Usage**: Consumption exceeded `%.1f%%` (threshold %.1f%%).\n", r.memUsage, memThreshold)
		isAlert = true
	}
	if r.diskUsage > diskThreshold {
		alertMsg += fmt.Sprintf("💥 **Disk Usage**: Consumption exceeded `%.1f%%` (threshold %.1f%%).\n", r.diskUsage, diskThreshold)
		isAlert = true
	}

	if isAlert {
		alertMsg += "\nPlease check the server status. Press 'High Consumption Processes (Top)' button to identify the issue."
		sendTelegramMessage(bot, alertMsg)
	}
}

// Data structure for system report
type systemReport struct {
	uptime    time.Duration
	loadAvg   load.AvgStat
	cpuUsage  float64
	memUsage  float64
	diskUsage float64
}

func getSystemStats() (systemReport, error) {
	r := systemReport{}
	v, err := mem.VirtualMemory()
	if err != nil {
		return r, err
	}
	r.memUsage = v.UsedPercent

	// Wait 100 milliseconds for accurate CPU percentage calculation
	c, err := cpu.Percent(time.Millisecond*100, false)
	if err != nil {
		return r, err
	}
	// gopsutil always returns a slice. If multi-core, we take the total average (index 0).
	if len(c) > 0 {
		r.cpuUsage = c[0]
	} else {
		return r, fmt.Errorf("CPU stats not available")
	}

	d, err := disk.Usage("/")
	if err != nil {
		return r, err
	}
	r.diskUsage = d.UsedPercent
	l, err := load.Avg()
	if err != nil {
		return r, err
	}
	r.loadAvg = *l
	h, err := host.Info()
	if err != nil {
		return r, err
	}
	r.uptime = time.Duration(h.Uptime) * time.Second

	return r, nil
}

func formatSystemReport(r systemReport) string {
	report := fmt.Sprintf("💚 **Instantaneous Server Status Report** 💚\n\n")
	report += fmt.Sprintf("⏰ **Uptime**: %s\n", formatDuration(r.uptime))
	report += fmt.Sprintf("📊 **Load Avg (1m/5m/15m)**: %.2f / %.2f / %.2f\n\n", r.loadAvg.Load1, r.loadAvg.Load5, r.loadAvg.Load15)
	report += fmt.Sprintf("🧠 **CPU Usage**: `%.1f%%` %s\n", r.cpuUsage, getStatusEmoji(r.cpuUsage, cpuThreshold))
	report += fmt.Sprintf("💾 **RAM Usage**: `%.1f%%` %s\n", r.memUsage, getStatusEmoji(r.memUsage, memThreshold))
	report += fmt.Sprintf("💿 **Disk Usage**: `%.1f%%` %s\n", r.diskUsage, getStatusEmoji(r.diskUsage, diskThreshold))

	return report
}

// =========================================================
// Command processing and access control functions
// =========================================================

func startBotPolling(bot *tgbotapi.BotAPI) {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message != nil {
			// **Main security rule: Only responds to authorized chat ID.**
			if update.Message.Chat.ID != chatID {
				log.Printf("Warning: Message received from unauthorized chat ID: %d", update.Message.Chat.ID)
				// Could send a security warning message for these chats
				// sendTelegramMessage(bot, "⛔️ Unauthorized access. This bot is only configured for server admin.", update.Message.Chat.ID)
				continue
			}

			// Check if the text message is a management command that the bot expects
			if strings.HasPrefix(update.Message.Text, "allow") ||
				strings.HasPrefix(update.Message.Text, "deny") ||
				strings.HasPrefix(update.Message.Text, "adduser") ||
				strings.HasPrefix(update.Message.Text, "passwd") {
				executeUserOrPortAction(bot, update.Message.Text)
			} else {
				handleCommands(bot, update.Message.Text)
			}
		} else if update.CallbackQuery != nil {
			handleCallback(bot, update.CallbackQuery)
		}
	}
}

func handleCommands(bot *tgbotapi.BotAPI, text string) {
	bot.Send(tgbotapi.NewChatAction(chatID, tgbotapi.ChatTyping))

	switch text {
	case "📊 Server Immediate Status":
		sendStatusReport(bot, false)
	case "🌐 Network and Traffic Report":
		sendNetworkReport(bot)
	case "🛡️ Security and Firewall Report":
		sendFirewallReport(bot)
	case "📄 Latest Error Logs":
		sendLogReport(bot)
	case "🔑 Advanced Management":
		sendAdvancedManagementMenu(bot)
	case "🛠️ Service Management":
		sendServiceStatus(bot)
	case "💿 Disk and Partition Details":
		sendDiskUsageReport(bot)
	case "⚙️ High Consumption Processes (Top)":
		sendTopProcessesReport(bot)
	case "👤 User and Login Management":
		sendUserReport(bot)
	case "🔗 Installation and Update Guide":
		sendInstallationGuide(bot)
	case "🗑️ Cache and Disk Cleanup":
		sendDiskCleanupConfirmation(bot) // Required function definition added
	case "🔄 Restart Server (Warning!)":
		sendConfirmation(bot, "reboot")
	case "🔌 Shutdown Server (Warning!)":
		sendConfirmation(bot, "shutdown")
	default:
		sendTelegramMessage(bot, "Invalid command. Please use the menu buttons.")
	}
}

// -----------------------------------------------------------------------
// New function: Confirms disk cleanup process
// -----------------------------------------------------------------------
func sendDiskCleanupConfirmation(bot *tgbotapi.BotAPI) {
	sendConfirmation(bot, "cleanup")
}

// New function: Shows advanced management menu
func sendAdvancedManagementMenu(bot *tgbotapi.BotAPI) {
	text := "🔑 **Advanced Server Management** 🔑\n\n"
	text += "Please select the desired operation. Note that these operations require `sudo` level access."

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🚪 Open/Close Firewall Port (UFW)", "adv_port"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("➕ Create New User (with Sudo)", "adv_adduser"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("🔄 Change Server User Password", "adv_changepass"),
		),
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("❌ Cancel and Return", "cancel"),
		),
	)
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ReplyMarkup = keyboard
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending advanced management message: %v", err)
	}
}

// New function: Sends system log report
func sendLogReport(bot *tgbotapi.BotAPI) {
	report := "📄 **Last 10 lines of important system logs** 📄\n\n"

	authLogOutput, err := executeCommand("tail", []string{"-n", "10", "/var/log/auth.log"})
	if err == nil {
		report += "🚨 **Auth Log (/var/log/auth.log) - Security/Login logs:**\n"
		report += fmt.Sprintf("```\n%s\n```\n", strings.TrimSpace(authLogOutput))
	} else {
		report += "🚨 **Auth Log:** ❓ Access error or file not found.\n"
	}

	// Attempt to get syslog
	sysLogOutput, err := executeCommand("tail", []string{"-n", "10", "/var/log/syslog"})
	if err == nil {
		report += "\n⚙️ **Syslog (/var/log/syslog) - General system logs:**\n"
		report += fmt.Sprintf("```\n%s\n```\n", strings.TrimSpace(sysLogOutput))
	} else {
		// If syslog not found, we use journalctl
		journalOutput, err := executeCommand("journalctl", []string{"-n", "10", "-q", "--no-pager"})
		if err == nil {
			report += "\n⚙️ **Journalctl (Last 10 lines):**\n"
			report += fmt.Sprintf("```\n%s\n```\n", strings.TrimSpace(journalOutput))
		} else {
			report += "\n⚙️ **Syslog:** ❓ Access error or file not found.\n"
		}
	}

	sendTelegramMessage(bot, report)
}

// Handler function for advanced actions (Callback)
func handleAdvancedManagementCallback(bot *tgbotapi.BotAPI, callback *tgbotapi.CallbackQuery, action string) {
	edit := tgbotapi.NewEditMessageText(chatID, callback.Message.MessageID, callback.Message.Text)
	edit.ReplyMarkup = nil // Remove previous buttons

	var keyboard tgbotapi.InlineKeyboardMarkup

	switch action {
	case "adv_port":
		edit.Text += "\n\n🚪 **Firewall Port Management (UFW)**\n"
		edit.Text += "Please send your command in one of the following formats:\n"
		edit.Text += "1. Open port: `allow <port>` (example: `allow 8080` or `allow 8080/tcp`)\n"
		edit.Text += "2. Close port: `deny <port>` (example: `deny 21` or `deny 21/tcp`)\n"

		keyboard = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("💡 Example: allow 22", "port_action:allow:22"),
				tgbotapi.NewInlineKeyboardButtonData("💡 Example: deny 23/udp", "port_action:deny:23/udp"),
			),
		)
		edit.ReplyMarkup = &keyboard

	case "adv_adduser":
		edit.Text += "\n\n➕ **Create New User (Sudo)**\n"
		edit.Text += "Please send the command in the following format:\n"
		edit.Text += "`adduser <username> <password>`\n\n"
		edit.Text += "⚠️ **Note**: The new user will be created and added to the `sudo` group. (Full access)"
		keyboard = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("💡 Example: adduser testuser P@ssword123", "user_action:adduser:testuser:P@ssword123"),
			),
		)
		edit.ReplyMarkup = &keyboard

	case "adv_changepass":
		edit.Text += "\n\n🔄 **Change Server User Password**\n"
		edit.Text += "Please send the command in the following format:\n"
		edit.Text += "`passwd <username> <new_password>`\n\n"
		edit.Text += "⚠️ **Note**: The new password will be set directly on the user."
		keyboard = tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("💡 Example: passwd root NewSecurePass!", "user_action:passwd:root:NewSecurePass!"),
			),
		)
		edit.ReplyMarkup = &keyboard
	}

	bot.Send(edit)
}

// -----------------------------------------------------------------------
// Function to execute user/port actions
// -----------------------------------------------------------------------
func executeUserOrPortAction(bot *tgbotapi.BotAPI, data string) {
	parts := strings.Fields(data)

	// 1. Port action (allow/deny) - must be exactly 2 parts: allow <port>
	if len(parts) == 2 && (parts[0] == "allow" || parts[0] == "deny") {
		action := parts[0]
		port := parts[1]
		executePortAction(bot, action, port)
		return
	}

	// 2. Create user or change password action - must be exactly 3 parts: <cmd> <user> <pass>
	if len(parts) == 3 {
		command := parts[0]
		username := parts[1]
		password := parts[2]

		if command == "adduser" {
			executeCreateUser(bot, username, password)
			return
		}

		if command == "passwd" {
			executeChangePassword(bot, username, password)
			return
		}
	}

	// If none of the above conditions are met, an error is sent.
	sendTelegramMessage(bot, fmt.Sprintf("❌ **Invalid command format!**\nReceived: `%s`\n\nPlease use one of these formats:\n- Open port: `allow 370`\n- Create user: `adduser newuser strongpass`\n- Change password: `passwd root newpass`", data))
}

func executePortAction(bot *tgbotapi.BotAPI, action, port string) {
	_, err := executeCommand("sudo", []string{"ufw", action, port})
	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("❌ **Error setting port %s**: \n`%v`", port, err))
		return
	}
	report := fmt.Sprintf("✅ **UFW operation completed successfully.**\n\n")
	report += fmt.Sprintf("Port: `%s`\nAction: **%s**\n\n", port, strings.ToUpper(action))
	report += "New firewall status:\n"
	// The output of this command (status) is used for user reporting.
	status, _ := executeCommand("sudo", []string{"ufw", "status", "numbered"})
	report += fmt.Sprintf("```\n%s\n```", status)
	sendTelegramMessage(bot, report)
}

func executeCreateUser(bot *tgbotapi.BotAPI, username, password string) {
	_, err := executeCommand("sudo", []string{"useradd", "-m", "-s", "/bin/bash", username})
	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("❌ **Error creating user %s**: \n`%v`", username, err))
		return
	}

	_, err = executeCommand("sudo", []string{"usermod", "-aG", "sudo", username})
	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("❌ **Error adding user %s to sudo**: \n`%v`", username, err))
		return
	}

	cmd := exec.Command("sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	_, err = cmd.CombinedOutput()
	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("❌ **Error setting password for user %s**: \n`%v`", username, err))
		return
	}

	report := fmt.Sprintf("✅ **User %s created successfully.**\n\n", username)
	report += "**Details**: \n"
	report += fmt.Sprintf("Username: `%s`\n", username)
	report += fmt.Sprintf("Password: `%s` (please change it)\n", password)
	report += "Groups: `sudo` (full root access)\n"

	sendTelegramMessage(bot, report)
}

func executeChangePassword(bot *tgbotapi.BotAPI, username, password string) {
	cmd := exec.Command("sudo", "chpasswd")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s:%s", username, password))
	output, err := cmd.CombinedOutput()

	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("❌ **Error changing password for user %s**: \n`%v`\nOutput: %s", username, err, string(output)))
		return
	}

	report := fmt.Sprintf("✅ **Password for user %s changed successfully.**\n\n", username)
	report += fmt.Sprintf("New password: `%s`\n", password)
	report += "⚠️ **Note**: This operation requires that the bot-running user has passwordless 'sudo' access."

	sendTelegramMessage(bot, report)
}

func handleCallback(bot *tgbotapi.BotAPI, callback *tgbotapi.CallbackQuery) {
	callbackData := callback.Data
	bot.Send(tgbotapi.NewChatAction(chatID, tgbotapi.ChatTyping))

	if strings.HasPrefix(callbackData, "adv_") {
		handleAdvancedManagementCallback(bot, callback, callbackData)
		return
	}

	// Ensure removal of previous message buttons with EditMessageText
	edit := tgbotapi.NewEditMessageText(chatID, callback.Message.MessageID, callback.Message.Text)

	// Send Callback to Telegram to remove loading spinner
	callbackConfig := tgbotapi.NewCallback(callback.ID, "Processing...")
	if _, err := bot.Request(callbackConfig); err != nil {
		log.Printf("Error sending Callback Query: %v", err)
	}

	switch callbackData {
	case "reboot_confirm":
		edit.Text += "\n\n✔️ **Confirmed! Restarting...**"
		bot.Send(edit)
		executeSystemAction(bot, "reboot")
	case "shutdown_confirm":
		edit.Text += "\n\n✔️ **Confirmed! Shutting down server...**"
		bot.Send(edit)
		executeSystemAction(bot, "shutdown")
	case "cleanup_confirm":
		edit.Text += "\n\n✔️ **Confirmed! Cleaning up disk...**"
		bot.Send(edit)
		diskCleanup(bot) // Call cleanup function
	case "cancel":
		edit.Text += "\n\n❌ **Operation canceled.**"
		edit.ReplyMarkup = nil
		bot.Send(edit)
	default:
		// If it's unknown data, ignore it to avoid logging errors
		if !strings.HasPrefix(callbackData, "port_action:") && !strings.HasPrefix(callbackData, "user_action:") {
			log.Printf("Unknown callback data received: %s", callbackData)
		}
	}
}

func sendFirewallReport(bot *tgbotapi.BotAPI) {
	report := "🛡️ **Security and Firewall Report** 🛡️\n\n"

	ufwStatus, err := executeCommand("sudo", []string{"ufw", "status"})
	if err == nil && strings.Contains(ufwStatus, "inactive") {
		report += "🚨 **UFW (Firewall) Status**: **❌ Inactive**!\n"
		report += "_To activate: `sudo ufw enable`_\n\n"
	} else if err == nil && strings.Contains(ufwStatus, "Status: active") {
		report += "✅ **UFW (Firewall) Status**: **Active**. (Basic security established)\n\n"
		rules, _ := executeCommand("sudo", []string{"ufw", "status", "numbered"})
		lines := strings.Split(rules, "\n")
		ruleLines := []string{}
		for i, line := range lines {
			if i > 2 && strings.TrimSpace(line) != "" {
				ruleLines = append(ruleLines, line)
				if len(ruleLines) >= 5 {
					break
				}
			}
		}
		if len(ruleLines) > 0 {
			report += "📜 **Top 5 Firewall Rules (UFW):**\n"
			report += fmt.Sprintf("```\n%s\n```\n", strings.Join(ruleLines, "\n"))
		}
	} else {
		report += "❓ **UFW Status:** Execution error or UFW not installed. (Requires `sudo apt install ufw`)\n"
	}

	netstatOutput, err := executeCommand("ss", []string{"-tuln"})
	if err == nil {
		report += "\n📡 **5 Open Ports (Listening)**:\n"
		lines := strings.Split(netstatOutput, "\n")
		if len(lines) > 1 {
			report += "```\n"
			count := 0
			for i, line := range lines {
				if i > 0 && strings.TrimSpace(line) != "" && strings.Contains(line, "LISTEN") {
					parts := strings.Fields(line)
					if len(parts) >= 5 {
						report += fmt.Sprintf("%-5s %s\n", parts[0], parts[4])
						count++
						if count >= 5 {
							break
						}
					}
				}
			}
			report += "```\n"
		}
	} else {
		report += "\n📡 **Open Ports:** Error executing `ss` command.\n"
	}

	sendTelegramMessage(bot, report)
}

func sendNetworkReport(bot *tgbotapi.BotAPI) {
	var report string
	publicIP, _ := executeCommand("curl", []string{"-s", "ifconfig.me"})
	if strings.Contains(publicIP, "error") || publicIP == "" {
		publicIP = "Error getting public IP"
	} else {
		publicIP = strings.TrimSpace(publicIP)
	}
	report += fmt.Sprintf("🌍 **Public IP Address**: `%s`\n", publicIP)
	localIP, _ := executeCommand("hostname", []string{"-I"})
	if strings.Contains(localIP, "error") || localIP == "" {
		localIP = "Error getting local IP"
	} else {
		localIP = strings.TrimSpace(localIP)
	}
	report += fmt.Sprintf("🏠 **Local IP Address**: `%s`\n\n", localIP)

	netStats, err := net.IOCounters(false)
	if err == nil && len(netStats) > 0 {
		totalRx := netStats[0].BytesRecv
		totalTx := netStats[0].BytesSent
		byteToGB := func(bytes uint64) string { return fmt.Sprintf("%.2f GB", float64(bytes)/(1024*1024*1024)) }
		report += "📈 **Network Traffic (I/O) since boot**:\n"
		report += fmt.Sprintf("⬇️ **Received (RX)**: %s\n", byteToGB(totalRx))
		report += fmt.Sprintf("⬆️ **Sent (TX)**: %s\n", byteToGB(totalTx))
	} else {
		report += "📈 **Network Traffic:** Error collecting traffic statistics.\n"
	}

	// Manual ping test to avoid dependency on specific packages
	pingResult, err := executeCommand("ping", []string{"-c", "4", "-W", "1", "8.8.8.8"})
	if err == nil {
		if strings.Contains(pingResult, "avg") {
			lines := strings.Split(pingResult, "\n")
			for _, line := range lines {
				if strings.Contains(line, "avg") {
					parts := strings.Split(line, "=")
					if len(parts) > 1 {
						// We want to capture only the average (avg)
						pingResult = strings.TrimSpace(strings.Split(parts[1], "/")[1])
						report += fmt.Sprintf("\n⚡ **Ping Test (8.8.8.8)**: `%s`ms\n", pingResult)
						break
					}
				}
			}
		} else {
			report += "\n⚡ **Ping Test (8.8.8.8)**: ❓ No response received or DNS issue.\n"
		}
	} else {
		report += "\n⚡ **Ping Test**: 🔴 Error or limited access (requires `iputils-ping` installation)\n"
	}
	sendTelegramMessage(bot, "🌐 **IP Status and Network Traffic Report**\n\n"+report)
}

func convertChatID(idStr string) (int64, error) {
	// Using strconv.ParseInt for safer conversion
	id, err := strconv.ParseInt(idStr, 10, 64)
	return id, err
}

func sendWelcomeMessage(bot *tgbotapi.BotAPI) {
	msg := tgbotapi.NewMessage(chatID, "🌟 Welcome to Server Management!\n\nPlease use the buttons below to control and monitor your server.")
	msg.ReplyMarkup = MainMenuKeyboard
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending welcome message: %v", err)
	}
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	days := d / (24 * time.Hour)
	d -= days * (24 * time.Hour)
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	return fmt.Sprintf("%d days, %d hours, %d minutes", days, hours, minutes)
}

func getStatusEmoji(usage, threshold float64) string {
	if usage > threshold {
		return "🔴"
	} else if usage > threshold*0.8 {
		return "🟠"
	}
	return "🟢"
}

func sendTelegramMessage(bot *tgbotapi.BotAPI, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending Telegram message: %v", err)
	}
}

type ProcessInfo struct {
	PID           int32
	CPUPercent    float64
	MemoryPercent float32
	Name          string
	User          string
}

func sendTopProcessesReport(bot *tgbotapi.BotAPI) {
	report := "⚙️ **10 Most Consuming Server Processes** ⚙️\n\n"
	procs, err := process.Processes()
	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("🔴 Error accessing process list: %v", err))
		return
	}
	var infos []ProcessInfo
	time.Sleep(time.Millisecond * 200) // Pause to get accurate CPU statistics
	for _, p := range procs {
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()
		name, _ := p.Name()
		user, _ := p.Username()
		infos = append(infos, ProcessInfo{
			PID: p.Pid, CPUPercent: cpuPercent, MemoryPercent: memPercent, Name: name, User: user,
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].CPUPercent > infos[j].CPUPercent })

	// **Table header formatting:**
	report += "`%-6s %-7s %-7s %s`\n"
	report = fmt.Sprintf(report, "PID", "CPU%", "RAM%", "NAME")
	report += "`----------------------------------`\n"

	count := 0
	for _, info := range infos {
		if info.CPUPercent > 0.01 || info.MemoryPercent > 0.01 {
			report += fmt.Sprintf("`%-6d %-7.1f %-7.1f %s`\n", info.PID, info.CPUPercent, info.MemoryPercent, info.Name)
			count++
			if count >= 10 {
				break
			}
		}
	}

	if count == 0 {
		report += "\n**Server is very idle!**\n"
	}

	report += "\n_To close a process, use `kill [PID]` in the terminal._"
	sendTelegramMessage(bot, report)
}

func sendDiskUsageReport(bot *tgbotapi.BotAPI) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		sendTelegramMessage(bot, fmt.Sprintf("🔴 Error getting partition list: %v", err))
		return
	}
	report := "💿 **Disk Space and Partition Details** 💿\n\n"

	// **Table header formatting:**
	report += "`%-15s %-8s %-8s %-8s %s`\n"
	report = fmt.Sprintf(report, "Mountpoint", "Used%", "Used", "Free", "Total")
	report += "`-----------------------------------------------`\n"

	for _, p := range partitions {
		usage, err := disk.Usage(p.Mountpoint)
		if err != nil {
			continue
		}
		gb := func(bytes uint64) string { return fmt.Sprintf("%.1fG", float64(bytes)/(1024*1024*1024)) }
		report += fmt.Sprintf("`%-15s %-8.1f %-8s %-8s %s`\n", p.Mountpoint, usage.UsedPercent, gb(usage.Used), gb(usage.Free), gb(usage.Total))
	}
	sendTelegramMessage(bot, report)
}

func sendUserReport(bot *tgbotapi.BotAPI) {
	whoOutput, err := executeCommand("who", []string{})
	currentUsers := ""
	if err == nil {
		currentUsers = strings.TrimSpace(whoOutput)
		if currentUsers == "" {
			currentUsers = "Only the bot is running."
		}
	} else {
		currentUsers = "Error executing 'who' command"
	}
	report := "👤 **User and Login Report** 👤\n\n"
	report += "👥 **Active Users (Who):**\n"
	report += fmt.Sprintf("```\n%s\n```\n", currentUsers)
	lastOutput, err := executeCommand("last", []string{"-n", "5"})
	if err == nil {
		lastUsers := strings.TrimSpace(lastOutput)
		report += "\n📜 **5 Recent Logins (Last Logins):**\n"
		report += fmt.Sprintf("```\n%s\n```\n", lastUsers)
	} else {
		report += "\n📜 **5 Recent Logins:**\n Error executing 'last' command (may require 'util-linux' package on some distributions).\n"
	}
	sendTelegramMessage(bot, report)
}

func sendInstallationGuide(bot *tgbotapi.BotAPI) {
	guide := "🔗 **Bot Installation and Update Guide**\n\n"
	guide += "This bot is a compiled Linux binary (executable file). Use one of the following methods for installation or update.\n\n"
	guide += "1. **Download Compiled File Method (Simplest)**:\n"
	guide += "_Assuming you have a Release in your GitHub_\n"
	guide += "```bash\n"
	guide += "# Download latest version (you must replace with correct URL)\n"
	guide += fmt.Sprintf("wget %s/releases/latest/download/server-monitor -O server-monitor\n", githubRepoURL)
	guide += "chmod +x server-monitor\n"
	guide += "```\n\n"
	guide += "2. **Rebuild Method (for Developers)**:\n"
	guide += "_If you've made code changes and Go is installed on the server_\n"
	guide += "```bash\n"
	guide += "# 1. Get source code\n"
	guide += fmt.Sprintf("git clone %s\n", githubRepoURL)
	guide += "cd NightLink\n"
	guide += "\n# 2. Final compile\n"
	guide += "go mod tidy\n"
	guide += "go build -o server-monitor -ldflags \"-s -w\" main.go # Using security flags\n"
	guide += "```\n\n"
	guide += "3. **Final Execution (after download/compile)**:\n"
	guide += "_To run the bot in background (using nohup is recommended)_\n"
	guide += "```bash\n"
	guide += fmt.Sprintf("nohup TELEGRAM_BOT_TOKEN=\"...\" TELEGRAM_CHAT_ID=\"...\" ./server-monitor > server_monitor.log 2>&1 &\n")
	guide += "```\n"
	sendTelegramMessage(bot, guide)
}

func sendServiceStatus(bot *tgbotapi.BotAPI) {
	// Default controllable services, can be added or removed based on server needs
	services := []string{"nginx", "docker", "mysql", "apache2", "ssh", "systemd-networkd"}
	report := "🛠️ **Status of Key Services**\n\n"
	for _, service := range services {
		status, err := executeCommand("systemctl", []string{"is-active", service})
		if err == nil && strings.TrimSpace(status) == "active" {
			report += fmt.Sprintf("🟢 **%s**: Running (Active)\n", service)
		} else if err == nil && strings.TrimSpace(status) == "inactive" {
			report += fmt.Sprintf("🟡 **%s**: Stopped (Inactive)\n", service)
		} else if strings.Contains(status, "not-found") || strings.Contains(status, "failed") || err != nil {
			// Also try checking with is-failed
			if failedStatus, _ := executeCommand("systemctl", []string{"is-failed", service}); strings.TrimSpace(failedStatus) == "failed" {
				report += fmt.Sprintf("🔴 **%s**: Failed ❌\n", service)
			} else {
				report += fmt.Sprintf("⚪ **%s**: Not installed or access error ❓\n", service)
			}
		} else {
			report += fmt.Sprintf("🟠 **%s**: Unknown status: %s\n", service, strings.TrimSpace(status))
		}
	}
	sendTelegramMessage(bot, report)
}

func sendConfirmation(bot *tgbotapi.BotAPI, action string) {
	text := ""
	data := ""
	if action == "reboot" {
		text = "⚠️ Are you sure you want to **restart** the server? This action will execute immediately!"
		data = "reboot_confirm"
	} else if action == "shutdown" {
		text = "⚠️ Are you sure you want to **shutdown** the server? You will need physical access to turn it back on!"
		data = "shutdown_confirm"
	} else if action == "cleanup" {
		text = "⚠️ Disk cleanup includes removing extra files and cache (like APT cache and temporary files). Continue?"
		data = "cleanup_confirm"
	} else {
		return // If unknown action, no message is sent
	}

	keyboard := tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("✅ Yes, I'm sure!", data),
			tgbotapi.NewInlineKeyboardButtonData("❌ No, cancel!", "cancel"),
		),
	)
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ReplyMarkup = keyboard
	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error sending confirmation message: %v", err)
	}
}

func executeSystemAction(bot *tgbotapi.BotAPI, action string) {
	var cmd *exec.Cmd
	if action == "reboot" {
		cmd = exec.Command("sudo", "reboot")
	} else if action == "shutdown" {
		cmd = exec.Command("sudo", "shutdown", "now")
	} else {
		return // Unknown action
	}

	// Execute command and capture error output
	output, err := cmd.CombinedOutput()

	if err != nil {
		errorMessage := fmt.Sprintf("🔴 **Error executing %s command:**\n\n%v\n\n**Error Output:**\n`%s`\n\nPlease ensure the bot-running user has passwordless 'sudo' access.", action, err, strings.TrimSpace(string(output)))
		sendTelegramMessage(bot, errorMessage)
		log.Printf("Error executing %s command: %v | Output: %s", action, err, string(output))
	}
	// Note: If command succeeds, bot connection will be terminated.
}

// Completed function: Disk cleanup
func diskCleanup(bot *tgbotapi.BotAPI) {
	commands := [][]string{
		{"sudo", "apt", "autoremove", "-y"},
		{"sudo", "apt", "clean"},
		{"sudo", "rm", "-rf", "/var/tmp/*"},
		{"sudo", "rm", "-rf", "/var/cache/apt/archives/partial/*"}, // Clean incomplete APT cache
		{"sudo", "journalctl", "--vacuum-time=7d"}, // Clean system logs older than 7 days
	}
	report := "🧹 **Disk Cleanup Results** 🧹\n\n"
	successCount := 0

	for _, args := range commands {
		cmdName := args[0]
		cmdArgs := args[1:]

		_, err := executeCommand(cmdName, cmdArgs)

		if err != nil {
			report += fmt.Sprintf("🔴 **Error executing %s %s:**\n`%v`\n\n", cmdName, strings.Join(cmdArgs, " "), err)
		} else {
			if strings.Contains(strings.Join(cmdArgs, " "), "autoremove") {
				report += "🟢 **Extra APT packages removed.**\n"
			} else if strings.Contains(strings.Join(cmdArgs, " "), "clean") {
				report += "🟢 **APT package cache cleared.**\n"
			} else if strings.Contains(strings.Join(cmdArgs, " "), "/var/tmp") {
				report += "🟢 **Temporary cache (/var/tmp) cleared.**\n"
			} else if strings.Contains(strings.Join(cmdArgs, " "), "/var/cache/apt/archives/partial") {
				report += "🟢 **Incomplete APT cache cleared.**\n"
			} else if strings.Contains(strings.Join(cmdArgs, " "), "journalctl") {
				report += "🟢 **Old system logs (journal) cleared.**\n"
			} else {
				report += fmt.Sprintf("🟢 **%s %s executed successfully.**\n", cmdName, strings.Join(cmdArgs, " "))
			}
			successCount++
		}
	}

	if successCount == len(commands) {
		report += "\n✅ **Cleanup operation completed successfully!**"
	} else if successCount > 0 {
		report += "\n⚠️ **Cleanup completed with some warnings/errors.**"
	} else {
		report += "\n❌ **No cleanup operations completed successfully.**"
	}

	sendTelegramMessage(bot, report)
}

func executeCommand(name string, args []string) (string, error) {
	cmd := exec.Command(name, args...)
	// Execute command and capture output (stdout and stderr)
	output, err := cmd.CombinedOutput()

	// If error occurs, return error message
	if err != nil {
		return strings.TrimSpace(string(output)), fmt.Errorf("command execution `%s %s` failed: %w", name, strings.Join(args, " "), err)
	}

	return strings.TrimSpace(string(output)), nil
}
# 🛡️ Discord Security Bot

A Discord security bot for real-time malware and phishing detection using the VirusTotal API. Features include URL scanning and file integrity verification (SHA-256).

## ✨ Features
* **🔗 URL Scanning:** Checks links for phishing and malicious content before users click them.
* **📁 File Hash Analysis:** Scans uploaded files or user-provided SHA-256 hashes against the VirusTotal database.
* **🔐 File Integrity Verification:** Compares downloaded files with original developer hashes to ensure they haven't been tampered with or infected.
* **⚡ Real-time Responses:** Fast asynchronous operations using `aiohttp` and `discord.py`.

## 🛠️ Prerequisites
Before running the bot, you need to have:
* Python 3.8 or higher installed.
* A **Discord Bot Token** (from Discord Developer Portal).
* A **VirusTotal API Key** (from VirusTotal).

## 🚀 Installation & Setup
1. Clone this repository:
   ```bash
   git clone [https://github.com/Aomsmilee/Discord-BOT.git](https://github.com/Aomsmilee/Discord-BOT.git)

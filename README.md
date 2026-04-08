# Scaurity Scanner Bot
Chatbots automatically detect cyber threats on the LINE and Discord platforms.

## Origin and importance

Currently, LINE and Discord platforms are frequently used by cybercriminals as a channel for attacks, where phishing links and malware files are sent through conversational messages. This project therefore creates a chatbot on the LINE and Discord platforms that connects to the VirusTotal API to act as a real-time tool for filtering threats from links and attachments for users.

## Scope, Objectives, and Requirements

The chatbot will work on LINE and Discord, supporting link and attachment verification. It won't send the actual file to the user, but will calculate the hash value (SHA-256), send it for analysis via the VirusTotal API, and immediately provide a risk assessment summary.

## Features

- **URL Scanning**: Checks links for phishing and malicious content before users click them.  
- **File Hash Analysis**: Scans uploaded files or user-provided SHA-256 hashes against the VirusTotal database.   
- **Multi-Platform Support**: Works on both Discord and LINE messaging platforms.  

## Supported Platforms

- Discord Bot  
- LINE Bot  

## Limitations in Discord

If any file is malicious, Discord will immediately block the upload, making it impossible to test the bot.


## Limitations in LINE
There is no feature to check if the hash value of an attached file matches the entered hash value.

## Disadvantages in LINE
If any files are large, it may take a little longer to scan.

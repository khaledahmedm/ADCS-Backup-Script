Windows Certificate Authority Backup Script (V 1.1 under construction)

This repository provides a PowerShell script that automates full backups of a Windows Certificate Authority (CA), including:

Database

CA private key and certificates

Configuration (registry, CAPolicy.inf, CertEnroll files)

Logging, error handling, and retention cleanup

Optional email notifications on success or failure

The script is designed for production use and compatible with Windows Task Scheduler for scheduled, unattended backups.

Features

Full CA Backup – Database, private key (protected by password), CA certs, registry configuration, and policy files.

Detailed Logging – Structured log file for each run with timestamps and error messages.

Automatic Cleanup – Deletes backup folders older than a configurable number of days (default: 30).

Email Alerts – Sends success/failure notifications via SMTP.

Scheduler Ready – Runs silently and non-interactively for Task Scheduler.

Prerequisites

Windows Server with AD CS (Active Directory Certificate Services) installed.

Account running the script must:

Be a CA Administrator (or have Manage CA privileges).

Have Backup Operator rights.

Sufficient permissions to write to the backup folder.

SMTP server configured and reachable (if using email).

Configuration

At the top of the script, update the USER CONFIGURATION section:

Backup Settings

$BackupRoot – Root folder for backups (e.g., C:\CABackup)

$RetentionDays – Number of days to keep old backups (default 30)

Password for Key Backup

$PlainPassword – Strong password used to protect the private key backup (PFX).

Email Settings (optional)

$EmailEnabled – Enable/disable email notifications.

$SMTPServer, $SMTPPort, $SMTPUseSSL, $SMTPAuth – SMTP configuration.

$EmailFrom, $EmailTo – Notification addresses.

Usage

Run manually (with administrative rights):

.\CABackup.ps1


Schedule with Task Scheduler:

Open Task Scheduler → Create Task.

Run whether user is logged on or not, with highest privileges.

Action:

powershell.exe -File "C:\Path\CABackup.ps1" -NonInteractive -NoProfile -ExecutionPolicy Bypass


Set a schedule (e.g., daily at midnight).

Output

Each run produces:

A dated backup folder inside $BackupRoot containing:

CA database and log files

Encrypted PFX (CA key + cert)

Registry export of CA config

CAPolicy.inf (if present)

CA cert files from CertEnroll

A log file (CA_Backup_Log.txt) documenting the backup process.

Security Notes

Keep the backup password secret.

Protect the backup folder – it contains sensitive material (private keys, config).

Store backups on a secure, separate volume (not the CA’s database drive).

Consider encrypting the backup directory or storing it in a secure location.

###############################################################################
# Windows CA Full Backup Script - Enhanced
# Description: Performs a full backup of a Certificate Authority (CA), including 
# the CA database, private key (with certificate), and configuration. Incorporates 
# error handling, logging, retention cleanup, and email notifications.
# 
# **Prerequisites**: 
# - Must be run as an administrator on the CA server (user should have CA admin rights and Backup Operator privileges).
# - The ADCSAdministration PowerShell module (installed with AD CS) provides the Backup-CARoleService cmdlet.
# - SMTP server details should be configured for email notifications (and the machine/network should allow sending mail).
###############################################################################

#### USER CONFIGURATION ####
# Backup settings
$BackupRoot    = 'C:\CABackup'            # Root directory for backups (ensure this exists or script can create it)
$RetentionDays = 30                      # Retention period for old backups (in days)

# Secure password for CA private key backup (protect the PFX). 
# *** Replace 'YourSecurePasswordHere' with a strong password or use a secure method to retrieve it. ***
$PlainPassword   = 'YourSecurePasswordHere'  
$SecurePassword  = ConvertTo-SecureString $PlainPassword -AsPlainText -Force

# Email notification settings (set $EmailEnabled = $true to send emails)
$EmailEnabled = $true
$EmailFrom    = 'CAbackup@yourdomain.com'      # Sender email address
$EmailTo      = 'admin-team@yourdomain.com'    # Recipient email (or a list of emails)
$EmailSubject = 'CA Backup Results'            # Base subject line (script will append success/failure info)
$SMTPServer   = 'smtp.yourdomain.com'          # SMTP server address
$SMTPPort     = 25                             # SMTP port (25 default, or 587 for TLS)
$SMTPUseSSL   = $false                         # $true if SSL/TLS is required (e.g., for port 587)
$SMTPAuth     = $false                         # $true if SMTP server requires authentication
$SMTPUser     = 'smtp_username'                # SMTP username (if auth is needed)
$SMTPPassword = 'smtp_password'                # SMTP password (if auth is needed)
############################

# Prepare timestamp for this run and set up paths
$DateStamp   = Get-Date -Format 'yyyyMMdd-HHmmss'    # e.g. 20250904-121500
$BackupFolder = Join-Path -Path $BackupRoot -ChildPath $DateStamp

# Log file path (inside the backup folder)
$LogFile = Join-Path -Path $BackupFolder -ChildPath "CA_Backup_Log.txt"

# Create the new backup folder
try {
    New-Item -ItemType Directory -Path $BackupFolder -Force | Out-Null
} catch {
    Write-Error "Failed to create backup folder at $BackupFolder. $_"
    return  # Exit the script if we cannot create the backup directory
}

# Initialize logging function
function Write-Log {
    [CmdletBinding()]
    param(
        [string]$Message,
        [switch]$Error
    )
    $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    if ($Error) {
        $entry = "$timestamp [ERROR] $Message"
    } else {
        $entry = "$timestamp [INFO]  $Message"
    }
    # Write to log file (append)
    Add-Content -Path $LogFile -Value $entry
}

# Start logging
Write-Log "==== Starting CA Backup: $(Get-Date) ===="

# Perform the CA backup (database + private key) using Backup-CARoleService
Write-Log "Initiating CA backup (database + private key) to $BackupFolder ..."
try {
    Backup-CARoleService -Path $BackupFolder -Password $SecurePassword -Force
    # By default, this backs up the DB and the CA key (protected by the above password).
    # -Force is used to suppress any confirmation prompts.
} catch {
    Write-Log "Backup-CARoleService failed: $($_.Exception.Message)" -Error
    $BackupSuccess = $false
    # Proceed to send failure email and skip further steps
    Write-Log "Backup process aborted due to critical failure."
    goto Cleanup
}
Write-Log "CA database and private key backup completed successfully."

# Copy CA certificate files (includes current and any previous CA certs) to backup folder
Write-Log "Copying CA certificate files (CertEnroll) ..."
$certEnrollPath = Join-Path -Path $env:windir -ChildPath "System32\CertSrv\CertEnroll\*.crt"
try {
    Copy-Item $certEnrollPath -Destination $BackupFolder -ErrorAction Stop
    Write-Log "CA certificate files copied."
} catch {
    Write-Log "Warning: Failed to copy some CA certificate files. $_" -Error
    # Non-critical: log the error and continue
}

# Copy CAPolicy.inf if it exists (this file contains CA policy settings that might be needed for restoration)
$capolicyPath = Join-Path -Path $env:windir -ChildPath "CAPolicy.inf"
if (Test-Path $capolicyPath) {
    Write-Log "Backing up CAPolicy.inf ..."
    try {
        Copy-Item $capolicyPath -Destination $BackupFolder -ErrorAction Stop
        Write-Log "CAPolicy.inf copied."
    } catch {
        Write-Log "Warning: Could not copy CAPolicy.inf. $_" -Error
        # Not critical, continue execution
    }
}

# Export the CA configuration from registry to a .reg file
# This exports all configuration under CertSvc\Configuration\<<CA Name>>
Write-Log "Exporting CA configuration from registry..."
# Construct registry export command
$caRegistryPath = 'HKLM\System\CurrentControlSet\Services\CertSvc\Configuration'
# The output .reg file name:
$regFile = Join-Path -Path $BackupFolder -ChildPath "CA-Registry-Config.reg"
# Use reg.exe to export (with /y to overwrite without prompt if needed)
$regExportCmd = "reg.exe export `"$caRegistryPath`" `"$regFile`" /y"
try {
    # Execute the reg export command
    $exitCode = (Start-Process -FilePath "reg.exe" -ArgumentList @("export", $caRegistryPath, $regFile, "/y") -PassThru -Wait).ExitCode
    if ($exitCode -ne 0) {
        throw "reg export failed with exit code $exitCode"
    }
    Write-Log "Registry configuration exported to $regFile."
} catch {
    Write-Log "Error: Failed to export CA registry configuration. $_" -Error
    # Treat this as a non-critical warning or choose to fail:
    # If you consider registry export critical for a "full backup," mark backup as failed:
    # $BackupSuccess = $false
    # For now, we log and continue.
}

# (Optional) You could include additional backup steps, such as backing up any HSM-specific files or 
# exporting a list of certificate templates if this is an Issuing CA. These are environment-specific and not always needed.

$BackupSuccess = $true   # If we reached this point without a critical failure, consider backup successful.

# -- Retention Cleanup: delete old backup folders older than $RetentionDays --
Write-Log "Cleaning up backups older than $RetentionDays days..."
# Find all dated backup folders in $BackupRoot that are past retention and delete them
try {
    Get-ChildItem -Path $BackupRoot -Directory | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetentionDays) } | ForEach-Object {
        $oldFolder = $_.FullName
        # Skip deleting if it's the current backup folder or any special folder you want to keep (e.g., an "Initial Backup").
        if ($oldFolder -ne $BackupFolder) {
            Write-Log "Removing old backup folder: $oldFolder"
            Remove-Item -Path $oldFolder -Recurse -Force
        }
    }
    Write-Log "Old backup cleanup complete."
} catch {
    Write-Log "Warning: Failed to delete some old backup folders. $_" -Error
    # Continue even if cleanup partially fails
}

# Label the result and finish logging
if ($BackupSuccess) {
    Write-Log "Backup completed SUCCESSFULLY for CA '${env:COMPUTERNAME}' on $(Get-Date)."
} else {
    Write-Log "Backup completed with ERRORS for CA '${env:COMPUTERNAME}' on $(Get-Date)."
}
Write-Log "==== End of Backup Run ===="

# -- Email Notification --
if ($EmailEnabled) {
    # Construct email subject and body based on success/failure
    $hostname = $env:COMPUTERNAME
    if ($BackupSuccess) {
        $result = "SUCCESS"
        $subj = "$EmailSubject (SUCCESS)"
        $body = "The scheduled CA backup completed successfully on $hostname.`nBackup folder: $BackupFolder`n`nPlease review the log file for details: $LogFile"
    } else {
        $result = "FAILURE"
        $subj = "$EmailSubject (FAILED)"
        $body = "One or more errors occurred during the CA backup on $hostname.`nPlease review the log file for details: $LogFile`n`n(Last error: $($error[0]))"
    }

    # Prepare the parameters for Send-MailMessage
    $mailParams = @{
        To         = $EmailTo
        From       = $EmailFrom
        Subject    = $subj
        Body       = $body
        SmtpServer = $SMTPServer
        Port       = $SMTPPort
    }
    if ($SMTPUseSSL) { $mailParams.UseSsl = $true }
    if ($SMTPAuth) {
        # Create credential object for SMTP auth
        $cred = New-Object System.Management.Automation.PSCredential($SMTPUser, (ConvertTo-SecureString $SMTPPassword -AsPlainText -Force))
        $mailParams.Credential = $cred
    }
    try {
        Send-MailMessage @mailParams
        Write-Log "Email notification ($result) sent to $EmailTo."
    } catch {
        Write-Log "Warning: Failed to send email notification. $_" -Error
    }
}

# End of script
Cleanup:

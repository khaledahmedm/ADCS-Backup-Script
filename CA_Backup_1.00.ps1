c:
cd \CABackup
$Today = Get-Date -Format MMdd
New-Item -ItemType Directory -Name $Today
Backup-CARoleService -DatabaseOnly -Path $Today
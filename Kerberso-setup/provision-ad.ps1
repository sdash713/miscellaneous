# provision-ad.ps1
# Setup AD Domain Controller & Kerberos KDC

$DomainName = "lab.local"
$Realm = "LAB.LOCAL"
$Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

# Setup hosts file entry
$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$hostsContent = @"
192.168.56.10 ad-server.lab.local ad-server
192.168.56.11 linux-server.lab.local linux-server
192.168.56.12 linux-client.lab.local linux-client
"@
if (-not (Select-String -Path $hostsPath -Pattern "linux-server")) {
    Add-Content -Path $hostsPath -Value $hostsContent
}

# 1. Install AD DS and Promote to DC if not already installed
if (-not (Get-WindowsFeature -Name AD-Domain-Services).Installed) {
    Write-Host "Installing Active Directory Domain Services..."
    Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
    
    # Write the Post-Boot configuration script
    # This will run after the DC promotion reboot to create users and export the keytab
    $PostBootScript = @"
Start-Transcript -Path C:\post-boot-ad.log
Write-Host "Waiting for Vagrant shared folder..."
while (-not (Test-Path "C:\vagrant")) {
    Start-Sleep -Seconds 5
}

Write-Host "Waiting for Active Directory to be online..."
Import-Module ActiveDirectory
while (`$true) {
    try {
        `$domain = Get-ADDomain -ErrorAction Stop
        if (`$domain -ne `$null) {
            break
        }
    } catch {
        # AD DS not ready yet
    }
    Start-Sleep -Seconds 5
}

Write-Host "AD online. Creating users..."
`$DomainName = "lab.local"
`$Realm = "LAB.LOCAL"
`$Password = ConvertTo-SecureString "Password123!" -AsPlainText -Force

# Create Test User for client logon
`$userSam = "testuser"
if (-not (Get-ADUser -Filter "SamAccountName -eq '`$userSam'")) {
    New-ADUser -Name "Test User" -SamAccountName `$userSam -UserPrincipalName "`$userSam@`$DomainName" -AccountPassword `$Password -Enabled `$true -PasswordNeverExpires `$true
}

# Create Linux Server Service Account
`$svcSam = "linux-srv-svc"
if (-not (Get-ADUser -Filter "SamAccountName -eq '`$svcSam'")) {
    New-ADUser -Name "Linux Server Service" -SamAccountName `$svcSam -UserPrincipalName "`$svcSam@`$DomainName" -AccountPassword `$Password -Enabled `$true -PasswordNeverExpires `$true
    Set-ADUser -Identity `$svcSam -KerberosEncryptionType AES128,AES256
}

# Generate and Export the Keytab file for SSH GSSAPI authentication
Write-Host "Generating Keytab file..."
`$keytabPath = "C:\vagrant\linux-server.keytab"

& ktpass.exe /out `$keytabPath /princ "host/linux-server.lab.local@`$Realm" /mapuser "`$svcSam@`$DomainName" /mapOp set /pass "Password123!" /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL

Stop-Transcript
# Cleanup the scheduled task so it only runs once
Unregister-ScheduledTask -TaskName "PostBootADSetup" -Confirm:`$false
"@

    $PostBootScriptPath = "C:\post-boot-ad.ps1"
    Set-Content -Path $PostBootScriptPath -Value $PostBootScript
    
    # Register Scheduled Task to run at Startup as SYSTEM
    Write-Host "Registering post-boot AD config task..."
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File C:\post-boot-ad.ps1"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName "PostBootADSetup" -Action $action -Trigger $trigger -Principal $principal

    # Promote to Domain Controller (triggers auto-reboot)
    Write-Host "Configuring AD DS Forest and promoting DC (this will reboot the server)..."
    Import-Module ADDSDeployment
    Install-ADDSForest `
        -CreateDnsDelegation:$false `
        -DatabasePath "C:\Windows\NTDS" `
        -DomainMode "WinThreshold" `
        -DomainName $DomainName `
        -DomainNetbiosName "LAB" `
        -ForestMode "WinThreshold" `
        -InstallDns:$true `
        -LogPath "C:\Windows\NTDS" `
        -NoRebootOnCompletion:$true `
        -SysvolPath "C:\Windows\SYSVOL" `
        -SafeModeAdministratorPassword $Password `
        -Force:$true
} else {
    Write-Host "Active Directory Domain Services already installed. Checking if keytab needs to be generated..."
    
    # Check if Active Directory is online
    Import-Module ActiveDirectory
    $domain = Get-ADDomain -ErrorAction SilentlyContinue
    if ($domain -ne $null) {
        # Create Test User for client logon
        $userSam = "testuser"
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$userSam'")) {
            New-ADUser -Name "Test User" -SamAccountName $userSam -UserPrincipalName "$userSam@$DomainName" -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true
        }

        # Create Linux Server Service Account
        $svcSam = "linux-srv-svc"
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$svcSam'")) {
            New-ADUser -Name "Linux Server Service" -SamAccountName $svcSam -UserPrincipalName "$svcSam@$DomainName" -AccountPassword $Password -Enabled $true -PasswordNeverExpires $true
        }
        Set-ADUser -Identity $svcSam -KerberosEncryptionType AES128,AES256

        # Generate and Export the Keytab file for SSH GSSAPI authentication
        $keytabPath = "C:\vagrant\linux-server.keytab"
        if (-not (Test-Path $keytabPath)) {
            Write-Host "Generating Keytab file..."
            & ktpass.exe /out $keytabPath /princ "host/linux-server.lab.local@$Realm" /mapuser "$svcSam@$DomainName" /mapOp set /pass "Password123!" /crypto AES256-SHA1 /ptype KRB5_NT_PRINCIPAL
        } else {
            Write-Host "Keytab file already exists."
        }
    } else {
        Write-Host "Active Directory is not fully online yet."
    }
}

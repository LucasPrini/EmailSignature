# GPO Deployment Instructions for Email Signature System

## Overview
This solution deploys email signature assets via Group Policy to solve email client compatibility issues while maintaining exact visual fidelity to the official template.

## What This Solves
- **Email Client Compatibility**: Local file:// references work in all email clients
- **Asset Management**: Centralized deployment of logos and icons
- **Visual Fidelity**: Exact copy of PowerPoint template with only automated fields
- **Enterprise Safety**: All existing safety checks preserved

## Deployment Structure

```
C:\ProgramData\ModularDTC\EmailSignature\
├── Assets\
│   ├── modular-logo.png           # Company logo (13.7 KB)
│   ├── whatsapp-icon.png          # WhatsApp icon (30.6 KB)
│   └── phone-icon.png             # Phone icon (24.4 KB)
├── SignatureTemplate-GPO.html     # Template with local asset references
├── Update-EmailSignature-GPO.ps1  # Modified script with GPO verification
└── GPO-DEPLOYMENT-INSTRUCTIONS.md # This file
```

## GPO Deployment Steps

### Step 1: Create Group Policy Object

1. Open **Group Policy Management Console (GPMC)**
2. Right-click your target OU → **Create a GPO in this domain, and Link it here**
3. Name: `ModularDTC Email Signature Deployment`
4. Edit the new GPO

### Step 2: Deploy Asset Directory via GPO

**Option A: File System Policy (Recommended)**

1. In Group Policy Editor, navigate to:
   ```
   Computer Configuration → Preferences → Windows Settings → Files
   ```

2. Right-click → **New** → **File**

3. Configure each asset file:
   - **Source file**: `\\your-domain-server\share\ModularDTC\EmailSignature\Assets\modular-logo.png`
   - **Destination file**: `C:\ProgramData\ModularDTC\EmailSignature\Assets\modular-logo.png`
   - **Action**: Replace

4. Repeat for all assets:
   - `whatsapp-icon.png`
   - `phone-icon.png`
   - `SignatureTemplate-GPO.html`
   - `Update-EmailSignature-GPO.ps1`

**Option B: Startup Script Deployment**

1. Place all files on a network share accessible by Domain Computers
2. Create deployment script `Deploy-SignatureAssets.ps1`:

```powershell
# Deploy-SignatureAssets.ps1
$SourcePath = "\\your-domain-server\share\ModularDTC\EmailSignature"
$DestPath = "C:\ProgramData\ModularDTC\EmailSignature"

try {
    # Create destination directory
    if (-not (Test-Path $DestPath)) {
        New-Item -Path $DestPath -ItemType Directory -Force
        New-Item -Path "$DestPath\Assets" -ItemType Directory -Force
    }

    # Copy all files
    Copy-Item "$SourcePath\*" $DestPath -Recurse -Force

    # Set permissions (optional)
    $acl = Get-Acl $DestPath
    $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($accessRule)
    Set-Acl $DestPath $acl

    Write-EventLog -LogName Application -Source "ModularDTC Deployment" -EventId 1001 -Message "Email signature assets deployed successfully to $DestPath"
}
catch {
    Write-EventLog -LogName Application -Source "ModularDTC Deployment" -EventId 1002 -EntryType Error -Message "Failed to deploy email signature assets: $($_.Exception.Message)"
}
```

3. Add as Computer Startup Script:
   ```
   Computer Configuration → Policies → Windows Settings → Scripts → Startup
   ```

### Step 3: Configure Script Execution Policy

1. In Group Policy Editor:
   ```
   Computer Configuration → Policies → Administrative Templates → Windows Components → Windows PowerShell
   ```

2. Enable **Turn on Script Execution**
3. Set to **Allow local scripts and remote signed scripts**

### Step 4: Deploy User Script via GPO

**Option A: Logon Script**
```
User Configuration → Policies → Windows Settings → Scripts → Logon
```

**Option B: Scheduled Task**
1. Navigate to:
   ```
   Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks
   ```

2. Create new task:
   - **Name**: ModularDTC Email Signature Update
   - **User**: NT AUTHORITY\SYSTEM
   - **Trigger**: At user logon
   - **Action**: `powershell.exe -ExecutionPolicy Bypass -File "C:\ProgramData\ModularDTC\EmailSignature\Update-EmailSignature-GPO.ps1" -UserName "$env:USERNAME"`

## Security Considerations

### File Permissions
```powershell
# Set secure permissions
icacls "C:\ProgramData\ModularDTC" /grant "Domain Users:(OI)(CI)R" /T
icacls "C:\ProgramData\ModularDTC" /grant "Administrators:(OI)(CI)F" /T
icacls "C:\ProgramData\ModularDTC" /grant "SYSTEM:(OI)(CI)F" /T
```

### Registry Access
- Script uses same enterprise-safe Outlook registry checks
- Only updates signatures for verified domain email accounts
- Skips personal email configurations

## Testing Process

### Phase 1: Test OU Deployment
1. Create test OU with limited users
2. Deploy GPO to test OU only
3. Verify asset deployment on test machines
4. Test script execution with test accounts

### Phase 2: Verification Commands
```powershell
# Verify asset deployment
Test-Path "C:\ProgramData\ModularDTC\EmailSignature\Assets\modular-logo.png"
Test-Path "C:\ProgramData\ModularDTC\EmailSignature\SignatureTemplate-GPO.html"

# Test signature generation
& "C:\ProgramData\ModularDTC\EmailSignature\Update-EmailSignature-GPO.ps1" -UserName "testuser" -TestMode

# Check event logs
Get-EventLog -LogName Application -Source "ModularDTC Deployment" -Newest 10
```

### Phase 3: Gradual Rollout
1. Deploy to pilot group (10-20 users)
2. Monitor for 1 week
3. Deploy to department level
4. Full organization rollout

## Monitoring and Maintenance

### Event Log Monitoring
The script logs to Windows Event Log:
- **Source**: ModularDTC Deployment
- **Success**: Event ID 1001
- **Failure**: Event ID 1002

### Health Check Script
```powershell
# Check-SignatureDeployment.ps1
$AssetPath = "C:\ProgramData\ModularDTC\EmailSignature\Assets"
$RequiredAssets = @("modular-logo.png", "whatsapp-icon.png", "phone-icon.png")

foreach ($asset in $RequiredAssets) {
    $path = Join-Path $AssetPath $asset
    if (Test-Path $path) {
        $size = (Get-Item $path).Length
        Write-Host "✓ $asset ($size bytes)" -ForegroundColor Green
    } else {
        Write-Host "✗ $asset MISSING" -ForegroundColor Red
    }
}
```

## Troubleshooting

### Common Issues

**Assets Not Deploying**
- Check network share permissions
- Verify GPO replication
- Run `gpupdate /force` on client

**Script Not Executing**
- Check PowerShell execution policy
- Verify script path in GPO
- Check event logs for errors

**Signatures Not Appearing**
- Verify email account matches AD
- Check Outlook profile configuration
- Restart Outlook/Thunderbird

**File Access Denied**
- Check NTFS permissions on ProgramData folder
- Verify user has read access to assets
- Run deployment as Administrator

### Verification Commands
```powershell
# Check GPO application
gpresult /r /scope:computer

# Test asset access
Get-ChildItem "C:\ProgramData\ModularDTC\EmailSignature\Assets\"

# Test template loading
Get-Content "C:\ProgramData\ModularDTC\EmailSignature\SignatureTemplate-GPO.html" -Raw

# Manual script execution
& "C:\ProgramData\ModularDTC\EmailSignature\Update-EmailSignature-GPO.ps1" -UserName $env:USERNAME -TestMode
```

## Update Process

### Asset Updates
1. Replace files on network share
2. GPO will automatically sync new versions
3. Users get updates on next login/refresh

### Template Updates
1. Modify `SignatureTemplate-GPO.html`
2. Maintain file:// asset references
3. Test with single user before deployment
4. Update via GPO file policy

### Script Updates
1. Test changes thoroughly in isolated environment
2. Backup current script version
3. Deploy via GPO file replacement
4. Monitor event logs for issues

## Production Checklist

- [ ] Network share accessible by all target computers
- [ ] All asset files present and correct sizes
- [ ] GPO created and linked to correct OU
- [ ] File deployment policies configured
- [ ] Script execution policy enabled
- [ ] Permissions set correctly
- [ ] Test deployment completed successfully
- [ ] Event log monitoring configured
- [ ] Rollback plan documented
- [ ] Support team trained on troubleshooting

## Success Criteria

1. **Asset Deployment**: All PNG files deployed to 100% of target machines
2. **Template Availability**: SignatureTemplate-GPO.html accessible on all machines
3. **Script Execution**: Update-EmailSignature-GPO.ps1 runs without errors
4. **Visual Fidelity**: Generated signatures match PowerPoint template exactly
5. **Email Integration**: Signatures appear correctly in Outlook/Thunderbird
6. **Safety Verification**: Only domain email accounts affected

This GPO deployment solution maintains the exact visual design while ensuring enterprise-grade reliability and compatibility across all email clients.
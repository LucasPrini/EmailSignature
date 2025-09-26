#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    Updates email signatures using GPO-deployed assets for maximum compatibility

.DESCRIPTION
    Production script designed for GPO deployment with centralized assets.
    Uses absolute paths to deployed assets for perfect email client compatibility.

.PARAMETER UserName
    Specific username to update (optional, if not provided prompts for input)

.PARAMETER TemplateFile
    Path to HTML signature template file (defaults to GPO location)

.PARAMETER OutputPath
    Path where signature files will be saved

.PARAMETER LogFile
    Path to log file for detailed error tracking

.PARAMETER TestMode
    Enable testing mode with Thunderbird (for development/testing only)

.EXAMPLE
    .\Update-EmailSignature-GPO.ps1 -UserName "jsmith"

.EXAMPLE
    .\Update-EmailSignature-GPO.ps1 -UserName "jsmith" -TestMode
#>

param(
    [string]$UserName,
    [string]$TemplateFile = "C:\ProgramData\ModularDTC\EmailSignature\SignatureTemplate-GPO.html",
    [string]$OutputPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Signatures",
    [string]$LogFile,
    [switch]$TestMode
)

# Error tracking
$script:ErrorCount = 0
$script:WarningCount = 0

# Script variables for Thunderbird signature assignment
$script:CurrentSignatureHTML = ""
$script:CurrentSignatureName = ""

# GPO Asset verification
$script:AssetBasePath = "C:\ProgramData\ModularDTC\EmailSignature\Assets"
$script:RequiredAssets = @(
    "modular-logo.png",
    "whatsapp-icon.png",
    "phone-icon.png"
)

# Logging function
function Write-LogMessage {
    param(
        [string]$Message,
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"

    switch ($Level) {
        'Info'    { Write-Host $Message -ForegroundColor White }
        'Success' { Write-Host $Message -ForegroundColor Green }
        'Warning' { Write-Warning $Message; $script:WarningCount++ }
        'Error'   { Write-Error $Message; $script:ErrorCount++ }
        'Test'    { Write-Host "[TEST] $Message" -ForegroundColor Yellow }
        'GPO'     { Write-Host "[GPO] $Message" -ForegroundColor Cyan }
    }

    if ($LogFile) {
        try {
            $logDir = Split-Path $LogFile -Parent
            if ($logDir -and -not (Test-Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            Add-Content -Path $LogFile -Value $logEntry -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warning "Failed to write to log file: $LogFile"
        }
    }
}

# Function to verify GPO asset deployment
function Test-GPOAssetDeployment {
    Write-LogMessage "Verifying GPO asset deployment..." -Level GPO

    if (-not (Test-Path $script:AssetBasePath)) {
        Write-LogMessage "CRITICAL: GPO asset directory not found: $script:AssetBasePath" -Level Error
        Write-LogMessage "SOLUTION: Deploy assets via GPO to all endpoints" -Level Error
        return $false
    }

    $missingAssets = @()
    foreach ($asset in $script:RequiredAssets) {
        $assetPath = Join-Path $script:AssetBasePath $asset
        if (-not (Test-Path $assetPath)) {
            $missingAssets += $asset
        } else {
            Write-LogMessage "Asset verified: $asset" -Level GPO
        }
    }

    if ($missingAssets.Count -gt 0) {
        Write-LogMessage "CRITICAL: Missing GPO assets: $($missingAssets -join ', ')" -Level Error
        Write-LogMessage "SOLUTION: Redeploy asset package via GPO" -Level Error
        return $false
    }

    Write-LogMessage "All GPO assets verified successfully" -Level Success
    return $true
}

# Function to get user data from AD with error handling
function Get-UserADData {
    param([string]$SamAccountName)

    Write-LogMessage "Fetching AD data for user: $SamAccountName" -Level Info

    try {
        $user = Get-ADUser -Identity $SamAccountName -Properties DisplayName, Title, Department,
                          TelephoneNumber, MobilePhone, EmailAddress, StreetAddress,
                          City, State, PostalCode, Company -ErrorAction Stop

        Write-LogMessage "Successfully retrieved AD data for: $($user.DisplayName)" -Level Success

        # Check for missing critical fields
        if (-not $user.DisplayName) {
            Write-LogMessage "WARNING: DisplayName is empty for user $SamAccountName" -Level Warning
        }
        if (-not $user.EmailAddress) {
            Write-LogMessage "WARNING: EmailAddress is empty for user $SamAccountName" -Level Warning
        }

        return $user
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        Write-LogMessage "User not found in Active Directory: $SamAccountName" -Level Error
        Write-LogMessage "TROUBLESHOOTING: Verify username spelling and domain membership" -Level Warning
        return $null
    }
    catch {
        Write-LogMessage "Could not retrieve AD data for user: $SamAccountName" -Level Error
        Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
        Write-LogMessage "TROUBLESHOOTING: Check AD connectivity and permissions" -Level Warning
        return $null
    }
}

# Function to replace template placeholders
function Update-SignatureTemplate {
    param(
        [string]$Template,
        [object]$UserData
    )

    if ([string]::IsNullOrEmpty($Template)) {
        Write-LogMessage "Template is empty - cannot process" -Level Error
        return $null
    }

    $updatedTemplate = $Template

    # Define placeholder mappings
    $placeholders = @{
        '{{DisplayName}}' = if ($UserData.DisplayName) { $UserData.DisplayName } else { "" }
        '{{Title}}' = if ($UserData.Title) { $UserData.Title } else { "" }
        '{{Department}}' = if ($UserData.Department) { $UserData.Department } else { "" }
        '{{TelephoneNumber}}' = if ($UserData.TelephoneNumber) { $UserData.TelephoneNumber } else { "" }
        '{{MobilePhone}}' = if ($UserData.MobilePhone) { $UserData.MobilePhone } else { "" }
        '{{EmailAddress}}' = if ($UserData.EmailAddress) { $UserData.EmailAddress } else { "" }
        '{{StreetAddress}}' = if ($UserData.StreetAddress) { $UserData.StreetAddress } else { "" }
        '{{City}}' = if ($UserData.City) { $UserData.City } else { "" }
        '{{State}}' = if ($UserData.State) { $UserData.State } else { "" }
        '{{PostalCode}}' = if ($UserData.PostalCode) { $UserData.PostalCode } else { "" }
        '{{Company}}' = if ($UserData.Company) { $UserData.Company } else { "" }
    }

    # Replace each placeholder
    foreach ($placeholder in $placeholders.GetEnumerator()) {
        try {
            $value = if ($placeholder.Value) { $placeholder.Value } else { "" }
            $updatedTemplate = $updatedTemplate -replace [regex]::Escape($placeholder.Key), $value
        }
        catch {
            Write-LogMessage "Failed to replace $($placeholder.Key): $($_.Exception.Message)" -Level Warning
        }
    }

    return $updatedTemplate
}

# PRODUCTION: Enterprise-safe Outlook registry function
function Set-OutlookDefaultSignature {
    param(
        [string]$SignatureName,
        [string]$UserEmail,
        [string]$UserName
    )

    if ($TestMode) {
        Write-LogMessage "TEST MODE: Skipping Outlook registry (production feature)" -Level Test
        Test-ThunderbirdIntegration -SignatureName $SignatureName -UserEmail $UserEmail -UserName $UserName
        return
    }

    Write-LogMessage "PRODUCTION: Checking Outlook configuration for registry update..." -Level Info

    # Skip if no email address
    if ([string]::IsNullOrEmpty($UserEmail)) {
        Write-LogMessage "SAFETY: No email address found - skipping registry update to prevent personal account modification" -Level Warning
        return
    }

    # Detect Outlook installation and version
    $outlookVersions = @()
    $officeRegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook",  # Office 2016/2019/365
        "HKLM:\SOFTWARE\Microsoft\Office\15.0\Outlook",  # Office 2013
        "HKLM:\SOFTWARE\Microsoft\Office\14.0\Outlook",  # Office 2010
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\16.0\Outlook",  # 32-bit on 64-bit
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\15.0\Outlook",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\14.0\Outlook"
    )

    foreach ($path in $officeRegistryPaths) {
        if (Test-Path $path) {
            $version = $path.Split('\')[4]  # Extract version number
            $outlookVersions += $version
            Write-LogMessage "SAFETY: Detected Outlook version $version" -Level Info
        }
    }

    if ($outlookVersions.Count -eq 0) {
        Write-LogMessage "SAFETY: No Outlook installation detected - skipping registry update" -Level Warning
        Write-LogMessage "This is safer for enterprise deployment to avoid affecting non-domain users" -Level Info
        return
    }

    # Check each detected version
    foreach ($version in $outlookVersions) {
        try {
            $userRegPath = "HKCU:\Software\Microsoft\Office\$version\Common\MailSettings"

            if (-not (Test-Path $userRegPath)) {
                Write-LogMessage "SAFETY: User hasn't configured Outlook $version yet - skipping to prevent profile creation" -Level Warning
                continue
            }

            # CRITICAL SAFETY: Verify email account matches
            $emailMatch = Test-OutlookEmailMatch -UserEmail $UserEmail -OutlookVersion $version
            if (-not $emailMatch) {
                Write-LogMessage "SAFETY: User's AD email ($UserEmail) not found in Outlook profiles - skipping registry update" -Level Warning
                Write-LogMessage "This prevents overwriting personal email signatures" -Level Warning
                continue
            }

            # Safe to update registry
            Write-LogMessage "SAFETY: Email verification passed - updating Outlook $version registry" -Level Success
            Set-ItemProperty -Path $userRegPath -Name "NewSignature" -Value $SignatureName -Force -ErrorAction Stop
            Set-ItemProperty -Path $userRegPath -Name "ReplySignature" -Value $SignatureName -Force -ErrorAction Stop

            Write-LogMessage "✓ Registry updated for Outlook $version with signature: $SignatureName" -Level Success
            Write-LogMessage "✓ Email account verified: $UserEmail" -Level Success
            return

        }
        catch {
            Write-LogMessage "SAFETY: Could not safely update Outlook $version registry: $($_.Exception.Message)" -Level Warning
        }
    }

    Write-LogMessage "SAFETY: Registry update completed with enterprise safety checks" -Level Info
}

# PRODUCTION: Function to verify email account exists in Outlook profiles
function Test-OutlookEmailMatch {
    param(
        [string]$UserEmail,
        [string]$OutlookVersion
    )

    try {
        # Check multiple locations where email might be stored
        $profilePaths = @(
            "HKCU:\Software\Microsoft\Office\$OutlookVersion\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676",
            "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows Messaging Subsystem\Profiles\Outlook"
        )

        foreach ($profilePath in $profilePaths) {
            if (Test-Path $profilePath) {
                # Search for email address in profile data
                $subKeys = Get-ChildItem $profilePath -Recurse -ErrorAction SilentlyContinue
                foreach ($key in $subKeys) {
                    try {
                        $properties = Get-ItemProperty $key.PSPath -ErrorAction SilentlyContinue
                        if ($properties) {
                            foreach ($prop in $properties.PSObject.Properties) {
                                if ($prop.Value -like "*$UserEmail*") {
                                    Write-LogMessage "SAFETY: Found matching email in Outlook profile" -Level Success
                                    return $true
                                }
                            }
                        }
                    }
                    catch {
                        # Ignore individual key access errors
                        continue
                    }
                }
            }
        }

        Write-LogMessage "SAFETY: User email $UserEmail not found in Outlook profiles" -Level Warning
        return $false

    }
    catch {
        Write-LogMessage "SAFETY: Error during email verification: $($_.Exception.Message)" -Level Warning
        Write-LogMessage "SAFETY: Defaulting to safe mode - skipping registry update" -Level Warning
        return $false
    }
}

# TESTING: Thunderbird integration for testing email verification logic
function Test-ThunderbirdIntegration {
    param(
        [string]$SignatureName,
        [string]$UserEmail,
        [string]$UserName
    )

    Write-LogMessage "TEST MODE: Using Thunderbird for testing email verification logic" -Level Test

    # Skip if no email address (same safety as production)
    if ([string]::IsNullOrEmpty($UserEmail)) {
        Write-LogMessage "TEST SAFETY: No email address found - would skip in production" -Level Test
        return
    }

    # Check for Thunderbird installation
    $thunderbirdPaths = @(
        "$env:PROGRAMFILES\Mozilla Thunderbird\thunderbird.exe",
        "${env:PROGRAMFILES(X86)}\Mozilla Thunderbird\thunderbird.exe",
        "$env:APPDATA\Thunderbird",
        "$env:APPDATA\Mozilla\Thunderbird"
    )

    $thunderbirdFound = $false
    foreach ($path in $thunderbirdPaths) {
        if (Test-Path $path) {
            $thunderbirdFound = $true
            Write-LogMessage "TEST: Found Thunderbird at: $path" -Level Test
            break
        }
    }

    if (-not $thunderbirdFound) {
        Write-LogMessage "TEST: Thunderbird not found - install for testing" -Level Test
        Write-LogMessage "TEST: In production, this would check for Outlook installation" -Level Test
        return
    }

    # Test email account verification with Thunderbird profiles
    $profilesPath = "$env:APPDATA\Thunderbird\profiles.ini"
    if (Test-Path $profilesPath) {
        Write-LogMessage "TEST: Found Thunderbird profiles, checking for email match..." -Level Test

        try {
            $profileContent = Get-Content $profilesPath -ErrorAction Stop
            Write-LogMessage "TEST: Thunderbird profiles found, simulating email verification" -Level Test

            # In a real scenario, we'd parse prefs.js files in profile folders
            # For testing, we'll simulate the verification
            $emailMatch = Test-ThunderbirdEmailMatch -UserEmail $UserEmail

            if ($emailMatch) {
                Write-LogMessage "TEST PASSED: Email verification would succeed in production" -Level Success
                Write-LogMessage "TEST: Would update Outlook registry with signature: $SignatureName" -Level Test
                Write-LogMessage "TEST: Would verify email: $UserEmail" -Level Test
            } else {
                Write-LogMessage "TEST SAFETY: Email not found - would skip in production to protect personal accounts" -Level Test
            }
        }
        catch {
            Write-LogMessage "TEST: Could not read Thunderbird profiles: $($_.Exception.Message)" -Level Test
        }
    } else {
        Write-LogMessage "TEST: Thunderbird installed but no profiles found" -Level Test
        Write-LogMessage "TEST: This simulates Outlook installed but not configured" -Level Test
    }
}

# TESTING: Find and configure Thunderbird signature for matching email
function Test-ThunderbirdEmailMatch {
    param([string]$UserEmail)

    try {
        # Look for Thunderbird profile directories
        $thunderbirdProfile = "$env:APPDATA\Thunderbird\Profiles"
        if (Test-Path $thunderbirdProfile) {
            $profileDirs = Get-ChildItem $thunderbirdProfile -Directory -ErrorAction SilentlyContinue

            foreach ($profileDir in $profileDirs) {
                $prefsFile = Join-Path $profileDir.FullName "prefs.js"
                if (Test-Path $prefsFile) {
                    $prefsContent = Get-Content $prefsFile -ErrorAction SilentlyContinue
                    if ($prefsContent -and ($prefsContent | Where-Object { $_ -like "*$UserEmail*" })) {
                        Write-LogMessage "TEST: Found matching email in Thunderbird profile: $($profileDir.Name)" -Level Test

                        # Actually assign the signature to this email account
                        $signatureAssigned = Set-ThunderbirdSignature -ProfilePath $profileDir.FullName -UserEmail $UserEmail -SignatureHTML $script:CurrentSignatureHTML -SignatureName $script:CurrentSignatureName

                        if ($signatureAssigned) {
                            Write-LogMessage "TEST: Successfully assigned HTML signature to $UserEmail in Thunderbird" -Level Success
                            return $true
                        } else {
                            Write-LogMessage "TEST: Found email but failed to assign signature" -Level Warning
                            return $true  # Email was found, assignment just failed
                        }
                    }
                }
            }
        }

        Write-LogMessage "TEST: Email $UserEmail not found in Thunderbird profiles" -Level Test
        return $false
    }
    catch {
        Write-LogMessage "TEST: Error during Thunderbird email check: $($_.Exception.Message)" -Level Test
        return $false
    }
}

# TESTING: Actually set Thunderbird signature for the matching email account
function Set-ThunderbirdSignature {
    param(
        [string]$ProfilePath,
        [string]$UserEmail,
        [string]$SignatureHTML,
        [string]$SignatureName
    )

    try {
        Write-LogMessage "TEST: Configuring Thunderbird signature for $UserEmail" -Level Test

        # Close Thunderbird if running (signature changes require restart)
        $thunderbirdProcess = Get-Process -Name "thunderbird" -ErrorAction SilentlyContinue
        if ($thunderbirdProcess) {
            Write-LogMessage "TEST: Thunderbird is running - signature changes require Thunderbird restart" -Level Warning
        }

        $prefsFile = Join-Path $ProfilePath "prefs.js"
        if (-not (Test-Path $prefsFile)) {
            Write-LogMessage "TEST: prefs.js not found in profile path" -Level Warning
            return $false
        }

        # Read current preferences
        $prefsContent = Get-Content $prefsFile -Encoding UTF8

        # Create signature file in profile directory
        $signatureFileName = "$SignatureName.html"
        $signatureFilePath = Join-Path $ProfilePath $signatureFileName

        try {
            $SignatureHTML | Out-File -FilePath $signatureFilePath -Encoding UTF8 -Force
            Write-LogMessage "TEST: Signature file created at: $signatureFilePath" -Level Test
        }
        catch {
            Write-LogMessage "TEST: Failed to create signature file: $($_.Exception.Message)" -Level Warning
            return $false
        }

        # Find the mail account configuration for this email
        $accountLines = $prefsContent | Where-Object { $_ -like "*$UserEmail*" -and $_ -like "*user_pref*" }

        if ($accountLines.Count -eq 0) {
            Write-LogMessage "TEST: No account configuration found for $UserEmail in prefs.js" -Level Warning
            return $false
        }

        # Extract account identifiers (improved regex)
        $accountIds = @()
        foreach ($line in $accountLines) {
            if ($line -match 'mail\.account\.([^\.]+)\.') {
                $accountIds += $matches[1]
            } elseif ($line -match 'mail\.identity\.([^\.]+)\.') {
                $accountIds += $matches[1]
            }
        }

        $accountIds = $accountIds | Sort-Object -Unique
        Write-LogMessage "TEST: Found account IDs: $($accountIds -join ', ')" -Level Test

        if ($accountIds.Count -eq 0) {
            Write-LogMessage "TEST: Could not extract account ID from preferences" -Level Warning
            return $false
        }

        # Prioritize longer account IDs (id1, id2, etc. over single letters)
        $accountId = $accountIds | Sort-Object {$_.Length} -Descending | Select-Object -First 1
        Write-LogMessage "TEST: Using account ID: $accountId (from: $($accountIds -join ', '))" -Level Test

        # Prepare new signature preferences
        $newPrefs = @()
        $signaturePrefsAdded = $false

        # Signature preferences to add/update
        $signatureSettings = @{
            "mail.identity.$accountId.htmlSigText" = $SignatureHTML
            "mail.identity.$accountId.htmlSigFormat" = "true"
            "mail.identity.$accountId.sig_file" = $signatureFilePath
            "mail.identity.$accountId.attach_signature" = "true"
            "mail.identity.$accountId.compose_html" = "true"
        }

        Write-LogMessage "TEST: Will update signature settings for account: $accountId" -Level Test

        # Process existing preferences and update signature settings
        foreach ($line in $prefsContent) {
            $lineProcessed = $false

            foreach ($setting in $signatureSettings.GetEnumerator()) {
                $prefPattern = "user_pref(`"$($setting.Key)`","
                if ($line -like "*$prefPattern*") {
                    # Update existing preference
                    if ($setting.Key -eq "mail.identity.$accountId.htmlSigText") {
                        $escapedHTML = $setting.Value -replace '"', '\"' -replace "`n", "\\n" -replace "`r", ""
                        $newPrefs += "user_pref(`"$($setting.Key)`", `"$escapedHTML`");"
                    } elseif ($setting.Key -eq "mail.identity.$accountId.sig_file") {
                        $escapedPath = $setting.Value -replace '\\', '\\\\' -replace '"', '\"'
                        $newPrefs += "user_pref(`"$($setting.Key)`", `"$escapedPath`");"
                    } elseif ($setting.Value -eq "true") {
                        $newPrefs += "user_pref(`"$($setting.Key)`", true);"
                    } else {
                        $newPrefs += "user_pref(`"$($setting.Key)`", `"$($setting.Value)`");"
                    }
                    $lineProcessed = $true
                    $signaturePrefsAdded = $true
                    Write-LogMessage "TEST: Updated preference: $($setting.Key)" -Level Test
                    break
                }
            }

            if (-not $lineProcessed) {
                $newPrefs += $line
            }
        }

        # Add missing signature preferences
        if (-not $signaturePrefsAdded) {
            Write-LogMessage "TEST: Adding new signature preferences for account $accountId" -Level Test
            foreach ($setting in $signatureSettings.GetEnumerator()) {
                if ($setting.Key -eq "mail.identity.$accountId.htmlSigText") {
                    $escapedHTML = $setting.Value -replace '"', '\"' -replace "`n", "\\n" -replace "`r", ""
                    $newPrefs += "user_pref(`"$($setting.Key)`", `"$escapedHTML`");"
                } elseif ($setting.Key -eq "mail.identity.$accountId.sig_file") {
                    $escapedPath = $setting.Value -replace '\\', '\\\\' -replace '"', '\"'
                    $newPrefs += "user_pref(`"$($setting.Key)`", `"$escapedPath`");"
                } elseif ($setting.Value -eq "true") {
                    $newPrefs += "user_pref(`"$($setting.Key)`", true);"
                } else {
                    $newPrefs += "user_pref(`"$($setting.Key)`", `"$($setting.Value)`");"
                }
                Write-LogMessage "TEST: Added preference: $($setting.Key)" -Level Test
            }
        }

        # Backup original prefs.js
        $backupFile = "$prefsFile.backup.$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        try {
            Copy-Item $prefsFile $backupFile -Force
            Write-LogMessage "TEST: Backed up original prefs.js to: $backupFile" -Level Test
        }
        catch {
            Write-LogMessage "TEST: Warning - Could not backup prefs.js: $($_.Exception.Message)" -Level Warning
        }

        # Write updated preferences
        try {
            $newPrefs | Out-File -FilePath $prefsFile -Encoding UTF8 -Force
            Write-LogMessage "TEST: Updated prefs.js with signature configuration" -Level Success

            Write-LogMessage "TEST: SIGNATURE ASSIGNMENT COMPLETE!" -Level Success
            Write-LogMessage "TEST: Email: $UserEmail" -Level Success
            Write-LogMessage "TEST: Signature file: $signatureFilePath" -Level Success
            Write-LogMessage "TEST: Restart Thunderbird to see the signature" -Level Success

            return $true
        }
        catch {
            Write-LogMessage "TEST: Failed to update prefs.js: $($_.Exception.Message)" -Level Warning

            # Restore backup if update failed
            if (Test-Path $backupFile) {
                try {
                    Copy-Item $backupFile $prefsFile -Force
                    Write-LogMessage "TEST: Restored original prefs.js from backup" -Level Warning
                }
                catch {
                    Write-LogMessage "TEST: CRITICAL: Could not restore backup! Manual intervention may be needed." -Level Error
                }
            }
            return $false
        }

    }
    catch {
        Write-LogMessage "TEST: Error setting Thunderbird signature: $($_.Exception.Message)" -Level Warning
        return $false
    }
}

# Function to deploy signature with error handling
function Deploy-Signature {
    param(
        [string]$SignatureHTML,
        [string]$UserName,
        [string]$OutputPath,
        [object]$UserData
    )

    try {
        # Create signatures directory if it doesn't exist
        if (-not (Test-Path $OutputPath)) {
            try {
                New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
                Write-LogMessage "Created directory: $OutputPath" -Level Success
            }
            catch {
                Write-LogMessage "Failed to create directory: $OutputPath" -Level Error
                Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
                Write-LogMessage "TROUBLESHOOTING: Check parent directory permissions" -Level Warning
                return $false
            }
        }

        # Create signature files
        $signatureName = "$UserName"
        $htmlFile = Join-Path $OutputPath "$signatureName.htm"
        $txtFile = Join-Path $OutputPath "$signatureName.txt"

        # Store signature data for Thunderbird integration in test mode
        $script:CurrentSignatureHTML = $SignatureHTML
        $script:CurrentSignatureName = $signatureName

        # Save HTML signature
        try {
            $SignatureHTML | Out-File -FilePath $htmlFile -Encoding UTF8 -Force
            Write-LogMessage "HTML signature saved: $htmlFile" -Level Success

            # ALSO copy to Thunderbird profile location for testing
            if ($TestMode) {
                $thunderbirdProfilePath = "$env:APPDATA\Thunderbird\Profiles"
                if (Test-Path $thunderbirdProfilePath) {
                    $profileDirs = Get-ChildItem -Path $thunderbirdProfilePath -Directory
                    if ($profileDirs.Count -gt 0) {
                        $profileDir = $profileDirs[0].FullName
                        $thunderbirdSigFile = Join-Path $profileDir "$signatureName.html"
                        try {
                            $SignatureHTML | Out-File -FilePath $thunderbirdSigFile -Encoding UTF8 -Force
                            Write-LogMessage "TEST: Signature also saved to Thunderbird profile: $thunderbirdSigFile" -Level Test
                        }
                        catch {
                            Write-LogMessage "TEST: Failed to save Thunderbird signature: $($_.Exception.Message)" -Level Warning
                        }
                    }
                }
            }
        }
        catch {
            Write-LogMessage "Failed to save HTML file: $htmlFile" -Level Error
            Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
            return $false
        }

        # Create text version (basic)
        try {
            $textSignature = $SignatureHTML -replace '<[^>]+>', '' -replace '&nbsp;', ' '
            $textSignature = ($textSignature -split "`n" | Where-Object { $_.Trim() -ne "" }) -join "`n"
            $textSignature | Out-File -FilePath $txtFile -Encoding UTF8 -Force
            Write-LogMessage "Text signature saved: $txtFile" -Level Success
        }
        catch {
            Write-LogMessage "Failed to save text file: $txtFile" -Level Error
            Write-LogMessage "Error: $($_.Exception.Message)" -Level Error
        }

        # Email client integration (Outlook production / Thunderbird testing)
        Set-OutlookDefaultSignature -SignatureName $signatureName -UserEmail $UserData.EmailAddress -UserName $UserName

        return $true
    }
    catch {
        Write-LogMessage "Critical error in Deploy-Signature: $($_.Exception.Message)" -Level Error
        return $false
    }
}

# Main execution
try {
    $modeText = if ($TestMode) { " (TEST MODE - Using Thunderbird)" } else { " (PRODUCTION MODE - Using Outlook)" }
    Write-LogMessage "Email Signature Update Script with GPO Assets$modeText" -Level Info
    Write-LogMessage "=========================================================" -Level Info
    Write-LogMessage "Starting at: $(Get-Date)" -Level Info
    Write-LogMessage "User context: $($env:USERDOMAIN)\$($env:USERNAME)" -Level Info

    if ($TestMode) {
        Write-LogMessage "TEST MODE: Enterprise Outlook logic preserved, testing with Thunderbird" -Level Test
    }

    # CRITICAL: Verify GPO asset deployment first
    if (-not (Test-GPOAssetDeployment)) {
        Write-LogMessage "CRITICAL: GPO asset deployment verification failed" -Level Error
        Write-LogMessage "Cannot proceed without required assets" -Level Error
        exit 1
    }

    # Check prerequisites
    Write-LogMessage "Checking prerequisites..." -Level Info

    # Check AD module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-LogMessage "Active Directory module loaded successfully" -Level Success
    }
    catch {
        Write-LogMessage "Active Directory module not available" -Level Error
        Write-LogMessage "TROUBLESHOOTING: Install RSAT tools or run on domain controller" -Level Warning
        exit 1
    }

    # Load template
    if (-not (Test-Path $TemplateFile)) {
        Write-LogMessage "Template file not found: $TemplateFile" -Level Error
        Write-LogMessage "TROUBLESHOOTING: Check GPO deployment of template file" -Level Warning
        exit 1
    }

    try {
        $template = Get-Content $TemplateFile -Raw -Encoding UTF8
        if ([string]::IsNullOrEmpty($template)) {
            Write-LogMessage "Template file is empty" -Level Error
            exit 1
        }
        Write-LogMessage "Template loaded from: $TemplateFile" -Level Success
        Write-LogMessage "GPO template contains $(($template -split "`n").Count) lines" -Level GPO
    }
    catch {
        Write-LogMessage "Failed to load template: $($_.Exception.Message)" -Level Error
        Write-LogMessage "TROUBLESHOOTING: Check file permissions and encoding" -Level Warning
        exit 1
    }

    # Determine users to process
    $usersToProcess = @()

    if ($UserName) {
        $usersToProcess += $UserName
    } else {
        # Get current user or prompt for users
        $currentUser = $env:USERNAME
        $response = Read-Host "Update signature for current user ($currentUser)? (Y/N/Specify username)"

        switch ($response.ToUpper()) {
            'Y' { $usersToProcess += $currentUser }
            'N' {
                $userList = Read-Host "Enter usernames (comma-separated)"
                $usersToProcess = $userList -split ',' | ForEach-Object { $_.Trim() }
            }
            default { $usersToProcess += $response }
        }
    }

    # Process each user
    $successCount = 0
    $failedUsers = @()

    Write-LogMessage "Processing $($usersToProcess.Count) user(s)..." -Level Info

    foreach ($user in $usersToProcess) {
        Write-LogMessage "" -Level Info
        Write-LogMessage "Processing user: $user" -Level Info

        # Get AD data
        $userData = Get-UserADData -SamAccountName $user
        if (-not $userData) {
            $failedUsers += $user
            continue
        }

        # Update template
        $personalizedSignature = Update-SignatureTemplate -Template $template -UserData $userData
        if (-not $personalizedSignature) {
            Write-LogMessage "Failed to create personalized signature for $user" -Level Error
            $failedUsers += $user
            continue
        }

        # Deploy signature
        if (Deploy-Signature -SignatureHTML $personalizedSignature -UserName $user -OutputPath $OutputPath -UserData $userData) {
            $successCount++
            Write-LogMessage "Successfully processed user: $user" -Level Success
        } else {
            $failedUsers += $user
        }
    }

    # Final summary
    Write-LogMessage "" -Level Info
    Write-LogMessage "=== EXECUTION SUMMARY ===" -Level Info
    Write-LogMessage "Total users: $($usersToProcess.Count)" -Level Info
    Write-LogMessage "Successful: $successCount" -Level Success
    Write-LogMessage "Failed: $($failedUsers.Count)" -Level $(if ($failedUsers.Count -gt 0) { "Warning" } else { "Info" })
    Write-LogMessage "Warnings: $script:WarningCount" -Level Info
    Write-LogMessage "Errors: $script:ErrorCount" -Level Info

    if ($failedUsers.Count -gt 0) {
        Write-LogMessage "Failed users: $($failedUsers -join ', ')" -Level Warning
    }

    if ($LogFile) {
        Write-LogMessage "Log file saved to: $LogFile" -Level Info
    }

    Write-LogMessage "=== GPO DEPLOYMENT STATUS ===" -Level GPO
    Write-LogMessage "Assets deployed to: $script:AssetBasePath" -Level GPO
    Write-LogMessage "Template deployed to: $TemplateFile" -Level GPO
    Write-LogMessage "All required assets verified" -Level GPO

    if ($TestMode) {
        Write-LogMessage "TEST MODE: Install Thunderbird and configure test email for full testing" -Level Test
        Write-LogMessage "TEST MODE: Production Outlook logic remains unchanged and enterprise-safe" -Level Test
    }

    Write-LogMessage "Script completed at: $(Get-Date)" -Level Info

} catch {
    Write-LogMessage "Critical script failure: $($_.Exception.Message)" -Level Error
    Write-LogMessage "EMERGENCY TROUBLESHOOTING:" -Level Error
    Write-LogMessage "  1. Check PowerShell execution policy" -Level Error
    Write-LogMessage "  2. Verify required modules are installed" -Level Error
    Write-LogMessage "  3. Verify GPO asset deployment" -Level Error
    Write-LogMessage "  4. Run as Administrator if needed" -Level Error
    exit 1
}
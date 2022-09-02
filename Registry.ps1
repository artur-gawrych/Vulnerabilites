# IE - Microsoft Internet Explorer Information Disclosure Vulnerability (September 2017)

reg add "HKLM\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /v iexplore.exe /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" /v iexplore.exe /t REG_DWORD /d 1 /f

# Spectre / Meltdown

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverride /t REG_DWORD /d 72 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v FeatureSettingsOverrideMask /t REG_DWORD /d 3 /f

# Diable AutoPlay

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
reg add "HKU\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f

# Require SMB Signing

reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f

# Don't allow Null Session

reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v RestrictAnonymous /t REG_DWORD /d 1 /f

# Disable Cached Logon Credential - use it only on the Servers!

reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "CachedLogonsCount"  /t REG_SZ /d 10 /f

# Disable anonymous access

reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1
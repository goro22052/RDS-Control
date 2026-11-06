#requires -Version 5.1
#requires -RunAsAdministrator

<#
RDS-Control.ps1
Режими: Install | Session | Nightly | Cleanup | Audit
Файл зберігається в UTF-8 з BOM (потрібно для PowerShell 5.1 з кирилицею).
#>

[CmdletBinding()]
param(
    [ValidateSet('Install', 'Session', 'Nightly', 'Cleanup', 'Audit')]
    [string]$Mode = 'Install'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ============================================================
# CONFIGURATION
# ============================================================

$InstallDir  = 'C:\Install\RDS-Maintenance'
$InstallFile = Join-Path $InstallDir 'RDS-Control.ps1'
$LogDir      = Join-Path $InstallDir 'Logs'

# Локальна група на цьому сервері (у неї можна додавати доменних користувачів
# і доменні групи, наприклад GG_*).
$VipGroup = 'GG_RDS_Session_Timeout_Exempt'

$IdleLimitMinutes         = 120
$DisconnectedLimitMinutes = 60

$MaintenanceStart = [TimeSpan]::Parse('02:30')
$MaintenanceEnd   = [TimeSpan]::Parse('04:30')

# $true  = перезавантажувати лише якщо потрібно (після оновлень / pending reboot)
# $false = перезавантажувати щоночі після успішного обслуговування
$RebootOnlyIfRequired = $true

$SessionTaskName = 'RDS_Session_Manager'
$NightTaskName   = 'RDS_Nightly_Maintenance'

$script:VipCache = $null

# ============================================================
# DIRECTORIES AND LOGGING
# ============================================================

New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
New-Item -ItemType Directory -Path $LogDir -Force | Out-Null

$LogFile = Join-Path $LogDir ("RDS-{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $Line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    # Повтор запису: Session і Nightly можуть писати в той самий файл одночасно.
    for ($i = 1; $i -le 5; $i++) {
        try {
            Add-Content -LiteralPath $LogFile -Value $Line -Encoding UTF8 -ErrorAction Stop
            break
        }
        catch {
            Start-Sleep -Milliseconds 200
        }
    }

    # Write-Host, а не Write-Output, щоб лог не потрапляв у значення, що повертають функції.
    Write-Host $Line
}

function Stop-WithLog {
    param([string]$Message)

    Write-Log $Message 'ERROR'
    throw $Message
}

# ============================================================
# WTS API
# ============================================================

$NativeCode = @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace RDSNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO
    {
        public int SessionID;
        public IntPtr pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WTSINFO
    {
        public int State;
        public int SessionId;
        public int IncomingBytes;
        public int OutgoingBytes;
        public int IncomingFrames;
        public int OutgoingFrames;
        public int IncomingCompressedBytes;
        public int OutgoingCompressedBytes;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string WinStationName;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)]
        public string Domain;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 21)]
        public string UserName;

        public long ConnectTime;
        public long DisconnectTime;
        public long LastInputTime;
        public long LogonTime;
        public long CurrentTime;
    }

    public class Session
    {
        public int ID;
        public int State;
        public string User;
        public string Domain;
        public long LastInputTime;
        public long DisconnectTime;
    }

    public static class Api
    {
        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSEnumerateSessions(
            IntPtr hServer, int Reserved, int Version,
            out IntPtr ppSessionInfo, out int pCount);

		[DllImport("wtsapi32.dll", SetLastError = true,
		CharSet = CharSet.Unicode, EntryPoint = "WTSQuerySessionInformationW")]
		static extern bool WTSQuerySessionInformation(
		IntPtr hServer, int sessionId, int infoClass,
		out IntPtr ppBuffer, out int pBytesReturned);
	
        [DllImport("wtsapi32.dll")]
        static extern void WTSFreeMemory(IntPtr pMemory);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSDisconnectSession(
            IntPtr hServer, int sessionId, bool bWait);

        [DllImport("wtsapi32.dll", SetLastError = true)]
        static extern bool WTSLogoffSession(
            IntPtr hServer, int sessionId, bool bWait);

        public static Session[] GetSessions()
        {
            IntPtr pSessions = IntPtr.Zero;
            int count = 0;

            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1,
                out pSessions, out count))
            {
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error());
            }

            List<Session> result = new List<Session>();

            try
            {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));

                for (int i = 0; i < count; i++)
                {
                    IntPtr pItem = IntPtr.Add(pSessions, i * size);
                    WTS_SESSION_INFO item =
                        (WTS_SESSION_INFO)Marshal.PtrToStructure(
                            pItem, typeof(WTS_SESSION_INFO));

                    IntPtr pInfo = IntPtr.Zero;
                    int bytes = 0;

                    if (!WTSQuerySessionInformation(
                        IntPtr.Zero, item.SessionID, 24,
                        out pInfo, out bytes))
                    {
                        continue;
                    }

                    try
                    {
                        int infoSize = Marshal.SizeOf(typeof(WTSINFO));

                        if (pInfo == IntPtr.Zero )
                            continue;

                        WTSINFO info = (WTSINFO)Marshal.PtrToStructure(
                            pInfo, typeof(WTSINFO));

                        result.Add(new Session {
                            ID = item.SessionID,
                            State = item.State,
                            User = info.UserName ?? "",
                            Domain = info.Domain ?? "",
                            LastInputTime = info.LastInputTime,
                            DisconnectTime = info.DisconnectTime
                        });
                    }
                    finally
                    {
                        if (pInfo != IntPtr.Zero)
                            WTSFreeMemory(pInfo);
                    }
                }
            }
            finally
            {
                if (pSessions != IntPtr.Zero)
                    WTSFreeMemory(pSessions);
            }

            return result.ToArray();
        }

        public static void Disconnect(int sessionId)
        {
            if (!WTSDisconnectSession(IntPtr.Zero, sessionId, false))
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error());
        }

        public static void Logoff(int sessionId)
        {
            if (!WTSLogoffSession(IntPtr.Zero, sessionId, false))
                throw new System.ComponentModel.Win32Exception(
                    Marshal.GetLastWin32Error());
        }
    }
}
'@

if (-not ([System.Management.Automation.PSTypeName]'RDSNative.Api').Type) {
    Add-Type -TypeDefinition $NativeCode -Language CSharp
}

# ============================================================
# VIP GROUP MEMBERSHIP
# ============================================================

function Get-AdsProperty {
    param($Object, [string]$Property)

    return $Object.GetType().InvokeMember(
        $Property,
        [System.Reflection.BindingFlags]::GetProperty,
        $null,
        $Object,
        $null
    )
}

function Add-GroupMembersToSet {
    param(
        $Group,
        [System.Collections.Generic.HashSet[string]]$Set,
        [System.Collections.Generic.HashSet[string]]$Visited
    )

    foreach ($Member in @($Group.psbase.Invoke('Members'))) {
        try {
            $Path  = [string](Get-AdsProperty $Member 'ADsPath')
            $Class = [string](Get-AdsProperty $Member 'Class')
            $Name  = [string](Get-AdsProperty $Member 'Name')

            $Parts  = @(($Path -replace '^WinNT://', '') -split '/')
            $Domain = $env:COMPUTERNAME

            if ($Parts.Count -ge 2) {
                $Domain = $Parts[$Parts.Count - 2]
            }

            if ($Class -eq 'Group') {
                $GroupKey = ('{0}\{1}' -f $Domain, $Name).ToLowerInvariant()

                if (-not $Visited.Add($GroupKey)) {
                    continue
                }

                if ($Domain -ieq $env:COMPUTERNAME) {
                    # Вкладена локальна група.
                    Add-GroupMembersToSet -Group ([ADSI]$Path) -Set $Set -Visited $Visited
                }
                elseif (Get-Command Get-ADGroupMember -ErrorAction SilentlyContinue) {
                    # Доменна група (потрібен модуль ActiveDirectory).
                    try {
                        $AdMembers = @(Get-ADGroupMember -Identity $Name -Recursive -ErrorAction Stop |
                            Where-Object { $_.objectClass -eq 'user' })

                        foreach ($AdMember in $AdMembers) {
                            [void]$Set.Add(('{0}\{1}' -f $Domain, $AdMember.SamAccountName).ToLowerInvariant())
                        }
                    }
                    catch {
                        Write-Log "Не вдалося розкрити доменну групу $GroupKey. $_" 'WARN'
                    }
                }
                else {
                    Write-Log "Доменну групу $GroupKey не розкрито (немає модуля ActiveDirectory)." 'WARN'
                }
            }
            else {
                [void]$Set.Add(('{0}\{1}' -f $Domain, $Name).ToLowerInvariant())
            }
        }
        catch {
            Write-Log "Не вдалося прочитати одного з учасників VIP-групи: $_" 'WARN'
        }
    }
}

function Initialize-VipCache {

    if ($null -ne $script:VipCache) {
        return
    }

    try {
        $Group = [ADSI]"WinNT://$env:COMPUTERNAME/$VipGroup,group"

        # Перевірка, що локальна група існує.
        $null = $Group.Name

        $Set     = New-Object 'System.Collections.Generic.HashSet[string]'
        $Visited = New-Object 'System.Collections.Generic.HashSet[string]'

        Add-GroupMembersToSet -Group $Group -Set $Set -Visited $Visited

        $script:VipCache = $Set
    }
    catch {
        Stop-WithLog "Не знайдено або не вдалося прочитати локальну групу '$VipGroup'. Перевірте її наявність. $_"
    }
}

function Test-VIP {
    param(
        [string]$User,
        [string]$Domain
    )

    if ([string]::IsNullOrWhiteSpace($User)) {
        return $false
    }

    # Група читається один раз за запуск скрипта.
    Initialize-VipCache

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        $Domain = $env:COMPUTERNAME
    }

    $Key = ('{0}\{1}' -f $Domain, $User).ToLowerInvariant()

    return $script:VipCache.Contains($Key)
}

# ============================================================
# SESSION INFORMATION
# ============================================================

function Get-RDPSessions {

    $NowUtc   = [DateTime]::UtcNow
    $Sessions = @()

    foreach ($S in [RDSNative.Api]::GetSessions()) {

        $IdleMinutes         = $null
        $DisconnectedMinutes = $null

        if ($S.LastInputTime -gt 0) {
            try {
                $LastInput   = [DateTime]::FromFileTimeUtc($S.LastInputTime)
                $IdleMinutes = [math]::Max(0, ($NowUtc - $LastInput).TotalMinutes)
            }
            catch {
                Write-Log "Не вдалося визначити час останньої активності сеансу $($S.ID)." 'WARN'
            }
        }

        if ($S.DisconnectTime -gt 0) {
            try {
                $DisconnectTime      = [DateTime]::FromFileTimeUtc($S.DisconnectTime)
                $DisconnectedMinutes = [math]::Max(0, ($NowUtc - $DisconnectTime).TotalMinutes)
            }
            catch {
                Write-Log "Не вдалося визначити час від'єднання сеансу $($S.ID)." 'WARN'
            }
        }

        $Sessions += [PSCustomObject]@{
            ID                  = $S.ID
            User                = $S.User
            Domain              = $S.Domain
            State               = $S.State
            IdleMinutes         = $IdleMinutes
            DisconnectedMinutes = $DisconnectedMinutes
        }
    }

    return $Sessions
}

# ============================================================
# SESSION ACTIONS
# ============================================================

function Remove-DisconnectedSessions {
    param(
        [switch]$AllDisconnected
    )

    $Sessions = @(Get-RDPSessions)

    foreach ($S in $Sessions) {

        # WTSDisconnected = 4
        if ($S.State -ne 4) {
            continue
        }

        if ([string]::IsNullOrWhiteSpace($S.User)) {
            continue
        }

        if (Test-VIP $S.User $S.Domain) {
            Write-Log "VIP: пропуск від'єднаного сеансу $($S.ID), користувач $($S.Domain)\$($S.User)."
            continue
        }

        $MustLogoff = $false

        if ($AllDisconnected) {
            $MustLogoff = $true
        }
        elseif (
            $null -ne $S.DisconnectedMinutes -and
            $S.DisconnectedMinutes -ge $DisconnectedLimitMinutes
        ) {
            $MustLogoff = $true
        }

        if (-not $MustLogoff) {
            continue
        }

        $DiscText = 'невідомо'
        if ($null -ne $S.DisconnectedMinutes) {
            $DiscText = [string][math]::Round($S.DisconnectedMinutes, 1)
        }

        Write-Log "Завершення від'єднаного сеансу $($S.ID), користувач $($S.Domain)\$($S.User), час від'єднання (хв): $DiscText."

        try {
            [RDSNative.Api]::Logoff($S.ID)
            Write-Log "Сеанс $($S.ID) успішно завершено."
        }
        catch {
            Write-Log "Помилка завершення сеансу $($S.ID): $_" 'ERROR'
        }
    }
}

function Invoke-SessionControl {

    Write-Log 'Початок перевірки RDS-сеансів.'

    $Sessions = @(Get-RDPSessions)

    foreach ($S in $Sessions) {

        if ([string]::IsNullOrWhiteSpace($S.User)) {
            continue
        }

        if (Test-VIP $S.User $S.Domain) {
            continue
        }

        # WTSActive = 0
        if (
            $S.State -eq 0 -and
            $null -ne $S.IdleMinutes -and
            $S.IdleMinutes -ge $IdleLimitMinutes
        ) {
            Write-Log "Від'єднання неактивного сеансу $($S.ID), користувач $($S.Domain)\$($S.User), бездіяльність (хв): $([math]::Round($S.IdleMinutes, 1))."

            try {
                [RDSNative.Api]::Disconnect($S.ID)
                Write-Log "Сеанс $($S.ID) від'єднано."
            }
            catch {
                Write-Log "Помилка від'єднання сеансу $($S.ID): $_" 'ERROR'
            }
        }
    }

    # Завершуємо від'єднані сеанси, якщо вони існують довше за ліміт.
    Remove-DisconnectedSessions

    Write-Log 'Перевірку RDS-сеансів завершено.'
}

# ============================================================
# VIP ACTIVE SESSION CHECK
# ============================================================

function Test-VIPActiveSession {

    $Sessions = @(Get-RDPSessions)

    foreach ($S in $Sessions) {

        # 0 = Active, 1 = Connected
        if ($S.State -notin @(0, 1)) {
            continue
        }

        if (Test-VIP $S.User $S.Domain) {
            Write-Log "Знайдено активний VIP-сеанс: $($S.Domain)\$($S.User), ID $($S.ID)." 'WARN'
            return $true
        }
    }

    return $false
}

# ============================================================
# WINDOWS UPDATE
# ============================================================

function Test-PendingReboot {

    $Keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    )

    foreach ($Key in $Keys) {
        if (Test-Path -LiteralPath $Key) {
            return $true
        }
    }

    return $false
}

function Install-WindowsUpdates {

    # Повертає об'єкт: Success (bool) і RebootRequired (bool).
    Write-Log 'Початок пошуку оновлень Windows Update.'

    $Out = [PSCustomObject]@{
        Success        = $false
        RebootRequired = $false
    }

    try {
        $UpdateSession = New-Object -ComObject Microsoft.Update.Session
        $UpdateSession.ClientApplicationID = 'RDS Nightly Maintenance'

        $Searcher = $UpdateSession.CreateUpdateSearcher()

        # Усі доступні, не приховані програмні оновлення (без драйверів).
        $SearchResult = $Searcher.Search(
            "IsInstalled=0 and IsHidden=0 and Type='Software'"
        )

        $Updates = New-Object -ComObject Microsoft.Update.UpdateColl

        foreach ($Update in $SearchResult.Updates) {

            if (-not $Update.EulaAccepted) {
                $Update.AcceptEula()
            }

            [void]$Updates.Add($Update)

            Write-Log "Знайдено оновлення: $($Update.Title)"
        }

        if ($Updates.Count -eq 0) {
            Write-Log 'Доступних оновлень немає.'
            $Out.Success = $true
            return $Out
        }

        Write-Log "Кількість оновлень для встановлення: $($Updates.Count)."

        $Downloader = $UpdateSession.CreateUpdateDownloader()
        $Downloader.Updates = $Updates

        Write-Log 'Завантаження оновлень...'

        $DownloadResult = $Downloader.Download()

        # 2 = Succeeded, 3 = SucceededWithErrors
        if ($DownloadResult.ResultCode -notin @(2, 3)) {
            Write-Log "Помилка завантаження оновлень. Код: $($DownloadResult.ResultCode)." 'ERROR'
            return $Out
        }

        $Installer = $UpdateSession.CreateUpdateInstaller()
        $Installer.Updates = $Updates
        $Installer.ForceQuiet = $true
        $Installer.AllowSourcePrompts = $false

        Write-Log 'Встановлення оновлень...'

        $InstallResult = $Installer.Install()

        $Failed = $false

        for ($i = 0; $i -lt $Updates.Count; $i++) {

            $Update = $Updates.Item($i)
            $Result = $InstallResult.GetUpdateResult($i)

            Write-Log "Оновлення: $($Update.Title). Код результату: $($Result.ResultCode). HRESULT: $($Result.HResult)."

            if ($Result.ResultCode -notin @(2, 3)) {
                $Failed = $true
            }
        }

        if ($InstallResult.ResultCode -notin @(2, 3)) {
            $Failed = $true
        }

        $Out.RebootRequired = [bool]$InstallResult.RebootRequired

        if ($Failed) {
            Write-Log 'Одне або декілька оновлень не встановлено. Перезавантаження заборонено.' 'ERROR'
            return $Out
        }

        Write-Log 'Встановлення оновлень завершено успішно.'
        $Out.Success = $true
        return $Out
    }
    catch {
        Write-Log "Помилка Windows Update: $_" 'ERROR'
        $Out.Success = $false
        return $Out
    }
}

# ============================================================
# MAINTENANCE WINDOW
# ============================================================

function Test-MaintenanceWindow {

    $Now = (Get-Date).TimeOfDay

    return (
        $Now -ge $MaintenanceStart -and
        $Now -lt $MaintenanceEnd
    )
}

# ============================================================
# NIGHTLY MAINTENANCE
# ============================================================

function Invoke-NightlyMaintenance {

    Write-Log 'Запуск нічного обслуговування.'

    if (-not (Test-MaintenanceWindow)) {
        Write-Log 'Поточний час поза вікном 02:30-04:30. Обслуговування скасовано.' 'WARN'
        return
    }

    # 1. Перевірка VIP на початку обслуговування.
    if (Test-VIPActiveSession) {
        Write-Log 'Виявлено активний VIP-сеанс. Усе нічне обслуговування скасовано.' 'WARN'
        return
    }

    # 2. Завершуємо всі від'єднані сеанси, крім VIP.
    Write-Log "Завершення всіх від'єднаних сеансів не-VIP користувачів."
    Remove-DisconnectedSessions -AllDisconnected

    # 3. Перевірка часу перед початком оновлень.
    if (-not (Test-MaintenanceWindow)) {
        Write-Log 'Часове вікно завершилося до початку оновлень. Перезавантаження не буде.' 'WARN'
        return
    }

    # 4. Встановлення оновлень.
    $UpdateInfo = Install-WindowsUpdates

    if (-not $UpdateInfo.Success) {
        Write-Log 'Оновлення завершилися з помилкою. Перезавантаження скасовано.' 'ERROR'
        return
    }

    # 5. Чи потрібне перезавантаження.
    if ($RebootOnlyIfRequired) {
        $NeedReboot = ($UpdateInfo.RebootRequired -or (Test-PendingReboot))

        if (-not $NeedReboot) {
            Write-Log 'Перезавантаження не потрібне. Обслуговування завершено.'
            return
        }
    }

    # 6. Перевірка часу після оновлень.
    if (-not (Test-MaintenanceWindow)) {
        Write-Log 'Оновлення завершилися після 04:30. Перезавантаження скасовано.' 'WARN'
        return
    }

    # 7. Повторна перевірка VIP перед перезавантаженням.
    if (Test-VIPActiveSession) {
        Write-Log 'VIP-користувач підключився під час обслуговування. Перезавантаження скасовано.' 'WARN'
        return
    }

    # 8. Фінальна перевірка часу.
    if (-not (Test-MaintenanceWindow)) {
        Write-Log 'Часове вікно завершилося перед перезавантаженням.' 'WARN'
        return
    }

    Write-Log 'Усі перевірки пройдено. Перезавантаження сервера.'

    Restart-Computer -Force
}

# ============================================================
# TASK INSTALLATION
# ============================================================

function Install-ScheduledTasks {

    $PowerShellExe = Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe'

    if (-not (Test-Path -LiteralPath $PowerShellExe)) {
        Stop-WithLog "Не знайдено $PowerShellExe."
    }

    $BaseArgs = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Mode {1}'

    $Principal = New-ScheduledTaskPrincipal `
        -UserId 'SYSTEM' `
        -LogonType ServiceAccount `
        -RunLevel Highest

    # --- Контроль сеансів: щохвилини ---
    Write-Log 'Створення завдання щохвилинного контролю сеансів.'

    $SessionAction = New-ScheduledTaskAction `
        -Execute $PowerShellExe `
        -Argument ($BaseArgs -f $InstallFile, 'Session')

    $SessionTrigger = New-ScheduledTaskTrigger `
        -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 1) `
        -RepetitionDuration (New-TimeSpan -Days 3650)

    $SessionSettings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -StartWhenAvailable:$false

    Register-ScheduledTask `
        -TaskName $SessionTaskName `
        -Action $SessionAction `
        -Trigger $SessionTrigger `
        -Settings $SessionSettings `
        -Principal $Principal `
        -Force | Out-Null

    # --- Нічне обслуговування: щодня о 02:30 ---
    Write-Log 'Створення щоденного завдання нічного обслуговування.'

    $NightAction = New-ScheduledTaskAction `
        -Execute $PowerShellExe `
        -Argument ($BaseArgs -f $InstallFile, 'Nightly')

    $NightTrigger = New-ScheduledTaskTrigger -Daily -At '02:30'

    $NightSettings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Hours 3) `
        -StartWhenAvailable:$false

    Register-ScheduledTask `
        -TaskName $NightTaskName `
        -Action $NightAction `
        -Trigger $NightTrigger `
        -Settings $NightSettings `
        -Principal $Principal `
        -Force | Out-Null

    Write-Log 'Обидва заплановані завдання створено.'
}

# ============================================================
# INSTALL MODE
# ============================================================

function Invoke-Install {

    Write-Log 'Початок інсталяції RDS Session Manager.'

    if (-not $PSCommandPath) {
        Stop-WithLog 'Скрипт має бути збережений у файл RDS-Control.ps1 перед запуском.'
    }

    # Перевіряємо наявність локальної VIP-групи.
    Initialize-VipCache

    # Копіюємо скрипт у постійний каталог.
    $CurrentPath = [IO.Path]::GetFullPath($PSCommandPath)
    $TargetPath  = [IO.Path]::GetFullPath($InstallFile)

    if ($CurrentPath -ne $TargetPath) {
        Copy-Item -LiteralPath $PSCommandPath -Destination $InstallFile -Force
        Write-Log "Скрипт скопійовано до $InstallFile."
    }

    # Обмежуємо доступ до журналів (SYSTEM та Administrators).
    & icacls.exe $LogDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

    if ($LASTEXITCODE -ne 0) {
        Write-Log 'Не вдалося повністю налаштувати ACL каталогу журналів.' 'WARN'
    }

    Install-ScheduledTasks

    # Первинне очищення всіх від'єднаних сеансів не-VIP.
    Write-Log "Виконується первинне очищення від'єднаних сеансів."
    Remove-DisconnectedSessions -AllDisconnected

    Write-Log 'Інсталяцію завершено.'
    Write-Log "VIP-група: $VipGroup."
    Write-Log "Контроль бездіяльності (хв): $IdleLimitMinutes."
    Write-Log "Час до завершення від'єднаного сеансу (хв): $DisconnectedLimitMinutes."
    Write-Log 'Щоденне обслуговування: 02:30-04:30.'
}

# ============================================================
# AUDIT MODE
# ============================================================

function Invoke-Audit {

    Write-Log 'Аудит поточних RDS-сеансів.'

    Initialize-VipCache
    Write-Log "VIP-користувачі: $(@($script:VipCache) -join ', ')."

    $Sessions = @(Get-RDPSessions)

    foreach ($S in $Sessions) {

        $StateName = switch ($S.State) {
            0 { 'Active' }
            1 { 'Connected' }
            2 { 'ConnectQuery' }
            3 { 'Shadow' }
            4 { 'Disconnected' }
            5 { 'Idle' }
            6 { 'Listen' }
            7 { 'Reset' }
            8 { 'Down' }
            9 { 'Init' }
            default { "Unknown ($($S.State))" }
        }

        $IsVIP = Test-VIP $S.User $S.Domain

        Write-Log (
            "SessionID={0}; User={1}\{2}; State={3}; VIP={4}; IdleMinutes={5}; DisconnectedMinutes={6}" -f
            $S.ID,
            $S.Domain,
            $S.User,
            $StateName,
            $IsVIP,
            $S.IdleMinutes,
            $S.DisconnectedMinutes
        )
    }

    Write-Log 'Аудит завершено.'
}

# ============================================================
# MAIN
# ============================================================
try {
    Write-Log "Запуск скрипта. Mode=$Mode."

    switch ($Mode) {
        'Install' {
            Invoke-Install
        }

        'Session' {
            Invoke-SessionControl
        }

        'Nightly' {
            Invoke-NightlyMaintenance
        }

        'Cleanup' {
            Write-Log "Ручне очищення всіх від'єднаних сеансів не-VIP."
            Remove-DisconnectedSessions -AllDisconnected
        }

        'Audit' {
            Invoke-Audit
        }

        default {
            throw "Невідомий режим: $Mode"
        }
    }
}
catch {
    Write-Log -Message "Критична помилка: $($_.Exception.Message)" -Level 'ERROR'
    exit 1
}

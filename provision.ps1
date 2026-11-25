param(
    [Parameter(Mandatory = $true)][string]$Roster,
    [Parameter(Mandatory = $true)][string[]]$Venue,
    [Parameter(Mandatory = $true)][string]$CollectorHost,
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Policy = '',
    [string]$NetworkProfile = '',
    [string]$UiPassword = '',
    [switch]$RotateKeys,
    [string]$ListenerPy = '',
    [string]$GuardPy = '',
    [string]$CollectorPy = '',
    [int]$CollectorPort = 48123,
    [int]$WebPort = 8443
)
# provision.ps1 v1.5 — one command from roster.csv to deployable packages (§4).
# Requires Windows PowerShell 5.0+ on the PROVISION machine. The generated
# deploy-side scripts are Windows PowerShell 2.0-safe so they also run on Win7.
# v1.5: no PyInstaller exes — seats ship listener.py/guard.py and the collector
# ships collector.py for a Linux server (runs with the machine's python3).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
if ($PSVersionTable.PSVersion.Major -lt 5) { throw 'provision.ps1 需要 Windows PowerShell 5.0+（在发卷/备课机上运行即可，目标机不受影响）。' }

# PowerShell's current directory and .NET's process working directory can differ.
# Normalize every relative path here, otherwise .NET APIs may resolve them against
# the process startup directory instead of the prompt shown by PowerShell.
$psWorkingDir = (Get-Location).ProviderPath
if (![System.IO.Path]::IsPathRooted($Roster)) { $Roster = Join-Path $psWorkingDir $Roster }
if ($Policy -and ![System.IO.Path]::IsPathRooted($Policy)) { $Policy = Join-Path $psWorkingDir $Policy }
if ($NetworkProfile -and ![System.IO.Path]::IsPathRooted($NetworkProfile)) { $NetworkProfile = Join-Path $psWorkingDir $NetworkProfile }
if ($Out -and ![System.IO.Path]::IsPathRooted($Out)) { $Out = Join-Path $psWorkingDir $Out }
$Roster = [System.IO.Path]::GetFullPath($Roster)
if ($Policy) { $Policy = [System.IO.Path]::GetFullPath($Policy) }
if ($NetworkProfile) { $NetworkProfile = [System.IO.Path]::GetFullPath($NetworkProfile) }
if ($Out) { $Out = [System.IO.Path]::GetFullPath($Out) }
foreach ($PathVariable in @('ListenerPy', 'GuardPy', 'CollectorPy')) {
    $PathValue = (Get-Variable -Name $PathVariable -ValueOnly)
    if ($PathValue -and ![System.IO.Path]::IsPathRooted($PathValue)) {
        Set-Variable -Name $PathVariable -Value (Join-Path $psWorkingDir $PathValue)
    }
    $PathValue = (Get-Variable -Name $PathVariable -ValueOnly)
    if ($PathValue) { Set-Variable -Name $PathVariable -Value ([System.IO.Path]::GetFullPath($PathValue)) }
}

function Write-Utf8Bom([string]$Path, [string]$Text) {
    $enc = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($Path, $Text, $enc)
}
function Write-JsonFile([string]$Path, $Value, [int]$Depth = 8) {
    $json = ConvertTo-Json -InputObject $Value -Depth $Depth
    try { $null = ConvertFrom-Json -InputObject $json } catch {
        throw "生成 JSON 失败（$Path）：$($_.Exception.Message)"
    }
    Write-Utf8Bom $Path ($json + "`r`n")
}
function Read-TextSmart([string]$Path) {
    # UTF-8 BOM preferred; fall back to strict UTF-8, then GBK.
    if (![System.IO.Path]::IsPathRooted($Path)) {
        $Path = Join-Path (Get-Location).ProviderPath $Path
    }
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return (New-Object System.Text.UTF8Encoding($false)).GetString($bytes, 3, $bytes.Length - 3)
    }
    $strict = New-Object System.Text.UTF8Encoding($false, $true)
    try { return $strict.GetString($bytes) } catch [System.Text.DecoderFallbackException] {
        return [System.Text.Encoding]::GetEncoding(936).GetString($bytes)
    }
}
function New-Secret {
    # 45 random bytes -> base64url without padding = 60 chars (same as token_urlsafe(45)).
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 45
    $rng.GetBytes($bytes)
    return ([System.Convert]::ToBase64String($bytes)).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}
function New-MachineId {
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 5
    $rng.GetBytes($bytes)
    $hex = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLower()
    return ('m' + $hex)
}
function Get-SecretFingerprint([string]$Secret) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Secret))
    return ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLower().Substring(0, 8)
}
function New-Pbkdf2Hash([string]$Password) {
    # Must match collector.py: pbkdf2_sha256$200000$salt_hex$hash_hex (PBKDF2-SHA256).
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $salt = New-Object byte[] 16
    $rng.GetBytes($salt)
    try {
        $rfc = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $salt, 200000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch {
        return ''  # .NET < 4.7.2: let the collector hash a pending password instead
    }
    $hash = $rfc.GetBytes(32)
    return ('pbkdf2_sha256$200000$' + ([System.BitConverter]::ToString($salt)).Replace('-', '').ToLower() +
            '$' + ([System.BitConverter]::ToString($hash)).Replace('-', '').ToLower())
}

# ---------- resolve source scripts ----------
if (!$ListenerPy) { $ListenerPy = Join-Path $root 'listener.py' }
if (!$GuardPy)   { $GuardPy   = Join-Path $root 'guard.py' }
if (!$CollectorPy) { $CollectorPy = Join-Path $root 'collector.py' }
foreach ($py in @($ListenerPy, $GuardPy, $CollectorPy)) {
    if (!(Test-Path $py)) { throw ("缺少 $py —— 请在本目录（或用 -ListenerPy/-GuardPy/-CollectorPy 指定）提供三个 .py 源文件。") }
}

# ---------- validate venues ----------
$Venues = New-Object System.Collections.Generic.List[string]
foreach ($rawVenue in @($Venue)) {
    foreach ($piece in (($rawVenue -split '[,;\s]+') | Where-Object { $_ })) {
        if ($piece -notmatch '^[A-Za-z0-9_-]{1,16}$') {
            throw "场地名 '$piece' 不合法：仅允许字母/数字/下划线/连字符，1-16 位。"
        }
        if (!$Venues.Contains($piece)) { $Venues.Add($piece) }
    }
}
if ($Venues.Count -eq 0) { throw '至少需要指定一个场地名。' }
$VenueNames = $Venues -join ','

# ---------- read + validate roster (all errors before any output) ----------
if (!(Test-Path $Roster)) { throw "找不到名册文件: $Roster" }
$text = Read-TextSmart $Roster
Add-Type -AssemblyName Microsoft.VisualBasic
$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser((New-Object System.IO.StringReader($text)))
$parser.HasFieldsEnclosedInQuotes = $true
$parser.Delimiters = @(',')
$aliasMap = @{
    'account' = 'account'; 'oj账号' = 'account'; '账号' = 'account'; '学号' = 'account'
    'name' = 'name'; '姓名' = 'name'
    'venue' = 'venue'; '场地' = 'venue'; '考场' = 'venue'
    'note' = 'note'; '备注' = 'note'
}
$errors = New-Object System.Collections.Generic.List[string]
$rows = New-Object System.Collections.Generic.List[object]
$lineNo = 0
$headerSeen = $false
$colIndex = @{}
$seenAccounts = @{}
while (!$parser.EndOfData) {
    $lineNo++
    $fields = $null
    try { $fields = $parser.ReadFields() } catch {
        $errors.Add(("第 {0} 行: CSV 解析失败 {1}" -f $lineNo, $_.Exception.Message)); continue
    }
    if ($fields -eq $null -or ($fields.Count -eq 1 -and $fields[0] -eq '')) { continue }
    if (!$headerSeen) {
        for ($i = 0; $i -lt $fields.Count; $i++) {
            $key = ('' + $fields[$i]).Trim().ToLower()
            if ($aliasMap.ContainsKey($key)) {
                $canonical = $aliasMap[$key]
                if ($colIndex.ContainsValue($canonical)) { $errors.Add("第 $lineNo 行: 表头重复列 '$($fields[$i])'") }
                else { $colIndex[$i] = $canonical }
            }
        }
        foreach ($need in @('account', 'name', 'venue')) {
            if (!$colIndex.ContainsValue($need)) { $errors.Add("第 $lineNo 行: 表头缺少必需列 '$need'（可用别名：账号/OJ账号、姓名、场地/考场）") }
        }
        if ($errors.Count) { break }
        $headerSeen = $true
        continue
    }
    $record = @{ account = ''; name = ''; venue = ''; note = '' }
    foreach ($idx in $colIndex.Keys) { $record[$colIndex[$idx]] = ('' + $fields[$idx]).Trim() }
    $account = $record['account']; $name = $record['name']; $rowVenue = $record['venue']
    if ($account -notmatch '^[!-~]{2,64}$') { $errors.Add(("第 {0} 行: 账号 '{1}' 不合法（可见 ASCII，2-64 位）" -f $lineNo, $account)); continue }
    $lower = $account.ToLower()
    if ($seenAccounts.ContainsKey($lower)) { $errors.Add(("第 {0} 行: 账号 '{1}' 与第 {2} 行重复" -f $lineNo, $account, $seenAccounts[$lower])); continue }
    $seenAccounts[$lower] = $lineNo
    if ($name.Length -lt 1 -or $name.Length -gt 20) { $errors.Add(("第 {0} 行: 姓名 '{1}' 长度须为 1-20" -f $lineNo, $name)); continue }
    if ($name -match '[\\/:*?"<>|]') { $errors.Add(("第 {0} 行: 姓名 '{1}' 含非法字符 \ / : * ? `" < > |" -f $lineNo, $name)); continue }
    if (!$rowVenue) { $rowVenue = $Venues[0] }
    if ($rowVenue -notmatch '^[A-Za-z0-9_-]{1,16}$') { $errors.Add(("第 {0} 行: 场地 '{1}' 不合法" -f $lineNo, $rowVenue)); continue }
    if (!$Venues.Contains($rowVenue)) { continue }  # other venues are provisioned separately
    $rows.Add([pscustomobject]@{ account = $account; name = $name; venue = $rowVenue; note = $record['note'] })
}
$parser.Close()
if ($rows.Count -gt 1000) { $errors.Add("行数超过上限 1000（当前 $($rows.Count) 行）") }
if ($errors.Count) {
    $rosterResolved = (Resolve-Path $Roster).Path
    $errPath = Join-Path (Split-Path -Parent $rosterResolved) 'roster.errors.txt'
    Write-Utf8Bom $errPath (($errors -join "`r`n") + "`r`n")
    Write-Host "名册校验失败 $($errors.Count) 处，详见 $errPath" -ForegroundColor Red
    exit 1
}
if ($rows.Count -eq 0) { Write-Host '名册中没有选定场地（'$VenueNames'）的行，未生成任何输出。' -ForegroundColor Yellow; exit 1 }

# ---------- policy ----------
if ($Policy -and (Test-Path $Policy)) {
    $PolicyRaw = Read-TextSmart $Policy
    $PolicyData = ConvertFrom-Json -InputObject $PolicyRaw
} else {
    $PolicyData = [pscustomobject]@{
        version = 1
        venue = $VenueNames
        allowed_domains = @()
        ignored_domains = @('wpad', '*.msedge.net', '*.footprintdns.com', '*.azurefd.net', 'go.microsoft.com',
            'www.microsoft.com', 'edge.microsoft.com', 'ieonline.microsoft.com', 'checkappexec.microsoft.com',
            'oneocsp.microsoft.com', 'crl.microsoft.com', 'ocsp.digicert.com')
        ignored_processes = @('svchost.exe', 'services.exe', 'System')
        process_grades = [pscustomobject]@{
            interactive = @('chrome.exe', 'msedge.exe', 'firefox.exe', 'iexplore.exe', 'opera.exe', 'brave.exe',
                'vivaldi.exe', '360se.exe', '360chrome.exe', 'qqbrowser.exe', 'sogouexplorer.exe', 'maxthon.exe')
            system = @('svchost.exe', 'lsass.exe', 'services.exe', 'smss.exe', 'csrss.exe', 'wininit.exe',
                'winlogon.exe', 'spoolsv.exe', 'taskhostw.exe', 'conhost.exe', 'sihost.exe', 'dwm.exe',
                'fontdrvhost.exe', 'wudfhost.exe', 'searchindexer.exe', 'msmpeng.exe', 'nissrv.exe')
        }
        high_risk = [pscustomobject]@{
            flag_direct_ip = $true
            flag_nonstandard_port = $true
            suspicious_tlds = @('top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'work')
        }
        updated_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    }
}

# ---------- merge network baseline ----------
if ($NetworkProfile) {
    if (!(Test-Path $NetworkProfile)) { throw "找不到网络基线补丁文件: $NetworkProfile" }
    $networkProfileRaw = [System.IO.File]::ReadAllText((Resolve-Path $NetworkProfile).Path)
    $NetworkProfileData = ConvertFrom-Json -InputObject $networkProfileRaw
    if ((('' + $NetworkProfileData.schema) -ne 'network_baseline_config_patch_v1')) {
        throw "-NetworkProfile 不是 network_baseline_config_patch_v1 JSON。"
    }
    foreach ($listName in @('allowed_domains', 'ignored_domains', 'ignored_processes', 'ignored_ips')) {
        $baseList = @($PolicyData.$listName | Where-Object { $_ })
        $patchList = @($NetworkProfileData.$listName | Where-Object { $_ })
    $PolicyData | Add-Member -Force -NotePropertyName $listName -NotePropertyValue @(($baseList + $patchList) | Select-Object -Unique)
    }
    Write-Host ("合并网络基线：DNS {0}，进程 {1}，公网IP {2}" -f
        @($PolicyData.ignored_domains).Count, @($PolicyData.ignored_processes).Count, @($PolicyData.ignored_ips).Count)
}

# ---------- previous keys (reuse unless -RotateKeys); manifest.csv holds fingerprints only ----------
$outRootName = if ($Venues.Count -eq 1) { $Venues[0] } else { 'combined_' + ($Venues -join '_') }
$outRoot = Join-Path $Out $outRootName
$prevSecrets = @{}
$prevBackup = Join-Path $outRoot 'keys-backup.json'
if (!$RotateKeys -and (Test-Path $prevBackup)) {
    try {
        foreach ($k in ((Read-TextSmart $prevBackup | ConvertFrom-Json))) {
            if ($k.machine_id -and $k.secret) { $prevSecrets[$k.account] = @{ mid = $k.machine_id; secret = $k.secret } }
        }
    } catch { }
    if ($prevSecrets.Count) { Write-Host ("复用上次发放的 machine_id/密钥 {0} 条（-RotateKeys 可强制轮换）" -f $prevSecrets.Count) }
}

# ---------- generate identities ----------
$entries = New-Object System.Collections.Generic.List[object]
$usedMids = @{}
foreach ($row in $rows) {
    $mid = ''; $secret = ''
    if ($prevSecrets.ContainsKey($row.account)) {
        $mid = $prevSecrets[$row.account].mid; $secret = $prevSecrets[$row.account].secret
    }
    if (!$mid) { $mid = New-MachineId; while ($usedMids.ContainsKey($mid)) { $mid = New-MachineId } }
    if (!$secret -or $secret.Length -lt 32) { $secret = New-Secret }
    $usedMids[$mid] = $true
    $entries.Add([pscustomobject]@{ account = $row.account; name = $row.name; venue = $row.venue; note = $row.note;
                                    machine_id = $mid; secret = $secret; fingerprint = (Get-SecretFingerprint $secret) })
}

# ---------- output tree (only after validation passed) ----------
if (Test-Path $outRoot) { Write-Host "输出目录已存在，将覆盖: $outRoot" -ForegroundColor Yellow }
New-Item -ItemType Directory -Force -Path $outRoot | Out-Null
$seatsRoot = Join-Path $outRoot 'seats'
New-Item -ItemType Directory -Force -Path $seatsRoot | Out-Null
$collectorDir = Join-Path $outRoot 'collector-server'
New-Item -ItemType Directory -Force -Path $collectorDir | Out-Null

# roster.json / secrets.json / keys-backup.json / policy.json for the collector
$rosterJson = @(); $secretsJson = @{}; $backupRows = @()
foreach ($e in $entries) {
    $rosterJson += [pscustomobject]@{ account = $e.account; name = $e.name; venue = $e.venue; machine_id = $e.machine_id }
    $secretsJson[$e.machine_id] = $e.secret
    $backupRows += [pscustomobject]@{ account = $e.account; name = $e.name; venue = $e.venue; machine_id = $e.machine_id; secret = $e.secret }
}
Write-Utf8Bom (Join-Path $outRoot 'roster.json')   (($rosterJson | ConvertTo-Json -Depth 4) + "`r`n")
Write-Utf8Bom (Join-Path $outRoot 'secrets.json')  (($secretsJson | ConvertTo-Json -Depth 3) + "`r`n")
Write-Utf8Bom (Join-Path $outRoot 'keys-backup.json') (($backupRows | ConvertTo-Json -Depth 4) + "`r`n")
Write-JsonFile (Join-Path $outRoot 'policy.json') $PolicyData 6
Write-Utf8Bom (Join-Path $collectorDir 'roster.json') (($rosterJson | ConvertTo-Json -Depth 4) + "`r`n")
Write-Utf8Bom (Join-Path $collectorDir 'secrets.json') (($secretsJson | ConvertTo-Json -Depth 3) + "`r`n")
Write-JsonFile (Join-Path $collectorDir 'policy.json') $PolicyData 6

# dashboard.json: pre-hash -UiPassword when .NET supports SHA256 PBKDF2
if ($UiPassword) {
    $hash = New-Pbkdf2Hash $UiPassword
    if ($hash) {
        Write-Utf8Bom (Join-Path $collectorDir 'dashboard.json') ('{"password_hash": "' + $hash + '", "password_updated_at": "' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') + '"}')
    } else {
        Write-Utf8Bom (Join-Path $collectorDir 'dashboard.json') ('{"password_pending": "' + ($UiPassword -replace '"', '\"') + '"}')
        Write-Host '本机 .NET 不支持 SHA256 PBKDF2，已写入 pending 口令，采集器首次启动时会自动完成哈希。' -ForegroundColor Yellow
    }
}

# manifest.csv / 找人清单.csv
$manifest = 'account,name,venue,machine_id,secret_fingerprint' + "`r`n"
$findList = '账号,姓名,场地,座位包目录,备注' + "`r`n"
foreach ($e in $entries) {
    $seatName = ($e.name + '_' + $e.account).TrimEnd('.', ' ')
    $manifest += ('{0},{1},{2},{3},{4}' -f $e.account, $e.name, $e.venue, $e.machine_id, $e.fingerprint) + "`r`n"
    $findList += ('{0},{1},{2},{3},{4}' -f $e.account, $e.name, $e.venue,
        ('seats\' + $e.venue + '\' + $seatName), $e.note) + "`r`n"
}
Write-Utf8Bom (Join-Path $outRoot 'manifest.csv') $manifest
Write-Utf8Bom (Join-Path $outRoot '找人清单.csv') $findList

# ---------- embedded deploy-side templates (PS 2.0-safe on the target machine) ----------
$initPs1Template = @'
# init.ps1 v1.5 - install/uninstall the DNS monitoring prerequisites (elevated).
# Windows PowerShell 2.0-safe: no ConvertFrom-Json, no $PSScriptRoot, .NET registry API.
param(
    [ValidateSet('Install','Uninstall','Status')]
    [string]$Action = 'Install',
    [string]$DataDir = '',
    [string]$MachineId = ''
)
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$Channel = 'Microsoft-Windows-DNS-Client/Operational'
$ChannelSize = 134217728  # 128 MB ring buffer
if (!$DataDir) {
    $raw = [System.IO.File]::ReadAllText((Join-Path $here 'config.json'))
    $m = [regex]::Match($raw, '"data_dir"\s*:\s*"([^"]+)"')
    if ($m.Success) { $DataDir = $m.Groups[1].Value }
}
if (!$MachineId) {
    $raw = [System.IO.File]::ReadAllText((Join-Path $here 'config.json'))
    $m = [regex]::Match($raw, '"machine_id"\s*:\s*"([^"]+)"')
    if ($m.Success) { $MachineId = $m.Groups[1].Value }
}
function Invoke-Native([string]$exe, [string[]]$arguments) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = ($arguments -join ' ')
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd() + $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    return @{ ExitCode = $p.ExitCode; Output = $out }
}
function Get-ChannelState {
    $r = Invoke-Native 'wevtutil.exe' @('gl', $Channel)
    $enabled = ''; $size = ''
    foreach ($line in ($r.Output -split "`r?`n")) {
        if ($line -match '^enabled\s*:\s*(\S+)') { $enabled = $matches[1] }
        if ($line -match '^maxSize\s*:\s*(\d+)') { $size = $matches[1] }
    }
    return @{ Enabled = $enabled; Size = $size }
}
function Set-DoH([string]$browserKey, [bool]$off) {
    try {
        $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($browserKey, $true)
        if ($k -eq $null) {
            if ($off) {
                $k = [Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($browserKey)
                $k.SetValue('DnsOverHttpsMode', 'off')
            }
            return
        }
        if ($off) {
            $existing = $k.GetValue('DnsOverHttpsMode')
            if ($existing -ne $null) { $k.SetValue('DnsOverHttpsMode_prev', $existing) }
            $k.SetValue('DnsOverHttpsMode', 'off')
        } else {
            $prev = $k.GetValue('DnsOverHttpsMode_prev')
            if ($prev -ne $null) { $k.SetValue('DnsOverHttpsMode', $prev); $k.DeleteValue('DnsOverHttpsMode_prev') }
            else { $k.DeleteValue('DnsOverHttpsMode') }
        }
    } catch { Write-Host ("DoH 设置失败 {0}: {1}" -f $browserKey, $_.Exception.Message) }
}
switch ($Action) {
    'Install' {
        if (!$DataDir) { Write-Host '未找到 data_dir，跳过数据目录初始化'; }
        else {
            New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
            # BUILTIN\Users (S-1-5-32-545) Modify so the agent can write under any account.
            & icacls.exe $DataDir /grant '*S-1-5-32-545:(OI)(CI)M' | Out-Null
        }
        $state = Get-ChannelState
        if ($state.Enabled -ne '' -or $state.Size -ne '') {
            $json = '{"enabled": "' + $state.Enabled + '", "size": ' + $state.Size + '}'
            if ($DataDir) { [System.IO.File]::WriteAllText((Join-Path $DataDir 'channel-backup.json'), $json) }
        }
        $r1 = Invoke-Native 'wevtutil.exe' @('sl', $Channel, '/e:true')
        if ($r1.ExitCode -ne 0) { Write-Host ('启用 DNS 通道失败: ' + $r1.Output) }
        $r2 = Invoke-Native 'wevtutil.exe' @('sl', $Channel, ('/ms:' + $ChannelSize))
        if ($r2.ExitCode -ne 0) { Write-Host ('设置 DNS 通道大小失败: ' + $r2.Output) }
        Set-DoH 'SOFTWARE\Policies\Google\Chrome' $true
        Set-DoH 'SOFTWARE\Policies\Microsoft\Edge' $true
        Write-Host ('init: Install 完成 (machine=' + $MachineId + ', data=' + $DataDir + ')')
    }
    'Uninstall' {
        if ($DataDir -and (Test-Path (Join-Path $DataDir 'channel-backup.json'))) {
            try {
                $raw = [System.IO.File]::ReadAllText((Join-Path $DataDir 'channel-backup.json'))
                $mSize = [regex]::Match($raw, '"size"\s*:\s*(\d+)')
                $mEnabled = [regex]::Match($raw, '"enabled"\s*:\s*"([^"]+)"')
                if ($mSize.Success) { Invoke-Native 'wevtutil.exe' @('sl', $Channel, ('/ms:' + $mSize.Groups[1].Value)) | Out-Null }
                if ($mEnabled.Success -and $mEnabled.Groups[1].Value -eq 'false') { Invoke-Native 'wevtutil.exe' @('sl', $Channel, '/e:false') | Out-Null }
            } catch { Write-Host ('恢复 DNS 通道失败: ' + $_.Exception.Message) }
        }
        Set-DoH 'SOFTWARE\Policies\Google\Chrome' $false
        Set-DoH 'SOFTWARE\Policies\Microsoft\Edge' $false
        Write-Host 'init: Uninstall 完成'
    }
    'Status' {
        $state = Get-ChannelState
        Write-Host ('DNS 通道 enabled=' + $state.Enabled + ' maxSize=' + $state.Size)
        foreach ($bk in @('SOFTWARE\Policies\Google\Chrome', 'SOFTWARE\Policies\Microsoft\Edge')) {
            $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($bk)
            if ($k) { Write-Host ($bk + ' DnsOverHttpsMode=' + $k.GetValue('DnsOverHttpsMode')) }
        }
        Write-Host ('data_dir=' + $DataDir)
    }
}
'@

$deployPs1Template = @'
# deploy.ps1 v1.5 - deploy/uninstall the seat package (elevated). PS 2.0-safe.
# Run once from the seat folder (a USB stick is fine): the FIRST step copies the
# payload into the FINAL install directory, so the stick can be unplugged right
# after copying; every later step uses only that local copy.
param([switch]$Uninstall, [string]$SrcDir = '', [switch]$DryRun)
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (!$SrcDir) { $SrcDir = $here }
$raw = [System.IO.File]::ReadAllText((Join-Path $SrcDir 'config.json'))
$m = [regex]::Match($raw, '"machine_id"\s*:\s*"([^"]+)"'); $mid = $m.Groups[1].Value
$m = [regex]::Match($raw, '"data_dir"\s*:\s*"([^"]+)"');  $dataDir = $m.Groups[1].Value
$caches = Join-Path 'C:\ProgramData\Microsoft\Windows\Caches' $mid
$runPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
$runName = 'SchoolContestDnsMonitor_' + $mid
$payload = @('listener.py', 'guard.py', 'config.json', 'init.ps1', 'deploy.ps1')

function Find-Python {
    # v1.5: the agent runs from .py sources, so a Python is required. Try the py
    # launcher, then python/python3 on PATH; validate each candidate actually runs
    # (this also rejects the Windows Store stub, which exits non-zero), and prefer
    # the sibling pythonw.exe so the watchdog runs without a console window.
    $cands = @()
    foreach ($name in @('py', 'python', 'python3')) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { $cands += $cmd.Source }
    }
    foreach ($exe in $cands) {
        $out = & $exe -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -ne 0 -or !$out) { continue }
        $real = ('' + $out).Trim()
        if (!(Test-Path $real)) { continue }
        $pyw = Join-Path (Split-Path -Parent $real) 'pythonw.exe'
        if (Test-Path $pyw) { return $pyw }
        return $real
    }
    return ''
}

function Stop-Agent {
    # Kill legacy exe installs and any python running our scripts (v1.5 .py mode).
    & taskkill.exe /F /IM listener.exe /T 2>$null | Out-Null
    & taskkill.exe /F /IM guard.exe /T 2>$null | Out-Null
    $filter = "Name='python.exe' OR Name='pythonw.exe'"
    Get-WmiObject Win32_Process -Filter $filter -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -match 'listener\.(py|exe)|guard\.(py|exe)' } |
        ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}

if ($DryRun) {
    Write-Host ('dry-run: machine_id=' + $mid)
    Write-Host ('dry-run: data_dir=' + $dataDir)
    Write-Host ('dry-run: install dir=' + $caches)
    Write-Host ('dry-run: copy from ' + $SrcDir + ' -> ' + $caches + ': ' + ($payload -join ', '))
    Write-Host ('dry-run: Stop-Agent (taskkill listener/guard + WMI python* cmdline match)')
    $py = Find-Python
    if ($py) { Write-Host ('dry-run: python found: ' + $py) } else { Write-Host 'dry-run: python NOT found (deploy would fail)' }
    Write-Host ('dry-run: HKLM Run ' + $runName + ' = "<python>" "' + (Join-Path $caches 'guard.py') + '" --config "' + (Join-Path $caches 'config.json') + '"')
    Write-Host 'dry-run: self-check = guard.json fresh <=15s AND state.json fresh <=30s'
    exit 0
}

if ($Uninstall) {
    Stop-Agent
    $initExit = 0
    $runKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($runPath, $true)
    if ($runKey -ne $null -and $runKey.GetValue($runName) -ne $null) { $runKey.DeleteValue($runName) }
    if (Test-Path (Join-Path $caches 'init.ps1')) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $caches 'init.ps1') -Action Uninstall -DataDir $dataDir -MachineId $mid
        $initExit = $LASTEXITCODE
    }
    Start-Sleep -Seconds 1
    if (Test-Path $caches) { attrib.exe -h -s $caches | Out-Null; Remove-Item $caches -Recurse -Force -ErrorAction SilentlyContinue }
    if ($dataDir -and (Test-Path $dataDir)) { Remove-Item $dataDir -Recurse -Force -ErrorAction SilentlyContinue }
    if ($initExit -ne 0) {
        Write-Host 'uninstall: 失败——还原系统设置时出错，请查看上方错误信息。' -ForegroundColor Red
        Read-Host '卸载失败，按 Enter 关闭'
        exit 1
    }
    Write-Host 'uninstall: 已停止代理、还原系统设置并清理文件。'
    exit 0
}
# ---- install: copy to the FINAL directory first (no temp staging) ----
Stop-Agent
if (!(Test-Path $caches)) { New-Item -ItemType Directory -Force -Path $caches | Out-Null }
Write-Host ('正在复制文件到 ' + $caches + ' （复制开始后即可拔掉U盘）...')
foreach ($f in $payload) {
    Copy-Item (Join-Path $SrcDir $f) (Join-Path $caches $f) -Force
}
attrib.exe +h +s $caches | Out-Null
Get-ChildItem $caches | ForEach-Object { attrib.exe +h +s $_.FullName | Out-Null }
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $caches 'init.ps1') -Action Install -DataDir $dataDir -MachineId $mid
$py = Find-Python
if (!$py) {
    Write-Host 'deploy: 失败——本机未找到可用的 Python（需要 python/pythonw 或 py 启动器）。' -ForegroundColor Red
    Write-Host '请先安装 Python 3.8+（勾选 Add to PATH），然后重新运行 deploy.cmd。'
    Read-Host '部署失败，按 Enter 关闭'
    exit 1
}
# run-guard.cmd: start the watchdog from the final directory (used by start.vbs).
$rg = '@echo off' + "`r`n" + '"' + $py + '" "' + (Join-Path $caches 'guard.py') + '" --config "' + (Join-Path $caches 'config.json') + '"' + "`r`n"
[System.IO.File]::WriteAllText((Join-Path $caches 'run-guard.cmd'), $rg, (New-Object System.Text.ASCIIEncoding))
$runKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($runPath, $true)
$runKey.SetValue($runName, '"' + $py + '" "' + (Join-Path $caches 'guard.py') + '" --config "' + (Join-Path $caches 'config.json') + '"')
Start-Process -FilePath $py -ArgumentList ('"' + (Join-Path $caches 'guard.py') + '" --config "' + (Join-Path $caches 'config.json') + '"') -WindowStyle Hidden
# ---- self-check: guard.json fresh (<=15s) AND state.json fresh (<=30s) ----
# v1.5: no process-name checks (both sides run as python*.exe); freshness of the
# two watchdog-written files proves both loops are alive.
$deadline = (Get-Date).AddSeconds(40)
$ok = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 2
    $freshG = $false; $freshS = $false
    $guardFile = Join-Path $dataDir 'guard.json'
    $stateFile = Join-Path $dataDir 'state.json'
    if (Test-Path $guardFile) {
        if (((Get-Date) - (Get-Item $guardFile).LastWriteTime).TotalSeconds -le 15) { $freshG = $true }
    }
    if (Test-Path $stateFile) {
        if (((Get-Date) - (Get-Item $stateFile).LastWriteTime).TotalSeconds -le 30) { $freshS = $true }
    }
    if ($freshG -and $freshS) { $ok = $true; break }
}
$result = '{"deployed_at": "' + (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') + '", "machine_id": "' + $mid + '", "python": "' + ($py -replace '\\', '\\\\') + '", "caches": "' + ($caches -replace '\\', '\\\\') + '", "data_dir": "' + ($dataDir -replace '\\', '\\\\') + '", "self_check_ok": ' + $(if ($ok) { 'true' } else { 'false' }) + '}'
[System.IO.File]::WriteAllText((Join-Path $caches 'deploy.json'), $result)
if ($ok) { Write-Host 'deploy: 成功（guard/listener 均在运行，guard.json/state.json 已更新）。' }
else {
    Write-Host 'deploy: 失败——自检未完全通过，请查看 deploy.json 与事件日志。' -ForegroundColor Red
    Read-Host '部署失败，按 Enter 关闭'
    exit 1
}
'@

$deployCmdTemplate = @'
@echo off
rem Deploy this seat package. Files are copied straight into the FINAL install
rem directory (C:\ProgramData\Microsoft\Windows\Caches\<machine_id>) - no temp
rem staging - so the USB stick can be unplugged as soon as copying starts.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$q=[char]34; $s='%~dp0deploy.ps1'; $d='%~dp0.'; Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',($q+$s+$q),'-SrcDir',($q+$d+$q))"
    exit /b
)
rem Already elevated: run in this console. deploy.ps1 closes automatically when
rem successful and waits for Enter when it has failed.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy.ps1" -SrcDir "%~dp0."
'@

$uninstallCmdTemplate = @'
@echo off
rem Uninstall this seat package and restore system settings.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "$q=[char]34; $s='%~dp0deploy.ps1'; $d='%~dp0.'; Start-Process powershell.exe -Verb RunAs -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',($q+$s+$q),'-Uninstall','-SrcDir',($q+$d+$q))"
    exit /b
)
rem Already elevated: run in this console. Successful uninstall closes
rem automatically; errors from init.ps1 remain visible until Enter is pressed.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0deploy.ps1" -Uninstall -SrcDir "%~dp0."
$initCmdTemplate = @'
@echo off
rem Manually (re)install the DNS log channel / DoH-off / data dir prerequisites.
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator rights...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0init.ps1" -Action Install
pause
'@

$startVbsTemplate = @'
' start.vbs - start the deployed agent silently (double-click, no console window).
' v1.5: the agent runs from the final install directory via run-guard.cmd, which
' deploy.ps1 wrote with the machine's resolved python/pythonw.
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
seat = fso.GetParentFolderName(WScript.ScriptFullName)
raw = ""
On Error Resume Next
raw = fso.OpenTextFile(seat & "\config.json", 1).ReadAll()
On Error GoTo 0
machineId = ""
Set re = New RegExp
re.Pattern = """machine_id""\s*:\s*""([^""]+)"""
If re.Test(raw) Then machineId = re.Execute(raw)(0).SubMatches(0)
deployed = "C:\ProgramData\Microsoft\Windows\Caches\" & machineId
If machineId <> "" And fso.FileExists(deployed & "\run-guard.cmd") Then
    sh.Run """" & deployed & "\run-guard.cmd""", 0, False
Else
    MsgBox "未找到已部署的安装（run-guard.cmd）。请先双击 deploy.cmd 完成部署。", 48, "赛场DNS采集"
End If
'@

$stopVbsTemplate = @'
' stop.vbs - stop the listener/guard python processes on this machine (hidden).
Set sh = CreateObject("WScript.Shell")
cmd = "powershell -NoProfile -Command ""& taskkill.exe /F /IM listener.exe /T; & taskkill.exe /F /IM guard.exe /T; Get-WmiObject Win32_Process -Filter \""Name='python.exe' OR Name='pythonw.exe'\"" | Where-Object { $_.CommandLine -match 'listener\.(py|exe)|guard\.(py|exe)' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"""
sh.Run cmd, 0, True
'@

$seatReadmeTemplate = @'
本座位包使用说明（__NAME__ / 账号 __ACCOUNT__）
================================================
1. 把整个文件夹拷到学生机任意位置（U盘直接打开也行），双击 deploy.cmd，UAC 点"是"。
   - 脚本先把程序复制到本机安装目录 C:\ProgramData\Microsoft\Windows\Caches\__MID__
     （隐藏目录），复制开始后即可拔掉U盘，安装会继续完成；
   - 自动开启 DNS 记录通道、关闭 Chrome/Edge 加密 DNS、设置开机自启；
   - 需要本机已安装 Python 3.8+（deploy 会自动找 python/pythonw/py）。
2. 出现 "deploy: 成功" 即部署完成；约 15-30 秒后看板里本账号显示"在线"。
3. 手动启停：start.vbs / stop.vbs。开机自启已设置，无需人工干预。
4. 卸载：双击 uninstall.cmd（还原 DNS 通道与浏览器设置并删除安装文件）。
5. 遇到问题看安装目录里的 deploy.json（self_check_ok 是否为 true）。
注意：本程序仅记录 DNS 查询与公网连接，用于比赛防作弊；请不要删除或停用。
'@

$collectorStartShTemplate = @'
#!/usr/bin/env bash
# Start the collector in the foreground (Ctrl+C to stop). Data stays in this folder.
cd "$(dirname "$0")"
exec python3 collector.py --dir "$(pwd)" --port __PORT__ --web-port __WEBPORT__ --retain-days 7
'@

$collectorServiceTemplate = @'
[Unit]
Description=Contest DNS collector (UDP __PORT__ + dashboard __WEBPORT__, all venues)
After=network.target

[Service]
WorkingDirectory=/opt/nl-collector
ExecStart=/usr/bin/python3 /opt/nl-collector/collector.py --dir /opt/nl-collector --port __PORT__ --web-port __WEBPORT__ --retain-days 7
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
'@

$collectorReadmeTemplate = @'
采集器部署说明（场地 __VENUE__，Linux 服务器）
================================================
1. 把整个 collector-server 目录上传到服务器，例如 /opt/nl-collector：
   scp -r collector-server/* user@服务器:/opt/nl-collector/
2. 前台试跑：bash start-collector.sh（Ctrl+C 停止）。
   - UDP 采集端口 __PORT__（学生机发心跳/事件到这里，防火墙放行 UDP __PORT__ 入站）；
   - 看板 https://服务器IP或域名:__WEBPORT__（自签名证书，浏览器点"继续访问"）；
   - 首次启动生成 certs/（需 openssl）与 dashboard.json 随机口令；发放包已带口令则直接用。
   - 忘记口令：python3 collector.py --reset-password
   - policy.json 热更新：登录看板后，在“策略热更新”里选择新的 policy.json，导入立即生效。
3. 正式运行（systemd，开机自启）：
   sudo cp nl-collector.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now nl-collector
   sudo systemctl status nl-collector
   （python3 路径不同时先 which python3 再改 service 里的 ExecStart。）
4. 数据都在本目录：logs/*.jsonl（原始事件）、incidents.jsonl（聚合事件）、state.json（断点恢复）。
5. policy.json 热更新：登录看板后，在“策略热更新”里选择新的 policy.json，导入立即生效，无需重启服务。
6. 事件默认保留 7 天（--retain-days 可调）。
7. 本机 WSL 模拟：在 WSL 里进入该目录 bash start-collector.sh，学生机配置指向 WSL 的 IP。
'@

$importReadmeTemplate = @'
发放包导入说明（场地 __VENUE__，共 __COUNT__ 台机器）
================================================
一、裁判/采集端（Linux 服务器）
  1. 上传 collector-server\ 到服务器（如 /opt/nl-collector），bash start-collector.sh 试跑，
     正式环境用 nl-collector.service 注册 systemd 服务（见目录内 说明.txt）。
  2. 防火墙放行 UDP __PORT__ 入站；看板地址 https://服务器IP或域名:__WEBPORT__。
  3. 找人清单.csv / manifest.csv 供核对；keys-backup.json 务必离线备份保管。

二、学生机（按 seats\<场地>\姓名_账号 分类）
  1. 把对应文件夹整个拷到学生机（U盘或局域网共享均可）。
  2. 双击其中的 deploy.cmd，允许管理员权限；复制开始后即可拔掉U盘，等待 "deploy: 成功"。
  3. 学生机需已安装 Python 3.8+；开机自启已设置，重装系统后重新执行 deploy.cmd 即可。
  4. 比赛结束或机器回收时双击 uninstall.cmd 还原设置。

三、核对
  - 学生机部署后约 15-30 秒，看板"连接状态"里该账号应显示"在线"。
  - 每台机器的 machine_id 与密钥一一对应（manifest.csv），密钥泄露时用
    provision.ps1 -RotateKeys 重新发放。
'@

function Write-Template([string]$Path, [string]$Template, [hashtable]$Tokens, [bool]$Bom = $true) {
    $text = $Template
    foreach ($key in $Tokens.Keys) { $text = $text.Replace($key, [string]$Tokens[$key]) }
    if ($Bom) { Write-Utf8Bom $Path $text } else { [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.ASCIIEncoding)) }
}
function Write-UnixText([string]$Path, [string]$Template, [hashtable]$Tokens) {
    # LF line endings, no BOM: bash and systemd reject CRLF files.
    $text = $Template
    foreach ($key in $Tokens.Keys) { $text = $text.Replace($key, [string]$Tokens[$key]) }
    $text = $text.Replace("`r`n", "`n")
    [System.IO.File]::WriteAllText($Path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------- seat packages ----------
foreach ($e in $entries) {
    $seatName = ($e.name + '_' + $e.account).TrimEnd('.', ' ')
    $seatDir = Join-Path (Join-Path $seatsRoot $e.venue) $seatName
    New-Item -ItemType Directory -Force -Path $seatDir | Out-Null
    Copy-Item $ListenerPy (Join-Path $seatDir 'listener.py') -Force
    Copy-Item $GuardPy (Join-Path $seatDir 'guard.py') -Force
    $config = [pscustomobject]@{
        machine_id = $e.machine_id
        collector_host = $CollectorHost
        collector_port = $CollectorPort
        collector_ip = ''
        collector_resolve_seconds = 300
        shared_secret = $e.secret
        heartbeat_seconds = 15
        allowed_domains = @($PolicyData.allowed_domains | Where-Object { $_ })
        ignored_domains = @($PolicyData.ignored_domains | Where-Object { $_ })
        ignored_processes = @($PolicyData.ignored_processes | Where-Object { $_ })
        ignored_ips = @($PolicyData.ignored_ips | Where-Object { $_ })
        poll_seconds = 3
        stats_interval_seconds = 600
        state_file = 'state.json'
        local_log = 'alerts.jsonl'
        outbox_file = 'outbox.jsonl'
        guard_file = 'guard.json'
        data_dir = ('C:\ProgramData\SchoolContestDnsMonitor\' + $e.machine_id)
        tcp_watch = [pscustomobject]@{ enabled = $true; interval_seconds = 30 }
        report_failed_dns = $true
        report_resolver_errors = $false
        ignore_system_accounts = $true
    }
    Write-Utf8Bom (Join-Path $seatDir 'config.json') (($config | ConvertTo-Json -Depth 5) + "`r`n")
    $tokens = @{ __MID__ = $e.machine_id; __NAME__ = $e.name; __ACCOUNT__ = $e.account; __VENUE__ = $e.venue }
    Write-Template (Join-Path $seatDir 'init.ps1') $initPs1Template $tokens
    Write-Template (Join-Path $seatDir 'deploy.ps1') $deployPs1Template $tokens
    Write-Template (Join-Path $seatDir 'deploy.cmd') $deployCmdTemplate $tokens $false
    Write-Template (Join-Path $seatDir 'uninstall.cmd') $uninstallCmdTemplate $tokens $false
    Write-Template (Join-Path $seatDir 'init.cmd') $initCmdTemplate $tokens $false
    Write-Template (Join-Path $seatDir 'start.vbs') $startVbsTemplate $tokens $false
    Write-Template (Join-Path $seatDir 'stop.vbs') $stopVbsTemplate $tokens $false
    Write-Template (Join-Path $seatDir '说明.txt') $seatReadmeTemplate $tokens
}

# ---------- collector package (one Linux server handles every selected venue) ----------
Copy-Item $CollectorPy (Join-Path $collectorDir 'collector.py') -Force
$tokens = @{ __VENUE__ = $VenueNames; __PORT__ = $CollectorPort; __WEBPORT__ = $WebPort; __COUNT__ = $entries.Count }
Write-UnixText (Join-Path $collectorDir 'start-collector.sh') $collectorStartShTemplate $tokens
Write-UnixText (Join-Path $collectorDir 'nl-collector.service') $collectorServiceTemplate $tokens
Write-Template (Join-Path $collectorDir '说明.txt') $collectorReadmeTemplate $tokens
Write-Template (Join-Path $outRoot '导入说明.txt') $importReadmeTemplate $tokens

# self-signed cert for the dashboard (best effort via openssl on the provision machine)
$certDir = Join-Path $collectorDir 'certs'
$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if ($openssl) {
    New-Item -ItemType Directory -Force -Path $certDir | Out-Null
    # openssl writes key-generation progress to stderr; PS 5.1 promotes that to a
    # terminating error under $ErrorActionPreference='Stop', so relax it here.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    & openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj '/CN=contest-collector' `
        -keyout (Join-Path $certDir 'server.key') -out (Join-Path $certDir 'server.crt') 2>$null | Out-Null
    $ErrorActionPreference = $prevEap
    if (!(Test-Path (Join-Path $certDir 'server.crt'))) { Write-Host 'openssl 证书生成失败，采集器会在裁判机上自行重试或退回 HTTP。' -ForegroundColor Yellow }
} else {
    Write-Host '未找到 openssl：采集器首次启动时会在裁判机上尝试生成自签名证书，失败则退回 HTTP 8080。' -ForegroundColor Yellow
}

Write-Host ''
Write-Host ("发放完成：{0} 台机器 -> {1}" -f $entries.Count, $outRoot) -ForegroundColor Green
Write-Host ("  座位包: {0}\seats\<场地>\<姓名_账号>  （拷到学生机后双击 deploy.cmd；复制开始后即可拔U盘）" -f $outRoot)
Write-Host ("  采集器: {0}\collector-server  （上传到 Linux 服务器，bash start-collector.sh 或注册 systemd）" -f $outRoot)
Write-Host ("  看板:   https://<采集服务器IP或域名>:{0}  （口令见 dashboard.json / 发放时设定的口令）" -f $WebPort)
Write-Host  '  务必离线备份 keys-backup.json；manifest.csv 含密钥指纹用于核对。'

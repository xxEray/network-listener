$ErrorActionPreference = 'Stop'
# Multi-interpreter compatibility check (Windows PowerShell 2.0 compatible syntax).
# 1) Static : parse every source file under the grammar of Python 3.8..3.14
# 2) Runtime: --compat + --self-test under every locally available interpreter
# 3) PowerShell: parse provision.ps1 / test_compat.ps1
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root
$sources = @('baseline_network_profile.py', 'listener.py', 'collector.py', 'guard.py')

function Invoke-Checked([string]$exe, [string[]]$prefixArgs, [string[]]$extraArgs) {
    $all = @()
    if ($prefixArgs) { $all += $prefixArgs }
    $all += $extraArgs
    # Outer parentheses would capture stdout; Out-Host keeps the function's return value
    # limited to the numeric exit code.
    & $exe @all | Out-Host
    return $LASTEXITCODE
}

# ---------- 1. static grammar ----------
Write-Host '== 静态语法检查（3.8-3.14 语法规则） ==' -ForegroundColor Cyan
$pyCmd = (Get-Command py -ErrorAction SilentlyContinue)
$pythonCmd = (Get-Command python -ErrorAction SilentlyContinue)
$pyUsable = $false
if ($pyCmd) {
    & py --version 2>$null | Out-Null
    $pyUsable = ($LASTEXITCODE -eq 0)
}
$py = if ($pyUsable) { $pyCmd } else { $null }
if ($py) { $probeExe = 'py'; $probeArgs = @('-3.13') }
elseif ($pythonCmd) { $probeExe = 'python'; $probeArgs = @() }
else { throw '未找到 Python，无法执行静态语法检查。' }

$script = @'
import ast, sys
want = int(sys.argv[1])
limit = sys.version_info.minor
use = min(want, limit)
for path in sys.argv[2:]:
    src = open(path, encoding="utf-8").read()
    ast.parse(src, filename=path, feature_version=use)
print("OK 3.%d (parsed as 3.%d on running 3.%d)" % (want, use, limit))
'@
$tmp = Join-Path $env:TEMP '_compat_grammar.py'
Set-Content -LiteralPath $tmp -Value $script -Encoding ASCII
foreach ($minor in 8..14) {
    $runArgs = @($tmp, [string]$minor) + $sources
    if ((Invoke-Checked $probeExe $probeArgs $runArgs) -ne 0) { Remove-Item $tmp -Force; throw "语法检查失败: 3.$minor" }
}
Remove-Item $tmp -Force

# ---------- 2. runtime ----------
Write-Host "`n== 运行时自测（本机可用解释器） ==" -ForegroundColor Cyan
$interpreters = @()
if ($py) {
    $lines = & py -0p 2>$null
    foreach ($line in $lines) {
        if ("$line" -match '^\s*-V:(\d+\.\d+)\s+\*?\s*(.+?\.exe)\s*$') {
            $interpreters += ,@($matches[1], $matches[2])
        }
    }
}
if ($pythonCmd) { $interpreters += ,@('path', $pythonCmd.Source) }
foreach ($dir in @('D:\Soft\msys2\ucrt64\bin\python.exe', 'C:\Python38-32\python.exe', 'C:\Python313\python.exe')) {
    if (Test-Path $dir) { $interpreters += ,@('extra', $dir) }
}

$ran = 0
$failed = @()
$seen = @{}
foreach ($item in $interpreters) {
    $exe = $item[1]
    if (-not $exe) { continue }
    if ($seen.ContainsKey($exe)) { continue }
    $seen[$exe] = $true
    if (-not (Test-Path $exe)) { continue }
    $ver = (& $exe -c "import sys;print('%d.%d.%d' % sys.version_info[:3])" 2>$null)
    if ($LASTEXITCODE -ne 0) { continue }
    $bits = (& $exe -c "import struct;print(struct.calcsize('P')*8)" 2>$null)
    Write-Host ("--- {0} :: Python {1} ({2}-bit) ---" -f $exe, $ver, $bits)
    & $exe listener.py --compat
    if ($LASTEXITCODE -ne 0) { $failed += "compat $exe"; continue }
    & $exe listener.py --self-test --config ./config.json
    if ($LASTEXITCODE -ne 0) { $failed += "self-test $exe"; continue }
    & $exe guard.py --self-test
    if ($LASTEXITCODE -ne 0) { $failed += "guard $exe"; continue }
    & $exe collector.py --self-test
    if ($LASTEXITCODE -ne 0) { $failed += "collector $exe"; continue }
    $ran++
}

if ($ran -eq 0) { throw '没有可运行的 Python 解释器，运行时自测未执行。' }
if ($failed.Count) { throw ("以下解释器失败: " + ($failed -join '; ')) }
Write-Host ("运行时自测通过: {0} 个解释器" -f $ran) -ForegroundColor Green

# ---------- 3. PowerShell ----------
Write-Host "`n== PowerShell 脚本语法 ==" -ForegroundColor Cyan
foreach ($ps in @('provision.ps1', 'test_compat.ps1')) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $ps), [ref]$tokens, [ref]$errors) | Out-Null
    if ($errors.Count) { $errors | Format-List; throw "$ps 解析失败" }
    Write-Host "OK $ps"
}
Write-Host "`n全部兼容性检查通过。" -ForegroundColor Green

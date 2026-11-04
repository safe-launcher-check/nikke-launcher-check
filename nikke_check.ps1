# NIKKE PC launcher compromise (2026-11) - READ-ONLY indicator checker v0.2.0
# 파일 삭제, 레지스트리 변경, 프로세스 종료, 차단 설정, 외부 통신을 하지 않습니다. 발견 시 경고만 합니다.
# 관리자 권한 없이, 니케를 쓰던 Windows 계정으로 실행하세요.
# 기준 자료: MotherSphere 공개 기술 보고서 (2026-11-03 20:40 GMT 갱신본)
# 종료 코드: 0 = 흔적 미발견, 1 = 주의, 2 = 위험, 3 = 판정 제한

[CmdletBinding()]
param(
    [string[]]$NikkePath = @(),
    [string]$ReportDir = '',
    [switch]$NoPrompt,
    [switch]$DeepScan,
    [switch]$AllUsers
)

$ErrorActionPreference = 'Continue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }

$script:Findings = New-Object System.Collections.ArrayList
$script:Latin1 = [Text.Encoding]::GetEncoding(28591)
$script:MaxBytes = 1GB
$script:ReadErrors = 0
$script:StepFailed = 0
$script:ManualRegKeys = New-Object System.Collections.ArrayList
$script:ManualFolders = New-Object System.Collections.ArrayList
$script:ManualFiles = New-Object System.Collections.ArrayList
$script:KnownPayloadHash = 'cc0ad05bfe85940a6067b3a72c182d3953339129206634141926d5d0b35973ec'
$script:DllName = 'platform_experience_helper.dll'

function P {
    param([string]$Base, [Parameter(ValueFromRemainingArguments = $true)][string[]]$Parts)
    $r = $Base
    foreach ($x in $Parts) { $r = [IO.Path]::Combine($r, $x) }
    return $r
}

# 위험 = 에이전트 실행/지속성 흔적, 주의 = 변조 파일 또는 로더 흔적,
# 정상 = 검사했고 흔적 없음, 확인불가 = 검사 대상이 없거나 읽지 못함
function Add-Finding {
    param([string]$Level, [string]$Item, [string]$Detail)
    [void]$script:Findings.Add([PSCustomObject]@{ Level = $Level; Item = $Item; Detail = $Detail })
}

function Read-Shared {
    param([string]$Path)
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $len = [int]$fs.Length
        $buf = New-Object byte[] $len
        $off = 0
        while ($off -lt $len) {
            $n = $fs.Read($buf, $off, $len - $off)
            if ($n -le 0) { break }
            $off += $n
        }
        return $script:Latin1.GetString($buf, 0, $off)
    } finally { $fs.Dispose() }
}

# 파일별 문자열 개수를 셉니다. 일치한 내용 자체는 출력하지 않습니다(PC 이름, agent_pass 노출 방지).
function Search-Files {
    param([System.IO.FileInfo[]]$Files, [string[]]$Needles)
    $counts = @{}
    foreach ($n in $Needles) { $counts[$n] = 0 }
    $hitFiles = @{}
    foreach ($f in $Files) {
        if ($f.Length -gt $script:MaxBytes) { $script:ReadErrors++; continue }
        try { $text = Read-Shared $f.FullName } catch { $script:ReadErrors++; continue }
        foreach ($n in $Needles) {
            $c = [regex]::Matches($text, [regex]::Escape($n)).Count
            if ($c -gt 0) { $counts[$n] += $c; $hitFiles[$f.FullName] = $true }
        }
    }
    return [PSCustomObject]@{ Counts = $counts; HitFiles = @($hitFiles.Keys) }
}

function Get-FilesSafe {
    param([string]$Dir, [string]$Filter = '*', [switch]$Recurse)
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }
    $a = @{ LiteralPath = $Dir; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
    if ($Recurse) { $a.Recurse = $true }
    return @(Get-ChildItem @a | Where-Object { $_.Name -like $Filter })
}

function Format-Counts {
    param($Counts)
    return (($Counts.GetEnumerator() | Where-Object { $_.Value -gt 0 } |
        ForEach-Object { "'$($_.Key)' $($_.Value)건" }) -join ', ')
}

# 한 항목이 실패해도 나머지 검사를 계속하고, 실패 사실을 결과에 남깁니다.
function Invoke-Step {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body }
    catch {
        $script:StepFailed++
        Add-Finding '확인불가' $Name "검사 실패: $($_.Exception.Message)"
    }
}

function Get-RegDefault {
    param([string]$KeyPath)
    try { return (Get-Item -LiteralPath $KeyPath -ErrorAction Stop).GetValue('') } catch { return $null }
}

function Resolve-RegPath {
    param([string]$Value)
    if (-not $Value) { return '' }
    $v = [Environment]::ExpandEnvironmentVariables($Value).Trim()
    if ($v -match '^"([^"]+)"') { return $Matches[1] }
    return ($v -replace ',\s*-?\d+$', '')
}

# ---------- 1. 니케 설치 폴더 찾기 ----------
function Find-NikkeRoots {
    $found = New-Object System.Collections.ArrayList
    foreach ($p in $NikkePath) { [void]$found.Add($p) }
    if ($env:LOCALAPPDATA) { [void]$found.Add((P $env:LOCALAPPDATA 'NIKKE')) }

    $uninstall = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($u in $uninstall) {
        Get-ItemProperty -Path $u -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName -match 'NIKKE' -and $_.InstallLocation } |
            ForEach-Object { [void]$found.Add($_.InstallLocation) }
    }

    $skip = '^(Windows|\$Recycle\.Bin|System Volume Information|ProgramData|Users|Recovery|PerfLogs)$'
    $drives = Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | Where-Object { $_.Root -match '^[A-Za-z]:\\$' }
    foreach ($d in $drives) {
        $tops = Get-ChildItem -LiteralPath $d.Root -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notmatch $skip }
        foreach ($t in $tops) {
            if ($t.Name -match 'NIKKE') { [void]$found.Add($t.FullName) }
            Get-ChildItem -LiteralPath $t.FullName -Directory -Recurse -Depth 3 -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match 'NIKKE' } |
                ForEach-Object { [void]$found.Add($_.FullName) }
        }
    }

    if ($env:NIKKE_LAUNCHER) { [void]$found.Add($env:NIKKE_LAUNCHER) }
    foreach ($hive in @('HKCU:', 'HKLM:')) {
        $exe = Resolve-RegPath (Get-RegDefault "$hive\Software\Microsoft\Windows\CurrentVersion\App Paths\nikke_launcher.exe")
        if ($exe) {
            $d = Split-Path -Parent $exe
            for ($i = 0; $i -lt 4 -and $d; $i++) { [void]$found.Add($d); $d = Split-Path -Parent $d }
        }
    }

    $roots = @{}
    $addRoot = {
        param($c)
        if (-not $c) { return }
        $full = $null
        if (Test-Path -LiteralPath (P $c 'Launcher')) { $full = P $c 'Launcher' }
        elseif (Test-Path -LiteralPath (P $c 'intl_service')) { $full = $c }
        if ($full) { $roots[(Resolve-Path -LiteralPath $full).Path] = $true }
    }
    foreach ($c in $found) { & $addRoot $c }

    if ($DeepScan -or $roots.Count -eq 0) {
        Write-Host '설치 폴더 정밀 탐색 중입니다. 드라이브 크기에 따라 몇 분 걸릴 수 있습니다.'
        $deepSkip = '^(Windows|\$Recycle\.Bin|System Volume Information)$'
        foreach ($d in $drives) {
            Get-ChildItem -LiteralPath $d.Root -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch $deepSkip } | ForEach-Object {
                    Get-ChildItem -LiteralPath $_.FullName -Directory -Recurse -Depth 8 -Force -Filter 'intl_service' -ErrorAction SilentlyContinue |
                        ForEach-Object { & $addRoot (Split-Path -Parent $_.FullName) }
                }
        }
    }
    return @($roots.Keys)
}

Write-Host ''
Write-Host '=== 니케 PC 런처 감염 흔적 점검 (읽기 전용) ===' -ForegroundColor Cyan
Write-Host '아무것도 삭제하거나 변경하지 않습니다. 설치 폴더를 찾는 데 1~2분 걸릴 수 있습니다.'
Write-Host ''

$roots = @(Find-NikkeRoots)
if ($roots.Count -eq 0 -and -not $NoPrompt) {
    $ans = Read-Host '니케 설치 폴더를 찾지 못했습니다. 경로를 입력하세요 (없으면 그냥 Enter)'
    if ($ans) {
        $ans = $ans.Trim('"', ' ')
        if (Test-Path -LiteralPath (P $ans 'Launcher')) { $roots = @((P $ans 'Launcher')) }
        elseif (Test-Path -LiteralPath (P $ans 'intl_service')) { $roots = @($ans) }
        else { Write-Host '입력한 경로에 Launcher 폴더가 없어 건너뜁니다.' -ForegroundColor Yellow }
    }
}

# ---------- 2. 런처 실행 여부 ----------
$running = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match 'nikke|tbs_browser' })
if ($running.Count -gt 0) {
    $names = ($running | Select-Object -ExpandProperty ProcessName -Unique) -join ', '
    Add-Finding '주의' '런처 실행 중' "$names 실행 중. 이 도구는 종료하지 않으니 트레이까지 확인해 직접 닫으세요."
} else {
    Add-Finding '정상' '런처 실행 중' '니케 런처 관련 프로세스 없음'
}

# ---------- 3. 설치 폴더 로그 ----------
$strongLog = @('k2f_chan', 'agent started as', 'lua downloaded to log')
$logChecked = $false
foreach ($r in $roots) {
    $log = P $r 'intl_service' 'debug.log'
    $logs = @(Get-FilesSafe (P $r 'intl_service') 'debug*.log')
    if ($logs.Count -gt 0) {
        $logChecked = $true
        $res = Search-Files $logs ($strongLog + 'startup already in progress')
        $strong = 0
        foreach ($s in $strongLog) { $strong += $res.Counts[$s] }
        if ($strong -gt 0) {
            Add-Finding '위험' '런처 로그' "$log : 에이전트 실행 기록 ($(Format-Counts $res.Counts))"
            # PC 이름 자체는 결과에 남기지 않고 일치 여부만 표시합니다.
            foreach ($lf in $logs) {
                try { $t = Read-Shared $lf.FullName } catch { continue }
                $names = @([regex]::Matches($t, 'agent started as ([^"\r\n]+)') | ForEach-Object { $_.Groups[1].Value.Trim() } | Select-Object -Unique)
                if ($names.Count -gt 0) {
                    if ($names -contains $env:COMPUTERNAME) { Add-Finding '위험' '기록된 PC 이름' '로그의 PC 이름이 이 PC와 일치 (이름은 표시하지 않음)' }
                    else { Add-Finding '주의' '기록된 PC 이름' '로그의 PC 이름이 이 PC와 다름. PC 이름 변경 또는 다른 PC에서 복사한 폴더일 수 있음 (이름은 표시하지 않음)' }
                }
            }
        } elseif ($res.Counts['startup already in progress'] -gt 0) {
            Add-Finding '주의' '런처 로그' "$log : 'startup already in progress' 발견. 변조 코드가 돌았을 수 있으나 에이전트 시작 기록은 없음"
        } else {
            Add-Finding '정상' '런처 로그' "$log : 실행 기록 없음"
        }
    } else {
        Add-Finding '확인불가' '런처 로그' "$log 없음"
    }

    foreach ($tiny in @((P $r 'log' 'tinyget'), (P $r 'intl_service' 'log' 'tinyget'))) {
        $tinyFiles = @(Get-FilesSafe $tiny)
        if ($tinyFiles.Count -eq 0) { continue }
        $res = Search-Files $tinyFiles @('insight.bundle', 'insightjs.com')
        if ($res.HitFiles.Count -gt 0) {
            Add-Finding '위험' '다운로드 로그' "$tiny : 악성 페이로드 다운로드 기록 ($(Format-Counts $res.Counts))"
        } else {
            Add-Finding '정상' '다운로드 로그' "$tiny : 기록 없음"
        }
        foreach ($tf in $tinyFiles) {
            if ($tf.Name -eq 'k2f.lua') {
                Add-Finding '위험' '페이로드 파일' $tf.FullName
                [void]$script:ManualFiles.Add($tf.FullName)
            } elseif ($tf.Length -eq 205135) {
                $h = ''
                try { $h = (Get-FileHash -LiteralPath $tf.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }
                if ($h -eq $script:KnownPayloadHash) {
                    Add-Finding '위험' '페이로드 파일' "$($tf.FullName) : 공개된 페이로드 해시와 일치"
                } else {
                    Add-Finding '위험' '페이로드 파일' "$($tf.FullName) : 페이로드와 크기가 같음(205,135바이트). 빌드가 여러 개라 해시가 달라도 안전하다는 뜻은 아님"
                }
                [void]$script:ManualFiles.Add($tf.FullName)
            }
        }
    }
}
if ($roots.Count -eq 0) {
    Add-Finding '확인불가' '런처 로그' '설치 폴더를 찾지 못해 debug.log를 검사하지 못함 (삭제했거나 다른 위치에 설치)'
}

# ---------- 4. AppData의 런처 데이터 (니케 삭제 후에도 남음) ----------
$launcherDataFound = $false
foreach ($name in @('nikke_launcher', 'nikke_launcher_hmt')) {
    $base = P $env:APPDATA $name
    if (-not (Test-Path -LiteralPath $base)) { continue }
    $launcherDataFound = $true
    $tbs = P $base 'tbs_cache'

    $lsFiles = @(Get-FilesSafe (P $tbs 'Local Storage' 'leveldb'))
    if ($lsFiles.Count -gt 0) {
        $res = Search-Files $lsFiles @('k2f.agent')
        if ($res.HitFiles.Count -gt 0) {
            Add-Finding '위험' '에이전트 상태값' "$name Local Storage에서 k2f.agent 발견 (내용은 표시하지 않음)"
        } else {
            Add-Finding '정상' '에이전트 상태값' "$name Local Storage에 k2f.agent 없음 (압축된 .ldb에 숨은 옛 값은 못 볼 수 있음)"
        }
    } else {
        Add-Finding '확인불가' '에이전트 상태값' "$name Local Storage 없음"
    }

    $codeFiles = @(Get-FilesSafe (P $tbs 'Code Cache' 'js') -Recurse)
    $persist = @(Get-FilesSafe $tbs 'Network Persistent State' -Recurse)
    $res = Search-Files ($codeFiles + $persist) @('insightjs.com')
    if ($res.HitFiles.Count -gt 0) {
        Add-Finding '주의' '로더 흔적' "$name 캐시에서 insightjs.com 발견. 공격자 서버에 접속한 흔적이며, 에이전트 실행 여부는 다른 항목으로 판단"
    } elseif (($codeFiles.Count + $persist.Count) -gt 0) {
        Add-Finding '정상' '로더 흔적' "$name 코드 캐시에 insightjs.com 없음"
    }

    # 보고서에 공개된 변조 파일 ETag
    $httpFiles = @(Get-FilesSafe (P $tbs 'Cache') -Recurse)
    if ($httpFiles.Count -gt 0) {
        $res = Search-Files $httpFiles @(
            '50d1861152ea7f6875ffceb7d08445b5',
            '481e9b5ab8fb93406bf31980b53e0578',
            'b7d842200372ad0d9a84ef4cc8511311',
            'dd06875637a29cddd3bae2ba84142c78')
        if ($res.HitFiles.Count -gt 0) {
            Add-Finding '주의' '변조 파일 캐시' "$name HTTP 캐시에 변조 JS 파일이 남아 있음. 다음 실행 전 tbs_cache 삭제 필요"
        } else {
            Add-Finding '정상' '변조 파일 캐시' "$name HTTP 캐시에 알려진 변조 파일 없음"
        }
    }
}

# ---------- 5. 브라우저 지속성 DLL ----------
# PlatformExperienceHelper 폴더 자체는 Chrome 정상 폴더입니다. 폴더 이름만으로 판정하지 않습니다.
# DLL은 피해자별로 빌드된 것으로 보여 해시가 아니라 경로와 키로 판정합니다.
$script:DllPaths = @{}
function Test-TrustedSignature {
    param([string]$Path)
    if (-not (Get-Command Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) { return $false }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        return ($sig.Status -eq 'Valid' -and $sig.SignerCertificate.Subject -match 'Google|Microsoft')
    } catch { return $false }
}
function Register-Dll {
    param([string]$Path, [string]$Via)
    $key = $Path.ToLowerInvariant()
    if ($script:DllPaths.ContainsKey($key)) { return }
    $script:DllPaths[$key] = $true
    $parent = Split-Path -Leaf (Split-Path -Parent $Path)
    $grand = Split-Path -Leaf (Split-Path -Parent (Split-Path -Parent $Path))
    $isLayout = ($parent -match '^[0-9a-fA-F]{64}$' -and $grand -eq 'PlatformExperienceHelper')
    if (Test-TrustedSignature $Path) {
        Add-Finding '주의' '브라우저 DLL' "$Path : Google 또는 Microsoft 유효 서명이 있어 악성 판정은 하지 않음. 위치만 수동 확인 필요"
    } elseif ($isLayout) {
        Add-Finding '위험' '브라우저 악성 DLL' "$Path ($Via)"
        [void]$script:ManualFolders.Add((Split-Path -Parent $Path))
    } else {
        Add-Finding '주의' '브라우저 DLL' "$Path ($Via) : 같은 이름의 서명 없는 파일. 알려진 경로는 아니므로 추가 확인 필요"
    }
}

Invoke-Step '브라우저 DLL' {
    $searchRoots = @($env:LOCALAPPDATA, $env:APPDATA) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
    if ($searchRoots.Count -eq 0) { Add-Finding '확인불가' '브라우저 DLL' 'AppData 경로를 찾지 못함' }
    foreach ($root in $searchRoots) {
        Get-ChildItem -LiteralPath $root -Recurse -Depth 7 -File -Force -Filter $script:DllName -ErrorAction SilentlyContinue |
            ForEach-Object { Register-Dll $_.FullName 'AppData 검색' }
    }

    # DLL 없이 해시 폴더만 남은 경우. 18개 브라우저 프로필을 명시적으로 확인합니다.
    $browserRoots = @(
        'Google\Chrome\User Data', 'Google\Chrome SxS\User Data', 'Google\Chrome Beta\User Data', 'Google\Chrome Dev\User Data',
        'Chromium\User Data', 'Microsoft\Edge\User Data', 'Microsoft\Edge Beta\User Data', 'Microsoft\Edge Dev\User Data',
        'Microsoft\Edge SxS\User Data', 'BraveSoftware\Brave-Browser\User Data', 'BraveSoftware\Brave-Browser-Beta\User Data',
        'BraveSoftware\Brave-Browser-Nightly\User Data', 'Vivaldi\User Data', 'Yandex\YandexBrowser\User Data',
        'Thorium\User Data', 'CocCoc\Browser\User Data'
    ) | ForEach-Object { P $env:LOCALAPPDATA ($_ -replace '\\', [IO.Path]::DirectorySeparatorChar) }
    $browserRoots += @((P $env:APPDATA 'Opera Software' 'Opera Stable'), (P $env:APPDATA 'Opera Software' 'Opera GX Stable'))
    $present = @($browserRoots | Where-Object { Test-Path -LiteralPath $_ })
    foreach ($b in $present) {
        $peh = P $b 'PlatformExperienceHelper'
        if (-not (Test-Path -LiteralPath $peh)) { continue }
        Get-ChildItem -LiteralPath $peh -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '^[0-9a-fA-F]{64}$' -and -not (Test-Path -LiteralPath (P $_.FullName $script:DllName)) } |
            ForEach-Object { Add-Finding '주의' '브라우저 해시 폴더' "$($_.FullName) : DLL 없이 64자리 폴더만 남아 있음. 삭제된 흔적일 수 있음" }
    }
    if ($script:DllPaths.Count -eq 0) {
        Add-Finding '정상' '브라우저 DLL' "AppData에서 해당 DLL 없음, 브라우저 프로필 $($present.Count)개 확인. PlatformExperienceHelper 폴더 자체는 정상. 사용자 지정 프로필 경로는 찾지 못할 수 있음"
    }
}

# 에이전트 정리 코드가 지우는 구버전 경로로 추정. 정황 항목이라 주의로만 표시합니다.
$appDirs = @(
    (P $env:LOCALAPPDATA 'Google' 'Chrome' 'Application'),
    $(if ($env:ProgramFiles) { P $env:ProgramFiles 'Google' 'Chrome' 'Application' }),
    $(if (${env:ProgramFiles(x86)}) { P ${env:ProgramFiles(x86)} 'Google' 'Chrome' 'Application' })
) | Where-Object { $_ }
foreach ($a in $appDirs) {
    foreach ($dll in @('service_util.dll', 'platform_experience_helper.dll')) {
        $x = P $a 'PlatformExperienceHelper' $dll
        if ((Test-Path -LiteralPath $x) -and -not (Test-TrustedSignature $x)) { Add-Finding '주의' 'Chrome 구버전 경로' "$x 존재. 서명 없는 파일이라 추가 확인 필요" }
    }
}

# ---------- 6. 레지스트리 (HKCU만 악성, HKLM의 같은 CLSID는 Windows 정상) ----------
$clsidId = '{E77CC89B-7401-4C04-8CED-149DB35ADD04}'
function Test-UserHive {
    param([string]$HiveRoot, [string]$Label)
    $hit = $false
    foreach ($sub in @('Software\Classes\CLSID', 'Software\Classes\Wow6432Node\CLSID')) {
        $key = "$HiveRoot\$sub\$clsidId"
        if (Test-Path -LiteralPath $key) {
            $hit = $true
            $target = Resolve-RegPath (Get-RegDefault "$key\InprocServer32")
            $state = '연결 대상 없음'
            if ($target) { if (Test-Path -LiteralPath $target) { $state = "연결 파일 있음: $target" } else { $state = "연결 파일 없음: $target" } }
            Add-Finding '위험' '레지스트리' "$Label $sub\$clsidId 키 존재. $state"
            [void]$script:ManualRegKeys.Add("$Label\$sub\$clsidId")
            if ($target -and (Test-Path -LiteralPath $target)) { Register-Dll $target '레지스트리 연결' }
        }
        # 같은 DLL 이름을 가리키는 다른 COM 등록
        $base = "$HiveRoot\$sub"
        if (Test-Path -LiteralPath $base) {
            Get-ChildItem -LiteralPath $base -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.PSChildName -ieq $clsidId) { return }
                foreach ($srv in @('InprocServer32', 'LocalServer32')) {
                    $val = Get-RegDefault "$($_.PSPath)\$srv"
                    if ($val -and $val -match 'platform_experience_helper\.dll') {
                        $hit = $true
                        Add-Finding '위험' '레지스트리' "$Label $sub\$($_.PSChildName)\$srv 가 같은 이름의 DLL을 가리킴"
                        [void]$script:ManualRegKeys.Add("$Label\$sub\$($_.PSChildName)")
                    }
                }
            }
        }
    }
    return $hit
}
Invoke-Step '레지스트리' {
    if (-not (Test-UserHive 'HKCU:' 'HKCU')) { Add-Finding '정상' '레지스트리' 'HKCU CLSID 키 없음, 같은 DLL을 가리키는 COM 등록 없음' }
    if ($AllUsers -and (Test-Path 'Registry::HKEY_USERS')) {
        $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue |
            Where-Object { $_.PSChildName -match '^S-1-5-21-[\d-]+$' -and $_.PSChildName -ne $me } |
            ForEach-Object {
                $sid = $_.PSChildName
                $null = Test-UserHive "Registry::HKEY_USERS\$sid" "HKU\$sid"
                Add-Finding '정상' '다른 계정' "로드된 계정 $sid 레지스트리 확인 (로그아웃한 계정은 확인하지 못함)"
            }
    }
}

# ---------- 7. 임시 파일 ----------
$tempHits = @(Get-ChildItem -LiteralPath $env:TEMP -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'k2f-bcreds-*' -or $_.Name -like 'k2f_screen_*' })
if ($tempHits.Count -gt 0) {
    Add-Finding '위험' '임시 파일' "TEMP에서 $($tempHits.Count)개 발견: $(($tempHits | Select-Object -First 5 -ExpandProperty Name) -join ', ')"
} else {
    Add-Finding '정상' '임시 파일' 'k2f 임시 파일 없음 (악성코드가 사용 후 지우므로 없어도 안전 보장은 아님)'
}

# ---------- 8. 네트워크 ----------
$c2 = @('89.127.233.127', '89.126.250.172')
if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
    $conn = @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $c2 -contains $_.RemoteAddress })
    if ($conn.Count -gt 0) { Add-Finding '위험' '현재 연결' "공격자 서버 IP에 연결 중: $(($conn.RemoteAddress | Select-Object -Unique) -join ', ')" }
    else { Add-Finding '정상' '현재 연결' '공격자 서버 IP 연결 없음' }
} else {
    Add-Finding '확인불가' '현재 연결' 'Get-NetTCPConnection 사용 불가'
}
if (Get-Command Get-DnsClientCache -ErrorAction SilentlyContinue) {
    $dns = @(Get-DnsClientCache -ErrorAction SilentlyContinue | Where-Object { $_.Entry -match 'insightjs\.(com|org)$' })
    if ($dns.Count -gt 0) {
        Add-Finding '주의' 'DNS 캐시' "최근 조회 기록: $(($dns.Entry | Select-Object -Unique) -join ', '). insightjs.org는 제3자 경고 페이지이므로 그 도메인만 있으면 위험도가 낮음"
    } else {
        Add-Finding '정상' 'DNS 캐시' 'insightjs 조회 기록 없음 (재부팅하면 지워짐)'
    }
}

# ---------- 결과 ----------
if ($script:ReadErrors -gt 0) {
    Add-Finding '확인불가' '파일 읽기' "파일 $($script:ReadErrors)개를 읽지 못해 검사에서 빠짐"
    $script:StepFailed++
}
$danger = @($script:Findings | Where-Object { $_.Level -eq '위험' })
$warn = @($script:Findings | Where-Object { $_.Level -eq '주의' })
$limited = (-not $logChecked) -or ($script:StepFailed -gt 0)

if ($danger.Count -gt 0) {
    $verdict = '위험: 악성 에이전트가 이 PC에서 실행된 흔적이 있습니다.'; $color = 'Red'; $code = 2
} elseif ($warn.Count -gt 0) {
    $verdict = '주의: 실행 기록은 없지만 변조 파일이나 공격자 서버 접속 흔적이 있습니다.'; $color = 'Yellow'; $code = 1
} elseif ($script:StepFailed -gt 0) {
    $verdict = '판정 제한: 일부 검사를 끝내지 못했습니다. 아래 확인불가 항목을 확인하세요.'; $color = 'Yellow'; $code = 3
} elseif ($limited -and ($launcherDataFound)) {
    $verdict = '판정 제한: 런처를 쓴 흔적은 있으나 debug.log가 없어 실행 기록을 확인하지 못했습니다.'; $color = 'Yellow'; $code = 3
} elseif ($limited) {
    $verdict = '판정 제한: 이 Windows 계정에서 니케 PC 런처 사용 흔적을 찾지 못했습니다. 다른 계정이나 삭제된 설치는 확인하지 못합니다.'; $color = 'Yellow'; $code = 3
} else {
    $verdict = '알려진 흔적 미발견: 안전하다는 뜻은 아닙니다.'; $color = 'Green'; $code = 0
}

$lines = New-Object System.Collections.ArrayList
[void]$lines.Add('니케 PC 런처 감염 흔적 점검 결과')
[void]$lines.Add("점검 시각: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
[void]$lines.Add("설치 폴더: $(if ($roots.Count) { $roots -join '; ' } else { '찾지 못함' })")
[void]$lines.Add('')
[void]$lines.Add("판정: $verdict")
[void]$lines.Add('')
foreach ($lv in @('위험', '주의', '확인불가', '정상')) {
    foreach ($f in @($script:Findings | Where-Object { $_.Level -eq $lv })) {
        [void]$lines.Add("[$($f.Level)] $($f.Item): $($f.Detail)")
    }
}
[void]$lines.Add('')
if ($code -eq 2) {
    [void]$lines.Add('이 도구는 아무것도 변경하지 않았습니다. 다음 조치는 직접 하세요 (보고서 권고 순서).')
    [void]$lines.Add('1. 런처를 닫거나 인터넷을 끊기')
    [void]$lines.Add('2. HKCU 키 삭제 -> 재부팅 -> 64자리 폴더만 삭제 (PlatformExperienceHelper 폴더 전체와 HKLM 항목은 삭제 금지)')
    foreach ($k in $script:ManualRegKeys) { [void]$lines.Add("   레지스트리 키: $k") }
    foreach ($k in $script:ManualFolders) { [void]$lines.Add("   폴더: $k") }
    foreach ($k in $script:ManualFiles) { [void]$lines.Add("   파일: $k") }
    [void]$lines.Add('3. 가장 안전한 방법은 Windows 재설치')
    [void]$lines.Add('4. 깨끗한 다른 기기에서 비밀번호 변경, 2단계 인증 설정, 모든 세션 로그아웃')
    [void]$lines.Add('5. API 토큰, SSH 키, 개발자 자격증명 폐기 후 재발급')
    [void]$lines.Add('6. 암호화폐 지갑은 새 시드의 새 지갑으로 이전')
    [void]$lines.Add('백신 검사가 깨끗해도 제거를 보장하지 않습니다 (Defender 오프라인 검사가 DLL을 못 찾은 사례 보고).')
} else {
    [void]$lines.Add('참고')
    [void]$lines.Add('- 공개된 흔적만 검사합니다. 공격자가 흔적을 지웠거나 로그가 삭제됐으면 찾지 못합니다.')
    [void]$lines.Add('- 2026-10-24 이후 런처를 실행했다면 주요 비밀번호 변경과 세션 로그아웃을 권장합니다.')
    [void]$lines.Add('- 공식 조치 확인 전에는 런처를 열지 말고, 다시 열기 전 %APPDATA%\nikke_launcher\tbs_cache를 삭제하세요.')
}

Write-Host ''
Write-Host "판정: $verdict" -ForegroundColor $color
Write-Host ''
foreach ($l in ($lines | Select-Object -Skip 6)) {
    $c = 'Gray'
    if ($l -like '`[위험`]*') { $c = 'Red' } elseif ($l -like '`[주의`]*') { $c = 'Yellow' } elseif ($l -like '`[정상`]*') { $c = 'Green' }
    Write-Host $l -ForegroundColor $c
}

if (-not $ReportDir) { $ReportDir = [Environment]::GetFolderPath('Desktop') }
if (-not $ReportDir -or -not (Test-Path -LiteralPath $ReportDir)) { $ReportDir = $env:TEMP }
$out = P $ReportDir ("NIKKE_check_{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
try {
    [IO.File]::WriteAllLines($out, [string[]]$lines, (New-Object Text.UTF8Encoding($true)))
    Write-Host ''
    Write-Host "결과 파일: $out" -ForegroundColor Cyan
} catch {
    Write-Host "결과 파일 저장 실패: $($_.Exception.Message)" -ForegroundColor Yellow
}

exit $code

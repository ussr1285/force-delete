<#
.SYNOPSIS
  폴더나 파일을 잡고 있는 프로세스를 찾아 종료하고 강제로 삭제한다.

.EXAMPLE
  .\force-delete.ps1 "C:\Users\me\Downloads\old"
  .\force-delete.ps1 "D:\tmp\locked" -ListOnly     # 누가 잡고 있는지만 확인
  .\force-delete.ps1 "D:\tmp\cache" -KeepRoot      # 폴더는 남기고 안의 내용만 삭제
  .\force-delete.ps1 "D:\tmp\locked" -Yes          # 확인 질문 없이 바로 진행
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Path,
    [switch]$Yes,
    [switch]$ListOnly,
    [switch]$KeepRoot,
    [switch]$PauseAtEnd
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

# ---------------------------------------------------------------------------
# Native helpers: handle scan (handle.exe 와 같은 방식), Restart Manager, 재부팅 시 삭제
# ---------------------------------------------------------------------------
if (-not ('FdScan' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class FdLocker {
    public int Pid;
    public string Path;
    public string Source;
}

public static class FdScan {
    // ---------------- Restart Manager (파일 단위 잠금) ----------------
    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmStartSession(out uint h, int flags, string key);
    [DllImport("rstrtmgr.dll")] static extern int RmEndSession(uint h);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] static extern int RmRegisterResources(uint h, uint nFiles, string[] files, uint nApps, IntPtr apps, uint nSvc, string[] svcs);
    [DllImport("rstrtmgr.dll")] static extern int RmGetList(uint h, out uint needed, ref uint n, [In, Out] RM_PROCESS_INFO[] info, ref uint reasons);

    public static List<FdLocker> RestartManager(string[] files) {
        List<FdLocker> result = new List<FdLocker>();
        const int batch = 500;
        for (int i = 0; i < files.Length; i += batch) {
            int len = Math.Min(batch, files.Length - i);
            string[] chunk = new string[len];
            Array.Copy(files, i, chunk, 0, len);
            uint h;
            if (RmStartSession(out h, 0, Guid.NewGuid().ToString("N")) != 0) continue;
            try {
                if (RmRegisterResources(h, (uint)len, chunk, 0, IntPtr.Zero, 0, null) != 0) continue;
                uint needed = 0, n = 0, reasons = 0;
                int rc = RmGetList(h, out needed, ref n, null, ref reasons);
                if (rc == 234 && needed > 0) {
                    RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed];
                    n = needed;
                    if (RmGetList(h, out needed, ref n, info, ref reasons) == 0) {
                        for (int k = 0; k < n; k++) {
                            FdLocker l = new FdLocker();
                            l.Pid = info[k].Process.dwProcessId;
                            l.Path = null;
                            l.Source = info[k].strAppName;
                            result.Add(l);
                        }
                    }
                }
            } finally { RmEndSession(h); }
        }
        return result;
    }

    // ---------------- 시스템 핸들 테이블 스캔 (폴더 핸들, 현재 디렉터리까지 잡힘) ----------------
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int retLen);
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool DuplicateHandle(IntPtr srcProc, IntPtr src, IntPtr dstProc, out IntPtr dst, uint access, bool inherit, uint options);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint GetFileType(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern uint GetFinalPathNameByHandleW(IntPtr h, StringBuilder buf, uint len, uint flags);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool MoveFileExW(string from, string to, uint flags);

    static readonly IntPtr INVALID = new IntPtr(-1);

    // 이름 조회는 드물게 멈출 수 있어서(동기 파이프 등) 별도 스레드에서 시간 제한을 두고 돌린다.
    class NameWorker {
        IntPtr handle;
        string result;
        readonly StringBuilder sb = new StringBuilder(32768);
        readonly AutoResetEvent go = new AutoResetEvent(false);
        readonly AutoResetEvent done = new AutoResetEvent(false);

        public NameWorker() {
            Thread t = new Thread(Loop);
            t.IsBackground = true;
            t.Start();
        }

        void Loop() {
            while (true) {
                go.WaitOne();
                string r = null;
                try {
                    if (GetFileType(handle) == 1) { // FILE_TYPE_DISK
                        sb.Length = 0;
                        uint n = GetFinalPathNameByHandleW(handle, sb, (uint)sb.Capacity, 0);
                        if (n > 0 && n < sb.Capacity) r = sb.ToString();
                    }
                } catch { }
                result = r;
                done.Set();
            }
        }

        public bool TryQuery(IntPtr h, int timeoutMs, out string name) {
            handle = h;
            go.Set();
            if (done.WaitOne(timeoutMs)) { name = result; return true; }
            name = null;
            return false;
        }
    }

    public static string Normalize(string p) {
        if (p == null) return null;
        if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) return @"\\" + p.Substring(8);
        if (p.StartsWith(@"\\?\")) return p.Substring(4);
        return p;
    }

    static string NameOf(IntPtr h) {
        StringBuilder sb = new StringBuilder(32768);
        uint n = GetFinalPathNameByHandleW(h, sb, (uint)sb.Capacity, 0);
        if (n > 0 && n < sb.Capacity) return Normalize(sb.ToString());
        return null;
    }

    // 8.3 이름, 대소문자, 매핑 드라이브 등을 핸들 스캔 결과와 같은 형태로 맞춘다.
    public static string FinalPath(string longPath) {
        IntPtr h = CreateFileW(longPath, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (h == INVALID) return null;
        try { return NameOf(h); } finally { CloseHandle(h); }
    }

    public static List<FdLocker> Handles(string target, int selfPid) {
        List<FdLocker> result = new List<FdLocker>();
        string t = target.TrimEnd('\\');

        // 우리 프로세스에 알려진 파일 핸들을 하나 열어서 File 객체의 타입 번호를 알아낸다.
        IntPtr probe = CreateFileW(Environment.GetEnvironmentVariable("SystemRoot"), 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
        if (probe == INVALID) return result;
        try {
            int size = 1 << 22;
            IntPtr buf;
            while (true) {
                buf = Marshal.AllocHGlobal(size);
                int ret;
                int st = NtQuerySystemInformation(64, buf, size, out ret); // SystemExtendedHandleInformation
                if (st == unchecked((int)0xC0000004)) {
                    Marshal.FreeHGlobal(buf);
                    size = Math.Max(size * 2, ret + (1 << 20));
                    if (size > (1 << 30)) return result;
                    continue;
                }
                if (st != 0) { Marshal.FreeHGlobal(buf); return result; }
                break;
            }
            try {
                int ps = IntPtr.Size;
                long count = Marshal.ReadIntPtr(buf).ToInt64();
                long first = buf.ToInt64() + ps * 2;
                int entrySize = ps * 3 + 16;
                int offPid = ps, offHandle = ps * 2, offType = ps * 3 + 6;

                int fileType = -1;
                for (long i = 0; i < count; i++) {
                    IntPtr e = new IntPtr(first + i * entrySize);
                    if (Marshal.ReadIntPtr(e, offPid).ToInt64() == selfPid && Marshal.ReadIntPtr(e, offHandle) == probe) {
                        fileType = (ushort)Marshal.ReadInt16(e, offType);
                        break;
                    }
                }
                if (fileType < 0) return result;

                Dictionary<int, IntPtr> procs = new Dictionary<int, IntPtr>();
                HashSet<string> seen = new HashSet<string>();
                IntPtr me = GetCurrentProcess();
                NameWorker worker = new NameWorker();
                try {
                    for (long i = 0; i < count; i++) {
                        IntPtr e = new IntPtr(first + i * entrySize);
                        if ((ushort)Marshal.ReadInt16(e, offType) != fileType) continue;
                        int pid = (int)Marshal.ReadIntPtr(e, offPid).ToInt64();
                        if (pid == selfPid || pid <= 4) continue;

                        IntPtr ph;
                        if (!procs.TryGetValue(pid, out ph)) {
                            ph = OpenProcess(0x40, false, pid); // PROCESS_DUP_HANDLE
                            procs[pid] = ph;
                        }
                        if (ph == IntPtr.Zero) continue;

                        IntPtr dup;
                        if (!DuplicateHandle(ph, Marshal.ReadIntPtr(e, offHandle), me, out dup, 0, false, 2)) continue;

                        string name;
                        if (worker.TryQuery(dup, 250, out name)) {
                            CloseHandle(dup);
                            name = Normalize(name);
                            if (name == null) continue;
                            if (name.Equals(t, StringComparison.OrdinalIgnoreCase) ||
                                name.StartsWith(t + "\\", StringComparison.OrdinalIgnoreCase)) {
                                if (seen.Add(pid + "|" + name)) {
                                    FdLocker l = new FdLocker();
                                    l.Pid = pid;
                                    l.Path = name;
                                    l.Source = "handle";
                                    result.Add(l);
                                }
                            }
                        } else {
                            worker = new NameWorker(); // 멈춘 스레드는 버리고 새로 띄운다
                        }
                    }
                } finally {
                    foreach (IntPtr p in procs.Values) if (p != IntPtr.Zero) CloseHandle(p);
                }
            } finally { Marshal.FreeHGlobal(buf); }
        } finally { CloseHandle(probe); }
        return result;
    }

    public static bool DeleteOnReboot(string longPath) {
        return MoveFileExW(longPath, null, 4); // MOVEFILE_DELAY_UNTIL_REBOOT
    }
}
'@
}

# ---------------------------------------------------------------------------
# 출력 / 입력
# ---------------------------------------------------------------------------
function Write-Step([string]$m) { Write-Host ""; Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Note([string]$m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Write-Bad([string]$m)  { Write-Host "  [X]  $m" -ForegroundColor Red }

function Confirm-Yes([string]$question) {
    if ($Yes) { return $true }
    $a = Read-Host "$question (Y/N)"
    return ($a -match '^\s*(y|yes|ㅛ)\s*$')
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------------------
# 경로
# ---------------------------------------------------------------------------
function Get-LongPath([string]$p) {
    if ($p.StartsWith('\\?\')) { return $p }
    if ($p.StartsWith('\\'))   { return '\\?\UNC\' + $p.Substring(2) }
    return '\\?\' + $p
}

function Test-Exists([string]$p) {
    $lp = Get-LongPath $p
    return ([IO.Directory]::Exists($lp) -or [IO.File]::Exists($lp))
}

function Resolve-Target([string]$raw) {
    if ($null -eq $raw) { return $null }
    $p = $raw.Trim().Trim('"').Trim()
    if (-not $p) { return $null }
    $p = [Environment]::ExpandEnvironmentVariables($p)
    if (-not [IO.Path]::IsPathRooted($p)) { $p = Join-Path (Get-Location).ProviderPath $p }
    $p = [IO.Path]::GetFullPath($p)
    $root = [IO.Path]::GetPathRoot($p)
    if ($p.Length -gt $root.Length) { $p = $p.TrimEnd('\') }
    return $p
}

function Test-Under([string]$child, [string]$parent) {
    $c = $child.TrimEnd('\'); $pp = $parent.TrimEnd('\')
    return ($c -ieq $pp -or $c.StartsWith($pp + '\', [StringComparison]::OrdinalIgnoreCase))
}

# 지우면 안 되는 곳: 드라이브 루트, 시스템 폴더, 사용자 폴더 자체, 그리고 그 상위 폴더 전부
function Get-ProtectReason([string]$p) {
    $root = [IO.Path]::GetPathRoot($p)
    if ($p.TrimEnd('\') -ieq $root.TrimEnd('\')) { return '드라이브 루트는 지울 수 없습니다.' }

    $guarded = New-Object System.Collections.Generic.List[string]
    foreach ($x in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432,
                     $env:ProgramData, $env:USERPROFILE, $env:PUBLIC, $env:APPDATA, $env:LOCALAPPDATA,
                     $env:OneDrive, $PSScriptRoot)) {
        if ($x) { $guarded.Add($x) }
    }
    foreach ($sf in 'Desktop', 'MyDocuments', 'MyPictures', 'MyMusic', 'MyVideos') {
        $x = [Environment]::GetFolderPath($sf); if ($x) { $guarded.Add($x) }
    }
    try {
        $dl = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path
        if ($dl) { $guarded.Add($dl) }
    } catch { }

    foreach ($g in $guarded) {
        if (Test-Under $g $p) { return "보호 대상 경로입니다: $g" }
    }
    return $null
}

# ---------------------------------------------------------------------------
# 잠금 프로세스 찾기
# ---------------------------------------------------------------------------
$script:ProtectedNames = @(
    'system', 'idle', 'registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso',
    'svchost', 'fontdrvhost', 'dwm', 'memcompression', 'msmpeng', 'securityhealthservice', 'searchindexer'
)

function Get-SelfChain {
    $chain = @{}
    $all = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $all[[int]$_.ProcessId] = $_ }
    $cur = $PID
    for ($i = 0; $i -lt 8 -and $all.ContainsKey($cur); $i++) {
        $chain[$cur] = $true
        $cur = [int]$all[$cur].ParentProcessId
    }
    return $chain
}

function Get-Lockers([string]$target, [string[]]$files) {
    $procInfo = @{}
    Get-CimInstance Win32_Process | ForEach-Object { $procInfo[[int]$_.ProcessId] = $_ }

    $hits = New-Object System.Collections.Generic.List[object]
    $lp = Get-LongPath $target
    $final = [FdScan]::FinalPath($lp)
    if (-not $final) { $final = $target }

    foreach ($l in [FdScan]::Handles($final, $PID)) {
        $hits.Add([pscustomobject]@{ Pid = $l.Pid; What = $l.Path })
    }
    if ($files -and $files.Count -gt 0 -and $files.Count -le 20000) {
        foreach ($l in [FdScan]::RestartManager($files)) {
            $hits.Add([pscustomobject]@{ Pid = $l.Pid; What = '(파일 사용 중)' })
        }
    }
    foreach ($proc in $procInfo.Values) {
        if ($proc.ExecutablePath -and (Test-Under $proc.ExecutablePath $target)) {
            $hits.Add([pscustomobject]@{ Pid = [int]$proc.ProcessId; What = '(이 경로 안의 프로그램이 실행 중)' })
        }
    }

    $result = @()
    foreach ($g in ($hits | Group-Object Pid)) {
        $id = [int]$g.Name
        if ($id -eq $PID) { continue }
        $info = $procInfo[$id]
        $name = if ($info) { [IO.Path]::GetFileNameWithoutExtension($info.Name) } else { '?' }
        $result += [pscustomobject]@{
            Pid   = $id
            Name  = $name
            Exe   = if ($info) { $info.ExecutablePath } else { $null }
            Items = @($g.Group | ForEach-Object What | Select-Object -Unique)
        }
    }
    return ,$result
}

function Show-Lockers($lockers, $selfChain) {
    foreach ($l in $lockers) {
        $tag = ''
        if ($selfChain.ContainsKey($l.Pid)) { $tag = '  <- 이 창(또는 상위 창). 직접 닫아야 함' }
        elseif ($script:ProtectedNames -contains $l.Name.ToLower()) { $tag = '  <- 시스템 프로세스라 종료하지 않음' }
        elseif ($l.Name -ieq 'explorer') { $tag = '  <- 탐색기 창 닫기 / 재시작으로 처리' }
        Write-Host ("  PID {0,-6} {1}{2}" -f $l.Pid, $l.Name, $tag) -ForegroundColor White
        $shown = 0
        foreach ($it in $l.Items) {
            if ($shown -ge 5) { Write-Host ("               ... 외 {0}개" -f ($l.Items.Count - 5)) -ForegroundColor DarkGray; break }
            Write-Host "               $it" -ForegroundColor DarkGray
            $shown++
        }
    }
}

function Close-ExplorerWindows([string]$target) {
    $closed = 0
    try {
        $shell = New-Object -ComObject Shell.Application
        foreach ($w in @($shell.Windows())) {
            try {
                $wp = $w.Document.Folder.Self.Path
                if ($wp -and (Test-Under $wp $target)) { $w.Quit(); $closed++ }
            } catch { }
        }
    } catch { }
    if ($closed -gt 0) { Write-Ok "이 경로를 열고 있던 탐색기 창 $closed 개를 닫았습니다."; Start-Sleep -Milliseconds 500 }
}

function Stop-Lockers($lockers, $selfChain) {
    foreach ($l in $lockers) {
        if ($selfChain.ContainsKey($l.Pid)) { continue }
        if ($script:ProtectedNames -contains $l.Name.ToLower()) { continue }
        if ($l.Name -ieq 'explorer') { continue }
        try {
            Stop-Process -Id $l.Pid -Force -ErrorAction Stop
            try { Wait-Process -Id $l.Pid -Timeout 5 -ErrorAction SilentlyContinue } catch { }
            Write-Ok ("종료: {0} (PID {1})" -f $l.Name, $l.Pid)
        } catch {
            if (-not (Get-Process -Id $l.Pid -ErrorAction SilentlyContinue)) {
                Write-Ok ("이미 종료됨: {0} (PID {1})" -f $l.Name, $l.Pid)
            } else {
                Write-Bad ("종료 실패: {0} (PID {1}) - {2}" -f $l.Name, $l.Pid, $_.Exception.Message)
            }
        }
    }
}

function Restart-Explorer {
    Get-Process explorer -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 1
    if (-not (Get-Process explorer -ErrorAction SilentlyContinue)) { Start-Process explorer.exe }
    Start-Sleep -Seconds 1
    Write-Ok '탐색기를 재시작했습니다.'
}

# ---------------------------------------------------------------------------
# 삭제
# ---------------------------------------------------------------------------
function Test-Done([string]$p, [bool]$keepRoot) {
    $lp = Get-LongPath $p
    if ($keepRoot) {
        if (-not [IO.Directory]::Exists($lp)) { return $true }
        return -not ([IO.Directory]::EnumerateFileSystemEntries($lp).GetEnumerator().MoveNext())
    }
    return -not (Test-Exists $p)
}

function Clear-Attributes([string]$lp) {
    try {
        if ([IO.Directory]::Exists($lp)) {
            foreach ($e in [IO.Directory]::EnumerateFileSystemEntries($lp, '*', [IO.SearchOption]::AllDirectories)) {
                try { [IO.File]::SetAttributes($e, [IO.FileAttributes]::Normal) } catch { }
            }
            try { [IO.File]::SetAttributes($lp, [IO.FileAttributes]::Directory) } catch { }
        } elseif ([IO.File]::Exists($lp)) {
            [IO.File]::SetAttributes($lp, [IO.FileAttributes]::Normal)
        }
    } catch { }
}

function Invoke-DotNetDelete([string]$lp, [bool]$keepRoot) {
    if ([IO.Directory]::Exists($lp)) {
        if ($keepRoot) {
            $err = $null
            foreach ($c in @([IO.Directory]::EnumerateFileSystemEntries($lp))) {
                try {
                    if ([IO.Directory]::Exists($c)) { [IO.Directory]::Delete($c, $true) } else { [IO.File]::Delete($c) }
                } catch { if (-not $err) { $err = $_.Exception.Message } }
            }
            return $err
        }
        try { [IO.Directory]::Delete($lp, $true); return $null } catch { return $_.Exception.Message }
    }
    if ([IO.File]::Exists($lp)) {
        try { [IO.File]::Delete($lp); return $null } catch { return $_.Exception.Message }
    }
    return $null
}

function Invoke-ShellDelete([string]$p, [bool]$keepRoot) {
    $lp = Get-LongPath $p
    if ([IO.Directory]::Exists($lp)) {
        # 빈 폴더로 미러링하면 이름이 이상하거나 경로가 아주 긴 항목도 대부분 지워진다.
        $empty = Join-Path $env:TEMP ('fd-empty-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $empty | Out-Null
        try { & robocopy.exe $empty $p /MIR /R:0 /W:0 /NFL /NDL /NJH /NJS /NP *> $null } catch { }
        Remove-Item -LiteralPath $empty -Force -ErrorAction SilentlyContinue
        if (-not $keepRoot) { & cmd.exe /d /c "rd /s /q `"$lp`"" *> $null }
    } elseif ([IO.File]::Exists($lp)) {
        & cmd.exe /d /c "del /f /q /a `"$lp`"" *> $null
    }
}

function Grant-Ownership([string]$p) {
    Write-Note '소유권을 가져오고 Administrators 에 모든 권한을 줍니다...'
    & takeown.exe /f $p /r /d y *> $null
    & takeown.exe /f $p *> $null
    & icacls.exe $p /grant '*S-1-5-32-544:F' /t /c /q *> $null
}

function Remove-Target([string]$p, [bool]$keepRoot) {
    $lp = Get-LongPath $p
    Clear-Attributes $lp
    $err = Invoke-DotNetDelete $lp $keepRoot
    if (Test-Done $p $keepRoot) { return $null }

    Invoke-ShellDelete $p $keepRoot
    if (Test-Done $p $keepRoot) { return $null }

    if (Test-Admin) {
        Grant-Ownership $p
        Clear-Attributes $lp
        $err2 = Invoke-DotNetDelete $lp $keepRoot
        if ($err2) { $err = $err2 }
        if (Test-Done $p $keepRoot) { return $null }
        Invoke-ShellDelete $p $keepRoot
        if (Test-Done $p $keepRoot) { return $null }
    }
    if (-not $err) { $err = '알 수 없는 이유로 일부 항목이 남았습니다.' }
    return $err
}

function Register-RebootDelete([string]$p, [bool]$keepRoot) {
    $lp = Get-LongPath $p
    $entries = @()
    if ([IO.Directory]::Exists($lp)) {
        try { $entries = @([IO.Directory]::EnumerateFileSystemEntries($lp, '*', [IO.SearchOption]::AllDirectories)) } catch { }
        # 깊은 것부터 지워야 폴더가 비어 있는 상태로 지워진다
        $entries = @($entries | Sort-Object { $_.Length } -Descending)
        if (-not $keepRoot) { $entries += $lp }
    } else {
        $entries = @($lp)
    }
    $ok = 0
    foreach ($e in $entries) { if ([FdScan]::DeleteOnReboot($e)) { $ok++ } }
    return $ok
}

function Get-Summary([string]$p) {
    $lp = Get-LongPath $p
    if ([IO.File]::Exists($lp)) {
        $fi = New-Object IO.FileInfo $lp
        return [pscustomobject]@{ IsDir = $false; Files = @($lp); Count = 1; Bytes = $fi.Length }
    }
    $files = New-Object System.Collections.Generic.List[string]
    $bytes = [long]0
    try {
        $di = New-Object IO.DirectoryInfo $lp
        foreach ($f in $di.EnumerateFiles('*', [IO.SearchOption]::AllDirectories)) {
            $files.Add($f.FullName); $bytes += $f.Length
        }
    } catch { }
    return [pscustomobject]@{ IsDir = $true; Files = $files.ToArray(); Count = $files.Count; Bytes = $bytes }
}

function Format-Size([long]$b) {
    if ($b -ge 1GB) { return '{0:N2} GB' -f ($b / 1GB) }
    if ($b -ge 1MB) { return '{0:N1} MB' -f ($b / 1MB) }
    if ($b -ge 1KB) { return '{0:N0} KB' -f ($b / 1KB) }
    return "$b B"
}

# ---------------------------------------------------------------------------
# 한 경로 처리
# ---------------------------------------------------------------------------
function Invoke-ForceDelete([string]$target) {
    Write-Host ""
    Write-Host ('=' * 70) -ForegroundColor DarkGray
    Write-Host "대상: $target" -ForegroundColor White

    if (-not (Test-Exists $target)) { Write-Note '이미 없습니다.'; return $true }

    $why = Get-ProtectReason $target
    if ($why) { Write-Bad $why; return $false }

    $isDir = [IO.Directory]::Exists((Get-LongPath $target))
    $keep = [bool]($KeepRoot -and $isDir)
    $sum = Get-Summary $target
    if ($isDir) {
        $mode = if ($keep) { '폴더는 남기고 안의 내용만 삭제' } else { '폴더째 삭제' }
        Write-Host ("종류: 폴더 / 파일 {0}개 / {1} / {2}" -f $sum.Count, (Format-Size $sum.Bytes), $mode)
    } else {
        Write-Host ("종류: 파일 / {0}" -f (Format-Size $sum.Bytes))
    }

    $selfChain = Get-SelfChain

    Write-Step '잡고 있는 프로세스를 찾는 중...'
    $lockers = Get-Lockers $target $sum.Files
    if ($lockers.Count -eq 0) {
        Write-Ok '잡고 있는 프로세스가 없습니다.'
    } else {
        Show-Lockers $lockers $selfChain
    }

    if ($ListOnly) { return $true }

    $q = if ($lockers.Count -gt 0) { '위 프로세스를 강제 종료하고, 휴지통을 거치지 않고 영구 삭제할까요?' }
         else { '휴지통을 거치지 않고 영구 삭제할까요?' }
    if (-not (Confirm-Yes $q)) { Write-Note '취소했습니다.'; return $false }

    $explorerRestarted = $false
    $lastErr = $null
    for ($attempt = 1; $attempt -le 3; $attempt++) {
        if ($attempt -gt 1) {
            Write-Step "다시 확인 중... ($attempt/3)"
            $lockers = Get-Lockers $target (Get-Summary $target).Files
            if ($lockers.Count -gt 0) { Show-Lockers $lockers $selfChain }
        }

        Close-ExplorerWindows $target
        if ($lockers.Count -gt 0) {
            Write-Step '프로세스 종료'
            Stop-Lockers $lockers $selfChain
            Start-Sleep -Milliseconds 400
        }

        Write-Step '삭제'
        $lastErr = Remove-Target $target $keep
        if (-not $lastErr) { Write-Ok '삭제 완료.'; return $true }
        Write-Bad $lastErr

        $left = Get-Lockers $target (Get-Summary $target).Files
        $explorerHolds = @($left | Where-Object { $_.Name -ieq 'explorer' }).Count -gt 0
        $selfHolds = @($left | Where-Object { $selfChain.ContainsKey($_.Pid) }).Count -gt 0
        if ($selfHolds) {
            Write-Note '이 스크립트를 실행한 창(cmd/터미널)이 그 경로 안에 있습니다. 다른 폴더로 cd 한 뒤 다시 실행하세요.'
        }
        if ($explorerHolds -and -not $explorerRestarted) {
            if (Confirm-Yes '탐색기(explorer.exe)가 아직 잡고 있습니다. 탐색기를 재시작할까요? (열린 탐색기 창이 모두 닫힙니다)') {
                Restart-Explorer
                $explorerRestarted = $true
                continue
            }
        }
        if ($left.Count -eq 0 -and $attempt -ge 2) { break }
    }

    if (-not (Test-Admin)) {
        if (Confirm-Yes '관리자 권한으로 다시 시도할까요?') {
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", "`"$target`"", '-PauseAtEnd')
            if ($keep) { $argList += '-KeepRoot' }
            Start-Process powershell.exe -Verb RunAs -ArgumentList ($argList -join ' ')
            Write-Note '관리자 창에서 이어서 진행합니다.'
        }
        return $false
    }

    if (Confirm-Yes '지금 지울 수 없는 항목을 다음 재부팅 때 지우도록 예약할까요?') {
        $n = Register-RebootDelete $target $keep
        if ($n -gt 0) { Write-Ok "재부팅 때 삭제되도록 $n 개 항목을 예약했습니다." }
        else { Write-Bad '예약에 실패했습니다.' }
    }
    return $false
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
$exitCode = 0
try {
    $inputs = @($Path | Where-Object { $_ -and $_.Trim() })
    if ($inputs.Count -eq 0) {
        Write-Host '폴더나 파일을 잡고 있는 프로세스를 종료하고 강제로 삭제합니다.' -ForegroundColor Cyan
        $raw = Read-Host '삭제할 경로를 입력하세요 (탐색기에서 이 창으로 끌어다 놓아도 됩니다)'
        $inputs = @($raw)
    }

    $targets = @($inputs | ForEach-Object { Resolve-Target $_ } | Where-Object { $_ })
    if ($targets.Count -eq 0) { Write-Note '경로가 비어 있습니다.'; $exitCode = 1 }

    # 우리 프로세스의 현재 디렉터리가 대상 안에 있으면 그 자체가 잠금이 되므로 옮겨 둔다.
    [IO.Directory]::SetCurrentDirectory($env:TEMP)
    Set-Location -LiteralPath $env:TEMP

    foreach ($t in $targets) {
        $ok = $false
        try { $ok = Invoke-ForceDelete $t } catch { Write-Bad $_.Exception.Message }
        if (-not $ok) { $exitCode = 1 }
    }
} finally {
    if ($PauseAtEnd) { Write-Host ''; Read-Host '엔터를 누르면 닫습니다' | Out-Null }
}
exit $exitCode

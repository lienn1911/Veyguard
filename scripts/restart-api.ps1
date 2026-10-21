param([Parameter(Mandatory = $true)][string]$ProjectRoot)

$ErrorActionPreference = 'Stop'
$port = 8765
$base = (Resolve-Path -LiteralPath $ProjectRoot).Path
$python = (Get-Command python.exe -ErrorAction Stop).Source

try {
    $apiProcesses = @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -in @('python.exe', 'pythonw.exe') -and
        $_.CommandLine -match '(?i)-m\s+services\.api\s*$'
    })
    $listeners = @(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
    $apiIds = @($apiProcesses | ForEach-Object { $_.ProcessId })

    foreach ($listener in $listeners) {
        if ($apiIds -notcontains $listener.OwningProcess) {
            throw "Port $port belongs to another program (PID $($listener.OwningProcess)). Close it before starting SOC Desk."
        }
    }

    # Windows can allow several SO_REUSEADDR Python servers on the same port.
    # Stop every exact services.api instance after confirming the port owner.
    if ($listeners.Count -gt 0) {
        foreach ($process in $apiProcesses) {
            Stop-Process -Id $process.ProcessId -Force -ErrorAction Stop
        }
        Start-Sleep -Milliseconds 500
    }
    if (@(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue).Count -gt 0) {
        throw "Port $port is still occupied; the API was not started."
    }

    $api = Start-Process -FilePath $python -ArgumentList '-m', 'services.api' -WorkingDirectory $base `
        -WindowStyle Hidden -RedirectStandardOutput (Join-Path $base 'data/api.out.log') `
        -RedirectStandardError (Join-Path $base 'data/api.err.log') -PassThru

    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        Start-Sleep -Milliseconds 350
        if ($api.HasExited) { throw 'SOC Desk API exited during startup. Check data/api.err.log.' }
        try {
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:$port/api/auth/session" -TimeoutSec 2
            if ($null -ne $response.authenticated) {
                Write-Output 'SOC Desk API ready.'
                exit 0
            }
        } catch { }
    }
    throw 'SOC Desk API did not become ready. Check data/api.err.log.'
} catch {
    Write-Error $_.Exception.Message
    exit 1
}

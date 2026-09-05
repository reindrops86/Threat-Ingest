$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$port = 8502
while ($true) {
    try {
        $test = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
        $test.Start()
        $test.Stop()
        break
    }
    catch {
        $port++
    }
}

$pythonCmd = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCmd) {
    Write-Host "Starting Streamlit on port $port"
    & py -m streamlit run app.py --server.headless true --server.port $port --server.address 127.0.0.1
} else {
    Write-Host "Starting Streamlit on port $port"
    python -m streamlit run app.py --server.headless true --server.port $port --server.address 127.0.0.1
}

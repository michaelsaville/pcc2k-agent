# pcc2k-agent Windows bootstrap.
# Required env: PCC2K_BOOTSTRAP_TOKEN, PCC2K_FLEETHUB_URL

if (-not $env:PCC2K_BOOTSTRAP_TOKEN) { throw "PCC2K_BOOTSTRAP_TOKEN env var required" }
if (-not $env:PCC2K_FLEETHUB_URL)    { throw "PCC2K_FLEETHUB_URL env var required" }

$installDir = "C:\\Program Files\\pcc2k-agent"
$binPath    = "$installDir\\pcc2k-agent.exe"
$secretPath = "$installDir\\agent.env"

New-Item -ItemType Directory -Path $installDir -Force | Out-Null

Write-Host "==> downloading pcc2k-agent (windows-amd64)"
$tmp = "$installDir\\pcc2k-agent.new.exe"
Invoke-WebRequest -UseBasicParsing -Uri "$env:PCC2K_FLEETHUB_URL/install/pcc2k-agent-windows-amd64.exe" -OutFile $tmp
if (Test-Path $binPath) { Stop-Service -Name pcc2k-agent -Force -ErrorAction SilentlyContinue }
Move-Item -Force $tmp $binPath

Write-Host "==> enrolling with FleetHub"
$body = @{
  token     = $env:PCC2K_BOOTSTRAP_TOKEN
  hostname  = [System.Net.Dns]::GetHostName()
  os        = "windows"
  osVersion = [System.Environment]::OSVersion.VersionString
} | ConvertTo-Json -Compress

$enrollResponse = Invoke-RestMethod -Method Post \`
  -Uri "$env:PCC2K_FLEETHUB_URL/api/agent-ingest/enroll" \`
  -ContentType "application/json" \`
  -Body $body

$agentId     = $enrollResponse.agentId
$agentSecret = $enrollResponse.agentSecret
if (-not $agentId -or -not $agentSecret) {
  throw "enrollment failed: $($enrollResponse | ConvertTo-Json)"
}

# Write secret as a restricted env file. Service runs as LocalSystem
# which can read it; operator non-admins cannot.
$envLines = @(
  "PCC2K_AGENT_ID=$agentId",
  "PCC2K_FLEETHUB_AGENT_SECRET=$agentSecret",
  "PCC2K_FLEETHUB_URL=$($env:PCC2K_FLEETHUB_URL)"
)
$envLines | Set-Content -Path $secretPath -Encoding ASCII

icacls $secretPath /inheritance:r | Out-Null
icacls $secretPath /grant:r "SYSTEM:(R)" "Administrators:(R)" | Out-Null

Write-Host "==> installing service"
& $binPath install --service-name pcc2k-agent --env-file $secretPath
& $binPath start

Write-Host "==> pcc2k-agent enrolled as $agentId and started."

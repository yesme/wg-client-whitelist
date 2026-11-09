# Install the delta between the master suffix list and live NRPT rules.
# Run elevated (UAC). Idempotent - only adds what is missing.
# Usage:  powershell -File nrpt_install.ps1 -MasterPath lists\nrpt_domains.txt
param(
  [Parameter(Mandatory = $true)][string]$MasterPath,
  [string[]]$NameServers = @("223.5.5.5", "119.29.29.29"),
  [string]$Log = "nrpt_install.log"
)
Start-Transcript -Path $Log -Force
try {
  $master = Get-Content $MasterPath | Where-Object { $_ } |
    ForEach-Object { $_.Trim().TrimStart(".") } | Select-Object -Unique
  $existing = @(Get-DnsClientNrptRule | ForEach-Object { $_.Namespace.TrimStart(".") })
  $todo = @($master | Where-Object { $existing -notcontains $_ })
  Write-Output ("existing rules: " + $existing.Count + ", to add: " + $todo.Count)
  $i = 0
  foreach ($d in $todo) {
    try {
      Add-DnsClientNrptRule -Namespace ("." + $d) -NameServers $NameServers `
        -ErrorAction Stop
      $i++
    } catch {
      Write-Output "  FAIL: $d"
    }
  }
  Write-Output ("added: " + $i)
  Write-Output ("total rules now: " + @(Get-DnsClientNrptRule).Count)
  Write-Output "REMINDER: run blocklist_audit.py after bulk additions"
} finally {
  Stop-Transcript
}

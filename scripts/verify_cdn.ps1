# Three-way verification for NRPT candidate domains:
#   1) china-list membership  2) live resolve via domestic DNS  3) IP geo
# Usage:  powershell -File verify_cdn.ps1 -ChinaFile china_accel.conf [-Dns 223.5.5.5]
# Edit $Cands for your candidates. ASCII only (PowerShell 5.1 GBK pitfall).
param(
  [string]$ChinaFile = "china_accel.conf",
  [string]$Dns = "223.5.5.5"
)
$Cands = [ordered]@{
  "cibntv.net"       = "youku/ali OTT streaming CDN (example)"
  "tencentcs.com"    = "tencent cloud CDN (example)"
  "kwimgs.com"       = "kuaishou content CDN (example)"
  "iq.com"           = "intl service (expect reject, example)"
}
if (-not (Test-Path $ChinaFile)) {
  "china-list file missing; download accelerated-domains.china.conf first"
  exit 1
}
$chinaTxt = Get-Content $ChinaFile -Raw
$ipMap = @{}
foreach ($d in $Cands.Keys) {
  $ips = @(Resolve-DnsName $d -Server $Dns -Type A -DnsOnly -NoHostsFile `
      -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -and $_.IPAddress -notmatch ':' } |
    Select-Object -First 2 -ExpandProperty IPAddress)
  $inList = $chinaTxt -match ("/" + [regex]::Escape($d) + "/")
  $note = $Cands[$d]
  if (-not $ips) {
    "{0,-22} {1,-8} NXDOMAIN  {2}" -f $d, $(if($inList){'IN-LIST'}else{'no'}), $note
    continue
  }
  foreach ($ip in $ips) { $ipMap[$ip] = $d }
  "{0,-22} {1,-8} OK  {2}  [{3}]" -f $d, $(if($inList){'IN-LIST'}else{'no'}), $note, ($ips -join ' ')
}
""
"=== GEO (batch via ip-api; rides whichever path ip-api.com takes) ==="
$ips = @($ipMap.Keys)
for ($i = 0; $i -lt $ips.Count; $i += 50) {
  $batch = @($ips[$i..([Math]::Min($i+49, $ips.Count-1))])
  $json = '["' + ($batch -join '","') + '"]'
  $resp = & curl.exe -s --max-time 30 -H "Content-Type: application/json" -d $json `
    "http://ip-api.com/batch?fields=status,country,isp,query"
  ($resp | ConvertFrom-Json) | ForEach-Object {
    "{0,-22} {1,-4} {2,-28} {3}" -f $ipMap[$_.query], $_.country, $_.isp, $_.query
  }
}
""
"verdict guide: IN-LIST + CN IP = add | intl/foreign IP = reject"
"apex answers 0.0.0.1 from ALL resolvers = query the authoritative NS:"
"  owner-side null route (defensive registration), do not add"

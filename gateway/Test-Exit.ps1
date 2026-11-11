param(
    [Parameter(Mandatory)][ValidateSet("Before","Connected","After")][string]$Phase,
    [Parameter(Mandatory)][string]$Region,
    [Parameter(Mandatory)][ipaddress]$ExpectedExit,
    [string]$Report = "vpn-pilot.csv"
)
$ErrorActionPreference = "Stop"
$ipv4 = & curl.exe --fail --silent --show-error -4 --max-time 10 https://api.ipify.org
if ($LASTEXITCODE -ne 0) { throw "IPv4 observation failed; retry before drawing conclusions." }
$observed = [ipaddress]::Parse($ipv4.Trim())
$ipv6 = & curl.exe --fail --silent -6 --max-time 8 https://api64.ipify.org
$v6Reached = $LASTEXITCODE -eq 0
$result = [pscustomobject]@{
    TimeUTC = [datetime]::UtcNow.ToString("o")
    Phase = $Phase
    Region = $Region
    ObservedIPv4 = $observed.IPAddressToString
    MatchesExit = $observed.Equals($ExpectedExit)
    IPv6ProbeSucceeded = $v6Reached
}
$result | Export-Csv -Append -NoTypeInformation -Path $Report
$result
if ($Phase -eq "Connected" -and (!$result.MatchesExit -or $v6Reached)) {
    throw "Connected result differs from the expected IPv4-only exit. Inspect the CSV."
}

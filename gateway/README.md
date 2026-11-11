# Regional exit gateway pilot

The C++ program remains the experimental tunnel. This mode uses WireGuard for
the network connection. Each dedicated Linux VPS provides one IPv4 exit.
Users import a separate profile for each region into WireGuard on Windows.
Activate one region at a time. The public exit IP belongs to that VPS;
geolocation databases may label it differently. GPS stays device-controlled.

## Prepare a gateway

Use a dedicated Ubuntu server on an isolated public network with no campus
or private service routes. Check the provider firewall and allow inbound UDP
51820 while keeping your existing management access. Determine the outbound
interface with `ip -4 route get 1.1.1.1`. On the gateway:

    sudo apt install wireguard iptables python3-venv
    python3 -m venv ~/wg-provision-env
    ~/wg-provision-env/bin/pip install 'cryptography>=40'
    read -rp "Public gateway IPv4: " endpoint
    read -rp "Outbound interface: " uplink
    ~/wg-provision-env/bin/python gateway/provision.py london "$endpoint" "$uplink" tanya-laptop --out ~/london-profiles
    sudo install -m 600 ~/london-profiles/wg-london.conf /etc/wireguard/
    echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/80-vpn-gateway.conf
    sudo sysctl -p /etc/sysctl.d/80-vpn-gateway.conf
    sudo systemctl enable --now wg-quick@wg-london

For multiple devices, list each name on the provisioning command before the
first run. Each gets its own key and address. Treat every generated config as
a secret. Transfer only the individual device's client config over an
authenticated channel. Keep profiles out of git. The gateway config belongs
only on the server. For another region repeat on another dedicated host with
a different region name. The configured address pool supports 253 devices
per independently provisioned region. Concurrent capacity needs measurement.

## Connect and verify on Windows

Install WireGuard for Windows. In PowerShell record the output of
`curl.exe -4 https://api.ipify.org` before connecting. Import
`clients/tanya-laptop/wg-london.conf` in WireGuard and activate it. Repeat the
command and compare with the gateway's own outbound public IPv4. The IP-check
service sees the requesting address. Check the latest handshake on the server
with `sudo wg show wg-london latest-handshakes`. IPv6 is routed into the
tunnel but this IPv4-only gateway provides no IPv6 internet service. Test
`curl.exe -6 --max-time 8 https://api64.ipify.org` with the tunnel active;
record any successful IPv6 response as a failed isolation check. Deactivate
and confirm the original connection returns.

## Pilot report and operations

Record gateway region, provider, commit, client OS, test time, public IPv4
before/during/after, IPv6 isolation result, handshake, and concurrent client
count. Retain addresses internally or redact them from the published report.
Repeat for each real gateway. Record throughput and latency under concurrent
load before proposing a supported user count. Capture no profile secrets.

To revoke one device immediately, remove its public key with
`sudo wg set wg-london peer DEVICE_PUBLIC_KEY remove` and delete the matching
peer section from /etc/wireguard/wg-london.conf to persist revocation.
To stop the gateway use `sudo systemctl disable --now wg-quick@wg-london`.
Remove the pilot sysctl file and restore the host's prior forwarding setting
when decommissioning. Institutional deployment requires a named operator,
an approved hosting network, and a review of key distribution and recovery.

Run the included PowerShell report collector once before connecting, once
while connected, and once after disconnecting. Substitute the observed public
IPv4 of your server. It appends timestamped observations to vpn-pilot.csv.

    .\gateway\Test-Exit.ps1 -Phase Before -Region london -ExpectedExit YOUR_SERVER_IP
    .\gateway\Test-Exit.ps1 -Phase Connected -Region london -ExpectedExit YOUR_SERVER_IP
    .\gateway\Test-Exit.ps1 -Phase After -Region london -ExpectedExit YOUR_SERVER_IP

An unsuccessful IPv6 probe alone cannot establish complete leak protection.
Compare before and after manually and test on each supported network.

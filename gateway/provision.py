"""Generate WireGuard profiles for one dedicated Linux IPv4 exit gateway."""
import argparse
import base64
import ipaddress
import os
from pathlib import Path
import re
import shutil
import tempfile

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def keypair():
    key = X25519PrivateKey.generate()
    return tuple(base64.b64encode(raw).decode("ascii") for raw in
                 (key.private_bytes_raw(), key.public_key().public_bytes_raw()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("region", help="short lowercase name, for example london")
    parser.add_argument("endpoint", type=ipaddress.IPv4Address)
    parser.add_argument("uplink", help="gateway internet interface, for example ens3")
    parser.add_argument("devices", nargs="+", help="unique device names")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.endpoint.is_global or args.endpoint.is_multicast:
        parser.error("endpoint must be a public unicast IPv4 address")
    if not re.fullmatch(r"[a-z][a-z0-9]{0,9}", args.region):
        parser.error("region must be 1 to 10 lowercase letters or digits")
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}", args.uplink):
        parser.error("invalid uplink interface name")
    if (len(args.devices) > 253 or len(set(args.devices)) != len(args.devices)
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", d) for d in args.devices)):
        parser.error("use up to 253 unique device names of 1 to 32 lowercase letters, digits or hyphens")
    if args.out.exists():
        parser.error("output directory already exists; existing keys must be preserved")
    os.umask(0o077)
    stage = Path(tempfile.mkdtemp(dir=args.out.parent))
    try:
        (stage / "clients").mkdir()
        server_key, server_public = keypair()
        iface = "wg-" + args.region
        server = [f"[Interface]\nAddress = 10.77.0.1/24\nPrivateKey = {server_key}\nListenPort = 51820"]
        # Dedicated exit host: prohibit access to the host, other peers and non-public destinations.
        rules = [("filter", "INPUT", "-i %i -j DROP"),
                 ("filter", "FORWARD", "-o %i -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"),
                 ("filter", "FORWARD", f"-i %i -o {args.uplink} -s 10.77.0.0/24 -j ACCEPT")]
        for network in ("0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
                        "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","224.0.0.0/4","240.0.0.0/4"):
            rules.append(("filter", "FORWARD", f"-i %i -d {network} -j DROP"))
        rules.append(("filter", "FORWARD", f"-i %i ! -o {args.uplink} -j DROP"))
        rules.append(("nat", "POSTROUTING", f"-s 10.77.0.0/24 -o {args.uplink} -j MASQUERADE"))
        for table, chain, rule in rules:
            server.append(f"PostUp = iptables -w -t {table} -I {chain} 1 {rule}")
        for table, chain, rule in reversed(rules):
            server.append(f"PostDown = iptables -w -t {table} -D {chain} {rule}")
        for host, device in enumerate(args.devices, 2):
            private, public = keypair()
            address = f"10.77.0.{host}/32"
            server.append(f"\n# {device}\n[Peer]\nPublicKey = {public}\nAllowedIPs = {address}")
            directory = stage / "clients" / device
            directory.mkdir()
            (directory / f"{iface}.conf").write_text(
                f"[Interface]\nPrivateKey = {private}\nAddress = {address}\nDNS = 1.1.1.1\n"
                f"\n[Peer]\nPublicKey = {server_public}\nEndpoint = {args.endpoint}:51820\n"
                "AllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n")
        (stage / f"{iface}.conf").write_text("\n".join(server) + "\n")
        stage.rename(args.out)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


if __name__ == "__main__":
    main()

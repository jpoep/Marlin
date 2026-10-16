#!/usr/bin/env python3
"""Build Marlin and flash it to the printer through the OctoPrint Pi.

The SKR Mini E3 is built with USB mass storage (STM32F103RC_btt_USB), so the Pi
sees the printer's SD card as a USB drive. This script:

  1. builds the firmware with PlatformIO
  2. refuses to continue if OctoPrint reports a running or paused print
  3. copies firmware.bin onto the printer's SD card via the Pi and verifies it
  4. reboots the board with M997 so the bootloader flashes the new firmware
  5. verifies the bootloader consumed firmware.bin and reconnects OctoPrint

Run `./flash-firmware.py --setup` once to request an OctoPrint API key and pin the
Pi's TLS certificate. Everything else is derived from the `octopi` entry in
~/.ssh/config. Only the Python standard library is used.
"""

import argparse
import hashlib
import http.client
import json
import os
import shlex
import shutil
import ssl
import subprocess
import sys
import time
from pathlib import Path

REPO_DIR = Path(__file__).resolve().parent
DEFAULT_ENV = "STM32F103RC_btt_USB"
DEFAULT_SSH_HOST = "octopi"
CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "marlin-flash" / "config.json"
HAPROXY_CERT = "/etc/haproxy/certs/haproxy.pem"

# Stable device names on the Pi (independent of /dev/sdX and /dev/ttyACMX numbering)
SD_GLOB = "/dev/disk/by-id/usb-MARLIN_*-part1"
SERIAL_GLOB = "/dev/serial/by-id/usb-STMicroelectronics_GENERICSTM32F103RC*"

# OctoPrint states in which the SD card and serial port are safe to touch
IDLE_STATES = ("Operational", "Offline", "Closed", "Error")


class FlashError(Exception):
    pass


def step(msg):
    print(f"\033[1m==> {msg}\033[0m", flush=True)


def info(msg):
    print(f"    {msg}", flush=True)


# --------------------------------------------------------------------------- #
# SSH helpers
# --------------------------------------------------------------------------- #

class Pi:
    def __init__(self, ssh_host):
        self.ssh_host = ssh_host
        self.base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", ssh_host]

    def hostname(self):
        """Resolve the real hostname/IP of the SSH alias, for talking to OctoPrint."""
        out = subprocess.run(["ssh", "-G", self.ssh_host], capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            key, _, value = line.partition(" ")
            if key == "hostname":
                return value
        raise FlashError(f"Could not resolve hostname of SSH host '{self.ssh_host}'")

    def run(self, script, *args, check=True):
        """Run a bash script on the Pi (strict mode), passing args safely."""
        cmd = self.base + ["bash", "-s", "--"] + [shlex.quote(str(a)) for a in args]
        res = subprocess.run(cmd, input="set -euo pipefail\nshopt -s nullglob\n" + script,
                             capture_output=True, text=True)
        if check and res.returncode != 0:
            raise FlashError(f"Command on the Pi failed:\n{(res.stderr or res.stdout).strip()}")
        return res

    def upload(self, local, remote):
        res = subprocess.run(["scp", "-q", "-o", "BatchMode=yes", str(local), f"{self.ssh_host}:{remote}"],
                             capture_output=True, text=True)
        if res.returncode != 0:
            raise FlashError(f"Upload failed: {res.stderr.strip()}")


# Shared shell snippet: find exactly one device matching a glob
FIND_ONE = """
find_one() {
  local matches=($1)
  if [ ${#matches[@]} -ne 1 ]; then
    echo "Expected exactly one device matching $1, found ${#matches[@]}" >&2
    return 1
  fi
  echo "${matches[0]}"
}
"""

# Mounts the SD card on a temporary mount point and always unmounts it again
MOUNT_SD = FIND_ONE + f"""
dev=$(find_one '{SD_GLOB}')
mnt=$(mktemp -d)
cleanup() {{
  if mountpoint -q "$mnt"; then sudo umount "$mnt"; fi
  rmdir "$mnt"
}}
trap cleanup EXIT
mount_sd() {{ sudo mount -t vfat -o "$1,uid=$(id -u),gid=$(id -g)" "$dev" "$mnt"; }}
"""

REMOTE_LIST_SD = MOUNT_SD + """
mount_sd ro
ls -la "$mnt"
"""

REMOTE_INSTALL = MOUNT_SD + """
src=$1
sha=$2
trap 'cleanup; rm -f "$src"' EXIT

mount_sd rw
# Keep the currently running firmware around for rollback
cur=$(find "$mnt" -maxdepth 1 -iname firmware.cur)
if [ -n "$cur" ]; then mv -f "$cur" "$mnt/FIRMWARE.OLD"; fi
# Write under a temporary name first so the bootloader never sees a partial file
cp "$src" "$mnt/firmware.tmp"
sync
mv -f "$mnt/firmware.tmp" "$mnt/firmware.bin"
sync
sudo umount "$mnt"

# Re-mount to verify what actually landed on the card, not the page cache
mount_sd ro
echo "$sha  $mnt/firmware.bin" | sha256sum --check --quiet
"""

REMOTE_VERIFY = MOUNT_SD + """
sha=$1
mount_sd ro
if [ -n "$(find "$mnt" -maxdepth 1 -iname firmware.bin)" ]; then
  echo "firmware.bin is still on the card: the bootloader did not flash it" >&2
  exit 2
fi
cur=$(find "$mnt" -maxdepth 1 -iname firmware.cur)
if [ -z "$cur" ]; then
  echo "firmware.bin is gone but there is no FIRMWARE.CUR" >&2
  exit 3
fi
echo "$sha  $cur" | sha256sum --check --quiet
"""

REMOTE_SEND_M997 = FIND_ONE + f"""
tty=$(find_one '{SERIAL_GLOB}')
stty -F "$tty" 115200 raw -echo
printf 'M997\\n' > "$tty"
"""

REMOTE_SERIAL_PRESENT = f"""
devs=({SERIAL_GLOB})
[ ${{#devs[@]}} -gt 0 ]
"""

REMOTE_CERT_FINGERPRINT = f"""
sudo openssl x509 -in {HAPROXY_CERT} -noout -fingerprint -sha256 | cut -d= -f2 | tr -d : | tr A-F a-f
"""


# --------------------------------------------------------------------------- #
# OctoPrint API
# --------------------------------------------------------------------------- #

class OctoPrint:
    """Minimal OctoPrint REST client that pins the Pi's self-signed certificate."""

    def __init__(self, host, cert_sha256, api_key=None):
        self.host = host
        self.cert_sha256 = cert_sha256
        self.api_key = api_key
        # Hostname/CA validation is replaced by pinning the exact certificate below
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE

    @staticmethod
    def served_fingerprint(host):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        conn = http.client.HTTPSConnection(host, timeout=10, context=ctx)
        conn.connect()
        try:
            return hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
        finally:
            conn.close()

    def request(self, method, path, body=None):
        conn = http.client.HTTPSConnection(self.host, timeout=15, context=self.ctx)
        try:
            conn.connect()
            served = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest()
            if served != self.cert_sha256:
                raise FlashError(f"OctoPrint TLS certificate changed (got {served}). "
                                 "If you replaced it on purpose, re-run with --setup.")
            headers = {"Content-Type": "application/json"}
            if self.api_key:
                headers["X-Api-Key"] = self.api_key
            conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
            resp = conn.getresponse()
            raw = resp.read()
            data = json.loads(raw) if raw and resp.getheader("Content-Type", "").startswith("application/json") else None
            return resp.status, data
        finally:
            conn.close()

    def connection(self):
        status, data = self.request("GET", "/api/connection")
        if status != 200:
            raise FlashError(f"OctoPrint /api/connection returned HTTP {status} (API key revoked? Re-run --setup)")
        return data["current"]

    def send_gcode(self, *commands):
        status, _ = self.request("POST", "/api/printer/command", {"commands": list(commands)})
        if status != 204:
            raise FlashError(f"OctoPrint refused to send {commands} (HTTP {status})")

    def connect(self, port=None, baudrate=None):
        body = {"command": "connect"}
        if port:
            body["port"] = port
        if baudrate:
            body["baudrate"] = baudrate
        status, _ = self.request("POST", "/api/connection", body)
        if status != 204:
            raise FlashError(f"OctoPrint could not reconnect (HTTP {status})")


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #

def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text())
    except FileNotFoundError:
        raise FlashError(f"No config at {CONFIG_PATH}. Run `{sys.argv[0]} --setup` first.")


def save_config(config):
    CONFIG_PATH.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(CONFIG_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(config, f, indent=2)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def setup(pi):
    host = pi.hostname()

    step("Pinning OctoPrint's TLS certificate")
    expected = pi.run(REMOTE_CERT_FINGERPRINT).stdout.strip()
    served = OctoPrint.served_fingerprint(host)
    if served != expected:
        raise FlashError(f"Certificate served at {host} ({served}) does not match "
                         f"{HAPROXY_CERT} on the Pi ({expected}). Not trusting it.")
    info(f"sha256 {served} (verified against the Pi over SSH)")

    step("Requesting an OctoPrint API key")
    octo = OctoPrint(host, served)
    status, _ = octo.request("GET", "/plugin/appkeys/probe")
    if status != 204:
        raise FlashError("OctoPrint's Application Keys plugin is not available")
    status, data = octo.request("POST", "/plugin/appkeys/request", {"app": "Marlin flash script"})
    if status != 201:
        raise FlashError(f"Key request failed (HTTP {status})")
    token = data["app_token"]
    info(f"Open https://{host} in your browser and click 'Allow' for 'Marlin flash script'...")
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        status, data = octo.request("GET", f"/plugin/appkeys/request/{token}")
        if status == 200:
            save_config({"cert_sha256": served, "api_key": data["api_key"]})
            info(f"Saved to {CONFIG_PATH}")
            return
        if status == 404:
            raise FlashError("The key request was denied or timed out")
        time.sleep(1)
    raise FlashError("Timed out waiting for approval")


def build(env):
    pio = shutil.which("pio") or str(Path.home() / ".platformio/penv/bin/pio")
    step(f"Building {env}")
    if subprocess.run([pio, "run", "-e", env], cwd=REPO_DIR).returncode != 0:
        raise FlashError("Build failed")


def wait_for_reboot(pi):
    """Wait for the board's USB serial device to disappear and come back."""
    def present():
        return pi.run(REMOTE_SERIAL_PRESENT, check=False).returncode == 0

    deadline = time.monotonic() + 15
    while present():
        if time.monotonic() > deadline:
            info("The board did not reset. Press the reset button on the board now.")
            deadline = time.monotonic() + 120
        time.sleep(0.5)
    info("Board is resetting, waiting for it to come back...")
    deadline = time.monotonic() + 120
    while not present():
        if time.monotonic() > deadline:
            raise FlashError("The board did not come back within 2 minutes")
        time.sleep(1)
    time.sleep(3)  # Give the USB mass storage device a moment to show up as well


def flash(pi, args):
    config = load_config()
    octo = OctoPrint(pi.hostname(), config["cert_sha256"], config["api_key"])

    firmware = REPO_DIR / ".pio" / "build" / args.env / "firmware.bin"
    if not args.no_build:
        build(args.env)
    if not firmware.is_file() or firmware.stat().st_size == 0:
        raise FlashError(f"No firmware at {firmware}")
    sha = hashlib.sha256(firmware.read_bytes()).hexdigest()
    built = time.strftime("%Y-%m-%d %H:%M", time.localtime(firmware.stat().st_mtime))
    info(f"{firmware.relative_to(REPO_DIR)}: {firmware.stat().st_size} bytes, built {built}, sha256 {sha[:16]}...")

    step("Checking printer state")
    current = octo.connection()
    state = current["state"]
    info(f"OctoPrint: {state}")
    if not state.startswith(IDLE_STATES):
        raise FlashError(f"Printer is busy ({state}). Not touching it.")
    was_connected = state == "Operational"

    if args.dry_run:
        step("Dry run: SD card contents")
        print(pi.run(REMOTE_LIST_SD).stdout)
        info("Dry run complete, nothing was changed.")
        return

    step("Copying firmware to the printer's SD card")
    remote_tmp = f"/tmp/marlin-firmware-{sha[:12]}.bin"
    pi.upload(firmware, remote_tmp)
    pi.run(REMOTE_INSTALL, remote_tmp, sha)
    info("firmware.bin written and verified")

    step("Rebooting the board into the bootloader")
    if was_connected:
        octo.send_gcode("M997")
    else:
        pi.run(REMOTE_SEND_M997)
    wait_for_reboot(pi)

    step("Verifying the flash")
    for _ in range(10):  # The SD card may enumerate a little after the serial port
        res = pi.run(REMOTE_VERIFY, sha, check=False)
        if res.returncode in (0, 2, 3):
            break
        time.sleep(1)
    if res.returncode != 0:
        raise FlashError(res.stderr.strip() or "Verification failed")
    info("Bootloader flashed the new firmware (FIRMWARE.CUR matches)")

    if was_connected:
        step("Reconnecting OctoPrint")
        octo.connect(current.get("port"), current.get("baudrate"))
        for _ in range(30):
            time.sleep(1)
            if octo.connection()["state"] == "Operational":
                info("Connected")
                break
        else:
            info("OctoPrint did not report 'Operational' yet, check its connection panel")

    step("Done")
    info("If the firmware version changed, EEPROM_AUTO_INIT has reset the stored settings.")
    info("Check with M503, then re-probe the bed: G28, G29, M500.")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--setup", action="store_true", help="request an OctoPrint API key and pin its certificate")
    parser.add_argument("--dry-run", action="store_true", help="build and run all checks, but do not flash")
    parser.add_argument("--no-build", action="store_true", help="flash the existing build without rebuilding")
    parser.add_argument("--env", default=DEFAULT_ENV, help=f"PlatformIO environment (default: {DEFAULT_ENV})")
    parser.add_argument("--ssh-host", default=DEFAULT_SSH_HOST, help=f"SSH host of the Pi (default: {DEFAULT_SSH_HOST})")
    args = parser.parse_args()

    pi = Pi(args.ssh_host)
    try:
        if args.setup:
            setup(pi)
        else:
            flash(pi, args)
    except FlashError as e:
        print(f"\033[31mError:\033[0m {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()

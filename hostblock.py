#!/usr/bin/env python3
"""
HostBlock - block ad, tracking and malware domains through the system hosts file.

What it does
------------
* Downloads a curated blocklist (default: StevenBlack's unified hosts list,
  https://github.com/StevenBlack/hosts) over verified HTTPS.
* Validates every line: only "block" entries (0.0.0.0 / 127.0.0.1) with
  well-formed domain names are kept, so a tampered list can never redirect
  a domain to some other server.
* Appends the entries to your hosts file inside a clearly marked section,
  leaving everything else in the file untouched.
* Saves an exact copy of your original hosts file first, so you can go back
  to it at any time.

Commands
--------
    python hostblock.py block      Download the list and add/update the blocked section
    python hostblock.py unblock    Remove only the blocked section (keeps your other edits)
    python hostblock.py restore    Put back the exact original hosts file from the backup
                                   (also removes the weekly auto-update task)
    python hostblock.py status     Show whether blocking is active (no admin needed)
    python hostblock.py update     Refresh the list using the current settings
    python hostblock.py schedule   Install a weekly auto-update task (default: Sunday 10:30)
    python hostblock.py unschedule Remove the weekly auto-update task
    python hostblock.py            Interactive menu

Weekly auto-update
------------------
`schedule` registers a task with the operating system's own scheduler
(Task Scheduler on Windows, launchd on macOS, a systemd timer or cron on
Linux) that runs `update` once a week with admin/root rights. The task runs
a protected copy of this script installed in an admin-only folder, so it
cannot be tampered with from a normal user account.

Running with Administrator / root privileges
--------------------------------------------
The hosts file is a protected system file, so block / unblock / restore must
run with elevated rights. `status` and `--dry-run` work without them.

  Windows
    1. Click Start, type "cmd" (or "PowerShell").
    2. Right-click "Command Prompt" -> "Run as administrator" -> Yes.
    3. cd /d "C:\\path\\to\\hostblock"
       python hostblock.py block
    Or, from a normal prompt, let the script show the UAC prompt itself:
       python hostblock.py --elevate block

  macOS / Linux
       sudo python3 hostblock.py block

Requires Python 3.8+ and only the standard library.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import plistlib
import re
import shlex
import shutil
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

APP_NAME = "HostBlock"
VERSION = "1.2.0"

STEVENBLACK_BASE = "https://raw.githubusercontent.com/StevenBlack/hosts/master"
DEFAULT_URL = f"{STEVENBLACK_BASE}/hosts"
# Optional StevenBlack extensions, in the order used by its "alternates/" paths.
EXTENSIONS = ("fakenews", "gambling", "porn", "social")

START_TAG = "# >>> HOSTBLOCK START"
END_TAG = "# <<< HOSTBLOCK END"
START_MARKER = f"{START_TAG} - managed by hostblock.py - do not edit inside this section >>>"
END_MARKER = f"{END_TAG} <<<"

# Addresses that mean "this domain goes nowhere". Anything else is a redirect and is rejected.
SINK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
BLOCK_IP = "0.0.0.0"
# Names that belong to the OS itself; never copy them from a downloaded list.
PROTECTED_NAMES = {
    "localhost", "localhost.localdomain", "local", "broadcasthost",
    "ip6-localhost", "ip6-loopback", "ip6-localnet", "ip6-mcastprefix",
    "ip6-allnodes", "ip6-allrouters", "ip6-allhosts",
}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
_IP_CHARS_RE = re.compile(r"^[0-9a-f:.]+(?:%[a-z0-9]+)?$")

MIN_ENTRIES_DEFAULT = 1000          # a real blocklist has tens of thousands
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
COMPACT_PER_LINE = 9                # Windows handles up to 9 names per hosts line well
WRITE_COMMANDS = ("block", "unblock", "restore", "update", "schedule", "unschedule")

# Weekly auto-update
TASK_NAME = "HostBlock Weekly Update"                    # Windows Task Scheduler
LAUNCHD_LABEL = "com.hostblock.update"                   # macOS
LAUNCHD_PLIST = Path("/Library/LaunchDaemons") / f"{LAUNCHD_LABEL}.plist"
SYSTEMD_UNIT = "hostblock-update"                        # Linux with systemd
SYSTEMD_DIR = Path("/etc/systemd/system")
CRON_FILE = Path("/etc/cron.d/hostblock")                # Linux without systemd
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
DAY_NAMES = dict(zip(DAYS, ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")))
CRON_DOW = {day: (i + 1) % 7 for i, day in enumerate(DAYS)}  # cron and launchd: 0 = Sunday
DEFAULT_DAY, DEFAULT_TIME = "sun", "10:30"
LOG_MAX_BYTES = 1_000_000
# On Windows, stop helper programs (ipconfig, schtasks) from flashing a console window
# when HostBlock runs without one (the GUI, or the scheduled task under pythonw.exe).
NO_WINDOW = {"creationflags": 0x08000000} if os.name == "nt" else {}

# Read/write the hosts file byte-for-byte: no newline translation, and any
# non-UTF-8 bytes survive the round trip unchanged.
FILE_OPTS = {"encoding": "utf-8", "errors": "surrogateescape", "newline": ""}


class HostBlockError(Exception):
    """A problem we can explain to the user without a traceback."""


# --------------------------------------------------------------------------- #
# Paths, privileges, elevation
# --------------------------------------------------------------------------- #

def default_hosts_path() -> Path:
    if os.name == "nt":
        root = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(root) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def backup_paths(hosts: Path) -> tuple[Path, Path]:
    """Return (original backup, previous-state backup) next to the hosts file."""
    return (hosts.with_name(hosts.name + ".hostblock-original"),
            hosts.with_name(hosts.name + ".hostblock-previous"))


def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def has_write_access(hosts: Path) -> bool:
    # On Windows os.access() ignores ACLs, so for the real system file trust the admin check.
    if os.name == "nt" and hosts == default_hosts_path() and not is_admin():
        return False
    target = hosts if hosts.exists() else hosts.parent
    return os.access(target, os.W_OK) and os.access(hosts.parent, os.W_OK)


def elevation_help(args: list[str]) -> str:
    if os.name == "nt":
        script = os.path.abspath(sys.argv[0])
        cmd = subprocess.list2cmdline(["python", script, *args])
        uac = subprocess.list2cmdline(["python", script, "--elevate", *args])
        return (
            "\nAdministrator rights are required for this command.\n"
            "  Option 1 - use an elevated prompt:\n"
            "    Start menu -> type 'cmd' -> right-click 'Command Prompt' ->\n"
            "    'Run as administrator' -> Yes, then run:\n"
            f"      {cmd}\n"
            "  Option 2 - let the script show the UAC prompt:\n"
            f"      {uac}\n"
        )
    cmd = shlex.join(["sudo", "python3", sys.argv[0], *args])
    return (
        "\nRoot privileges are required for this command.\n"
        "Run the same command with sudo:\n"
        f"    {cmd}\n"
    )


def relaunch_elevated(args: list[str]) -> int | None:
    """Re-run this script with admin/root rights. Returns an exit code, or None if not possible."""
    script = os.path.abspath(sys.argv[0])
    if os.name == "nt":
        import ctypes
        # A new elevated console window opens; --pause keeps it open so the output can be read.
        extra = ["--pause"] if any(a in WRITE_COMMANDS for a in args) else []
        params = subprocess.list2cmdline([script, *args, *extra])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
        if rc > 32:
            print("Continuing in the new Administrator window.")
            return 0
        print("The Administrator request was cancelled or failed.")
        return None
    sudo = shutil.which("sudo")
    if not sudo:
        return None
    print("Re-running with sudo (you may be asked for your password)...")
    return subprocess.call([sudo, sys.executable, script, *args])


# --------------------------------------------------------------------------- #
# Hosts file helpers
# --------------------------------------------------------------------------- #

def read_file(path: Path) -> str:
    with open(path, "r", **FILE_OPTS) as f:
        return f.read()


def write_file(path: Path, text: str) -> None:
    # Rewrite in place (same file) so ownership, permissions, Windows ACLs and
    # SELinux labels on the hosts file are preserved.
    with open(path, "w", **FILE_OPTS) as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())


def detect_newline(text: str) -> str:
    if "\r\n" in text:
        return "\r\n"
    if "\n" in text:
        return "\n"
    return os.linesep


def split_managed(text: str) -> tuple[str, str | None, str]:
    """Split the hosts text into (before, managed block or None, after)."""
    lines = text.splitlines(keepends=True)
    start = None
    for i, line in enumerate(lines):
        stripped = line.strip()
        if start is None:
            if stripped.startswith(START_TAG):
                start = i
        elif stripped.startswith(END_TAG):
            before = "".join(lines[:start])
            block = "".join(lines[start:i + 1])
            after = "".join(lines[i + 1:])
            if START_TAG in after:
                raise HostBlockError(
                    "the hosts file contains more than one HostBlock section. "
                    "Run 'restore', or remove the extra section by hand.")
            return before, block, after
    if start is not None:
        raise HostBlockError(
            "found a HostBlock START marker without a matching END marker - the "
            "section was edited by hand. Run 'restore', or fix the file manually.")
    return text, None, ""


def hostnames_in(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        names.extend(p.lower().rstrip(".") for p in parts[1:])
    return names


def block_info(block: str) -> dict[str, str]:
    info = {"domains": str(len(hostnames_in(block)))}
    for line in block.splitlines():
        for key in ("Source", "Updated", "Options"):
            prefix = f"# {key}:"
            if line.startswith(prefix):
                info[key.lower()] = line[len(prefix):].strip()
    return info


def stored_settings(block: str) -> tuple[str, bool, list[str]]:
    """Recover (url, compact, allow) from an existing HostBlock section."""
    info = block_info(block)
    options = dict(tok.split("=", 1) for tok in info.get("options", "").split() if "=" in tok)
    if "compact" in options:
        compact = options["compact"] == "yes"
    else:  # sections written by HostBlock 1.0 have no Options line
        compact = any(len(line.split("#", 1)[0].split()) > 2 for line in block.splitlines())
    allow = [a for a in options.get("allow", "").split(",") if a and a != "-"]
    return info.get("source") or DEFAULT_URL, compact, allow


# --------------------------------------------------------------------------- #
# Download and validation
# --------------------------------------------------------------------------- #

def resolve_url(url: str | None, extensions: list[str] | None) -> str:
    if url:
        return url
    if extensions:
        chosen = [e for e in EXTENSIONS if e in extensions]
        return f"{STEVENBLACK_BASE}/alternates/{'-'.join(chosen)}/hosts"
    return DEFAULT_URL


def download(url: str, timeout: float = 60) -> bytes:
    if not url.lower().startswith("https://"):
        raise HostBlockError("refusing to download over plain HTTP - use an https:// URL.")
    request = urllib.request.Request(url, headers={"User-Agent": f"hostblock/{VERSION}"})
    context = ssl.create_default_context()  # verifies the certificate and hostname
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            final_url = resp.geturl()
            if not final_url.lower().startswith("https://"):
                raise HostBlockError(f"download was redirected to a non-HTTPS address ({final_url}).")
            data = resp.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as e:
        raise HostBlockError(f"the server returned HTTP {e.code} for {url}") from e
    except urllib.error.URLError as e:
        raise HostBlockError(f"could not download {url}: {e.reason}") from e
    except OSError as e:
        raise HostBlockError(f"could not download {url}: {e}") from e
    if len(data) > MAX_DOWNLOAD_BYTES:
        raise HostBlockError("the download is unexpectedly large - aborting.")
    return data


def is_ip(name: str) -> bool:
    if not _IP_CHARS_RE.match(name):
        return False
    try:
        ipaddress.ip_address(name.split("%", 1)[0])
        return True
    except ValueError:
        return False


def parse_blocklist(text: str, skip: set[str], allow: list[str]) -> tuple[list[str], dict[str, int]]:
    """Extract the domains to block. Returns (domains, stats)."""
    stats = {"redirect": 0, "invalid": 0, "existing": 0, "allowed": 0, "duplicate": 0}
    allow = [a.lower().strip(".") for a in allow]
    domains: list[str] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        ip, *names = line.split()
        names = [n.lower().rstrip(".") for n in names]
        if not names:
            stats["invalid"] += 1
            continue
        if all(n in PROTECTED_NAMES or is_ip(n) for n in names):
            continue  # standard localhost / broadcast lines every hosts file has
        if ip not in SINK_IPS:
            # A real IP would send traffic somewhere instead of blocking it: never accept.
            stats["redirect" if is_ip(ip) else "invalid"] += len(names)
            continue
        for name in names:
            if name in PROTECTED_NAMES or is_ip(name) or not DOMAIN_RE.match(name):
                stats["invalid"] += 1
            elif name in seen:
                stats["duplicate"] += 1
            elif name in skip:
                stats["existing"] += 1
            elif any(name == a or name.endswith("." + a) for a in allow):
                stats["allowed"] += 1
            else:
                seen.add(name)
                domains.append(name)
    return domains, stats


def build_block(domains: list[str], source: str, nl: str, compact: bool, allow: list[str]) -> str:
    source = " ".join(source.split())  # keep the header on one line
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        START_MARKER,
        f"# Source: {source}",
        f"# Updated: {stamp}",
        f"# Domains: {len(domains)}",
        f"# Options: compact={'yes' if compact else 'no'} allow={','.join(allow) or '-'}",
        "# Remove: 'hostblock.py unblock'   Original file: 'hostblock.py restore'",
    ]
    if compact:
        lines += [f"{BLOCK_IP} " + " ".join(domains[i:i + COMPACT_PER_LINE])
                  for i in range(0, len(domains), COMPACT_PER_LINE)]
    else:
        lines += [f"{BLOCK_IP} {d}" for d in domains]
    lines.append(END_MARKER)
    return nl.join(lines) + nl


# --------------------------------------------------------------------------- #
# DNS cache
# --------------------------------------------------------------------------- #

def flush_dns() -> None:
    system = platform.system()
    if system == "Windows":
        steps = [[["ipconfig", "/flushdns"]]]
    elif system == "Darwin":
        steps = [[["dscacheutil", "-flushcache"]], [["killall", "-HUP", "mDNSResponder"]]]
    else:
        steps = [[["resolvectl", "flush-caches"], ["systemd-resolve", "--flush-caches"]],
                 [["nscd", "-i", "hosts"]]]
    done = []
    for alternatives in steps:
        for cmd in alternatives:
            if not shutil.which(cmd[0]):
                continue
            try:
                result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        stdin=subprocess.DEVNULL, timeout=20, **NO_WINDOW)
            except (OSError, subprocess.TimeoutExpired):
                continue
            if result.returncode == 0:
                done.append(" ".join(cmd))
                break
    if done:
        print(f"DNS cache flushed ({'; '.join(done)}).")
    else:
        print("No system DNS cache to flush - new lookups will use the updated hosts file.")
    print("Tip: restart your browser; browsers keep their own short-lived DNS cache.")


# --------------------------------------------------------------------------- #
# Weekly auto-update: Task Scheduler (Windows), launchd (macOS), systemd/cron (Linux)
# --------------------------------------------------------------------------- #

SCHEDULER_LABELS = {
    "windows": f"Windows Task Scheduler, task '{TASK_NAME}'",
    "launchd": f"launchd job {LAUNCHD_PLIST}",
    "systemd": f"systemd timer {SYSTEMD_UNIT}.timer",
    "cron": f"cron file {CRON_FILE}",
}
CATCH_UP = {
    "windows": "If the PC is off at that time, the update runs soon after it next starts.",
    "systemd": "If the computer is off at that time, the update runs soon after it next starts.",
    "launchd": "If the Mac is asleep at that time, the update runs when it wakes.",
    "cron": "Note: cron skips the update if the computer is off at that time.",
}


def install_dir() -> Path:
    """Admin-only folder holding the copy of this script that the scheduled task runs."""
    system = platform.system()
    if system == "Windows":
        return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "HostBlock"
    if system == "Darwin":
        return Path("/Library/Application Support/HostBlock")
    return Path("/usr/local/lib/hostblock")


def default_log_path() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "HostBlock" / "hostblock.log"
    return Path("/var/log/hostblock.log")


def scheduler_kind() -> str:
    system = platform.system()
    if system == "Windows":
        return "windows"
    if system == "Darwin":
        return "launchd"
    if shutil.which("systemctl") and Path("/run/systemd/system").is_dir():
        return "systemd"
    if Path("/etc/cron.d").is_dir():
        return "cron"
    return "none"


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          stdin=subprocess.DEVNULL, text=True, **NO_WINDOW)


def _run_checked(cmd: list[str]) -> None:
    result = _run(cmd)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise HostBlockError(f"'{' '.join(cmd)}' failed: {detail}")


def _writable_by_non_root(path: Path) -> bool:
    """POSIX: True if a non-root user could change path or a folder above it."""
    for p in (path, *path.parents):
        try:
            st = p.stat()
        except OSError:
            continue
        sticky = stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX
        if st.st_uid != 0 or (st.st_mode & stat.S_IWOTH and not sticky):
            return True
    return False


def scheduled_python() -> str:
    exe = Path(sys.executable)
    if os.name == "nt":
        windowless = exe.with_name("pythonw.exe")  # no console window pops up each week
        if windowless.exists():
            return str(windowless)
    return str(exe)


def interpreter_warning(python: str) -> str | None:
    if os.name == "nt":
        profile = os.environ.get("USERPROFILE", "")
        if profile and python.lower().startswith(profile.lower() + "\\"):
            return ("Python is installed only for your user account, so the program the weekly task runs "
                    "with admin rights sits in a folder your normal account can change. For the safest "
                    "setup, reinstall Python with 'Install Python for all users' and run 'schedule' again.")
        return None
    if _writable_by_non_root(Path(python)) or _writable_by_non_root(Path(python).resolve()):
        return (f"{python} can be changed by a non-root user (e.g. a virtualenv, pyenv or Homebrew Python), "
                "and the weekly task runs it as root. For the safest setup, run 'schedule' with the "
                "system Python instead, e.g. 'sudo /usr/bin/python3 hostblock.py schedule'.")
    return None


def task_command(hosts: Path) -> list[str]:
    # -I (isolated mode) ignores PYTHON* environment variables and user site-packages.
    cmd = [scheduled_python(), "-I", str(install_dir() / "hostblock.py"),
           "update", "--log", str(default_log_path())]
    if hosts != default_hosts_path():
        cmd += ["--hosts-file", str(hosts.resolve())]
    return cmd


def systemd_units(cmd: list[str], day: str, time: str) -> tuple[str, str]:
    def quote(arg: str) -> str:
        arg = arg.replace("%", "%%").replace("$", "$$")
        if re.fullmatch(r"[\w@%+=:,./-]+", arg):
            return arg
        return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'

    service = (
        "[Unit]\n"
        "Description=HostBlock blocklist update (hostblock.py)\n"
        "Wants=network-online.target\n"
        "After=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"ExecStart={' '.join(quote(a) for a in cmd)}\n"
    )
    timer = (
        "[Unit]\n"
        "Description=Weekly HostBlock blocklist update\n"
        "\n"
        "[Timer]\n"
        f"OnCalendar={day.capitalize()} *-*-* {time}:00\n"
        "Persistent=true\n"
        "RandomizedDelaySec=15min\n"
        "\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    )
    return service, timer


def cron_file_text(cmd: list[str], day: str, time: str) -> str:
    hour, minute = (int(x) for x in time.split(":"))
    command = shlex.join(cmd).replace("%", "\\%")  # % is special in crontab lines
    return (
        "# Installed by hostblock.py: weekly blocklist update. Remove with 'hostblock.py unschedule'.\n"
        "SHELL=/bin/sh\n"
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
        f"{minute} {hour} * * {CRON_DOW[day]} root {command}\n"
    )


def launchd_plist(cmd: list[str], day: str, time: str) -> bytes:
    hour, minute = (int(x) for x in time.split(":"))
    return plistlib.dumps({
        "Label": LAUNCHD_LABEL,
        "ProgramArguments": cmd,
        "StartCalendarInterval": {"Weekday": CRON_DOW[day], "Hour": hour, "Minute": minute},
        "ProcessType": "Background",
    })


def windows_task_xml(cmd: list[str], day: str, time: str, workdir: str, user: str | None) -> str:
    if user:   # runs as this user, elevated, while they are signed in
        principal = f"<UserId>{xml_escape(user)}</UserId>\n      <LogonType>InteractiveToken</LogonType>"
    else:      # SYSTEM account: runs even when nobody is signed in
        principal = "<UserId>S-1-5-18</UserId>"
    start = f"{datetime.now():%Y-%m-%d}T{time}:00"
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Weekly update of the HostBlock ad and tracker blocklist (hostblock.py).</Description>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>{start}</StartBoundary>
      <Enabled>true</Enabled>
      <ScheduleByWeek>
        <DaysOfWeek><{DAY_NAMES[day]} /></DaysOfWeek>
        <WeeksInterval>1</WeeksInterval>
      </ScheduleByWeek>
    </CalendarTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      {principal}
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{xml_escape(cmd[0])}</Command>
      <Arguments>{xml_escape(subprocess.list2cmdline(cmd[1:]))}</Arguments>
      <WorkingDirectory>{xml_escape(workdir)}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"""


def schedule_status() -> str | None:
    """Describe the installed weekly task, or return None if there is none."""
    system = platform.system()
    if system == "Windows":
        try:
            found = _run(["schtasks", "/Query", "/TN", TASK_NAME]).returncode == 0
        except OSError:
            found = False
        kind = "windows"
    elif system == "Darwin":
        found, kind = LAUNCHD_PLIST.exists(), "launchd"
    elif (SYSTEMD_DIR / f"{SYSTEMD_UNIT}.timer").exists():
        found, kind = True, "systemd"
    else:
        found, kind = CRON_FILE.exists(), "cron"
    if not found:
        return None
    try:
        when = (install_dir() / "schedule.txt").read_text(encoding="utf-8").strip()
    except OSError:
        when = "weekly"
    return f"ON - {when} ({SCHEDULER_LABELS[kind]})"


def install_schedule(hosts: Path, day: str, time: str, dry_run: bool) -> str:
    kind = scheduler_kind()
    if kind == "none":
        raise HostBlockError("no supported scheduler found (needs systemd or cron). Add this to root's "
                             f"crontab instead: {CRON_DOW[day]} ... {shlex.join(task_command(hosts))}")
    cmd = task_command(hosts)
    folder = install_dir()
    shown = subprocess.list2cmdline(cmd) if os.name == "nt" else shlex.join(cmd)
    print(f"Weekly auto-update: every {DAY_NAMES[day]} at {time}")
    print(f"  Scheduler : {SCHEDULER_LABELS[kind]}")
    print(f"  Command   : {shown}")
    print(f"  Log file  : {default_log_path()}")
    warning = interpreter_warning(cmd[0])
    if warning:
        print(f"\nWarning: {warning}\n")
    if dry_run:
        print("[dry run] Nothing was installed.")
        return kind

    # Install a copy of this script where only admins/root can change it.
    folder.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(folder, 0o755)
        if _writable_by_non_root(folder):
            raise HostBlockError(f"{folder} can be changed by non-root users, so it is not safe to run "
                                 "a root task from it.")
    script = folder / "hostblock.py"
    if Path(__file__).resolve() != script.resolve():
        shutil.copyfile(Path(__file__).resolve(), script)
    if os.name != "nt":
        os.chmod(script, 0o644)

    if kind == "windows":
        user = None
        if "\\windowsapps\\" in cmd[0].lower():
            user = "\\".join(filter(None, (os.environ.get("USERDOMAIN"), os.environ.get("USERNAME"))))
            print("Note: Microsoft Store Python can't run as SYSTEM, so the task runs as you, "
                  "with admin rights, while you are signed in.")
        xml_file = folder / "task.xml"
        xml_file.write_text(windows_task_xml(cmd, day, time, str(folder), user), encoding="utf-16")
        try:
            _run_checked(["schtasks", "/Create", "/TN", TASK_NAME, "/XML", str(xml_file), "/F"])
        finally:
            xml_file.unlink(missing_ok=True)
    elif kind == "launchd":
        if LAUNCHD_PLIST.exists():
            _run(["launchctl", "bootout", f"system/{LAUNCHD_LABEL}"])
        LAUNCHD_PLIST.write_bytes(launchd_plist(cmd, day, time))
        os.chmod(LAUNCHD_PLIST, 0o644)
        if _run(["launchctl", "bootstrap", "system", str(LAUNCHD_PLIST)]).returncode != 0:
            _run_checked(["launchctl", "load", "-w", str(LAUNCHD_PLIST)])
    elif kind == "systemd":
        service, timer = systemd_units(cmd, day, time)
        (SYSTEMD_DIR / f"{SYSTEMD_UNIT}.service").write_text(service, encoding="utf-8")
        (SYSTEMD_DIR / f"{SYSTEMD_UNIT}.timer").write_text(timer, encoding="utf-8")
        _run_checked(["systemctl", "daemon-reload"])
        _run_checked(["systemctl", "enable", f"{SYSTEMD_UNIT}.timer"])
        _run_checked(["systemctl", "restart", f"{SYSTEMD_UNIT}.timer"])
    else:
        CRON_FILE.write_text(cron_file_text(cmd, day, time), encoding="utf-8")
        os.chmod(CRON_FILE, 0o644)

    (folder / "schedule.txt").write_text(f"every {DAY_NAMES[day]} at {time}\n", encoding="utf-8")
    return kind


def installed_by_setup() -> bool:
    """True when Hostblock.setup.exe installed the app (with its own Python) in install_dir()."""
    return (install_dir() / "runtime").is_dir()


def remove_schedule(dry_run: bool) -> bool:
    """Remove the weekly task and its installed files. Returns True if anything was found."""
    found = schedule_status()
    folder = install_dir()
    if found is None and (installed_by_setup() or not folder.exists()):
        return False
    if dry_run:
        print(f"[dry run] Would remove the weekly auto-update task and {folder}.")
        return True
    system = platform.system()
    if system == "Windows":
        if found:
            _run_checked(["schtasks", "/Delete", "/TN", TASK_NAME, "/F"])
    elif system == "Darwin":
        if LAUNCHD_PLIST.exists():
            if _run(["launchctl", "bootout", f"system/{LAUNCHD_LABEL}"]).returncode != 0:
                _run(["launchctl", "unload", "-w", str(LAUNCHD_PLIST)])
            LAUNCHD_PLIST.unlink()
    else:
        timer = SYSTEMD_DIR / f"{SYSTEMD_UNIT}.timer"
        if timer.exists():
            if scheduler_kind() == "systemd":
                _run(["systemctl", "disable", "--now", timer.name])
            timer.unlink()
            (SYSTEMD_DIR / f"{SYSTEMD_UNIT}.service").unlink(missing_ok=True)
            if scheduler_kind() == "systemd":
                _run(["systemctl", "daemon-reload"])
        CRON_FILE.unlink(missing_ok=True)
    for name in ("schedule.txt", "task.xml"):
        (folder / name).unlink(missing_ok=True)
    if not installed_by_setup():  # never delete the installed app; its uninstaller does that
        (folder / "hostblock.py").unlink(missing_ok=True)
        try:
            folder.rmdir()
        except OSError:
            pass
    return True


class _Tee:
    """Write output to the console (if there is one) and to a log file."""

    def __init__(self, stream, log):
        self._stream, self._log = stream, log

    def write(self, text: str) -> int:
        if self._stream is not None:
            try:
                self._stream.write(text)
            except (OSError, ValueError):
                pass
        self._log.write(text)
        self._log.flush()
        return len(text)

    def flush(self) -> None:
        if self._stream is not None:
            try:
                self._stream.flush()
            except (OSError, ValueError):
                pass


def start_log(path: Path, argv: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > LOG_MAX_BYTES:
        os.replace(path, path.with_name(path.name + ".old"))
    log = open(path, "a", encoding="utf-8", errors="replace")
    log.write(f"\n=== {datetime.now():%Y-%m-%d %H:%M:%S} hostblock {' '.join(argv)} ===\n")
    sys.stdout = _Tee(sys.stdout, log)
    sys.stderr = _Tee(sys.stderr, log)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def commit(hosts: Path, current: str, new_text: str, dry_run: bool) -> bool:
    """Write new_text to the hosts file after saving the current state. Returns True if written."""
    if new_text == current:
        print("No changes needed.")
        return False
    if dry_run:
        print("[dry run] The hosts file was NOT modified.")
        return False
    _, previous = backup_paths(hosts)
    write_file(previous, current)
    write_file(hosts, new_text)
    if read_file(hosts) != new_text:
        write_file(hosts, current)
        raise HostBlockError("the hosts file did not save correctly; the previous version was put back.")
    return True


def cmd_block(hosts: Path, url: str, allow: list[str], compact: bool,
              min_entries: int, dry_run: bool, flush: bool) -> None:
    allow = sorted({a.lower().strip(".") for a in allow} - {""})
    bad = [a for a in allow if not re.fullmatch(r"[a-z0-9_.-]+", a)]
    if bad:
        raise HostBlockError(f"invalid --allow domain: {', '.join(bad)}")
    current = read_file(hosts) if hosts.exists() else ""
    nl = detect_newline(current)
    before, block, after = split_managed(current)
    unmanaged = before + after

    print(f"Downloading blocklist: {url}")
    data = download(url)
    print(f"  Downloaded {len(data) / 1_048_576:.1f} MB")
    domains, stats = parse_blocklist(data.decode("utf-8", errors="replace"),
                                     skip=set(hostnames_in(unmanaged)), allow=allow)

    print(f"  Domains to block ...................... {len(domains):,}")
    if stats["existing"]:
        print(f"  Skipped, already in your hosts file ... {stats['existing']:,}")
    if stats["allowed"]:
        print(f"  Skipped by your --allow list .......... {stats['allowed']:,}")
    if stats["redirect"]:
        print(f"  REJECTED, pointed to a real IP ........ {stats['redirect']:,}  (only 0.0.0.0 blocks are accepted)")
    if stats["invalid"]:
        print(f"  Ignored, malformed names .............. {stats['invalid']:,}")

    if len(domains) < min_entries:
        raise HostBlockError(
            f"only {len(domains):,} valid domains found (expected at least {min_entries:,}). "
            "This does not look like a hosts blocklist, so nothing was changed.")

    new_block = build_block(domains, url, nl, compact, allow)
    if block is None:
        base = current
        if base and not base.endswith(("\n", "\r")):
            base += nl
        new_text = base + new_block
    else:
        new_text = before + new_block + after

    original = backup_paths(hosts)[0]
    if not dry_run and not original.exists():
        write_file(original, unmanaged)
        print(f"Saved a backup of your original hosts file: {original}")

    if commit(hosts, current, new_text, dry_run):
        action = "updated" if block else "added"
        print(f"Blocking {action}: {len(domains):,} domains are now blocked in {hosts}")
        if flush:
            flush_dns()


def cmd_unblock(hosts: Path, dry_run: bool, flush: bool) -> None:
    current = read_file(hosts)
    before, block, after = split_managed(current)
    if block is None:
        print("No HostBlock section found in the hosts file - nothing to remove.")
        return
    count = int(block_info(block)["domains"])
    if commit(hosts, current, before + after, dry_run):
        original, previous = backup_paths(hosts)
        # The file is now back to "your own entries only"; a later 'block' takes a fresh backup.
        original.unlink(missing_ok=True)
        print(f"Removed the HostBlock section ({count:,} domains). Your other entries were left untouched.")
        print(f"A copy of the file from before this change is at: {previous}")
        if hosts == default_hosts_path() and schedule_status():
            print("The weekly auto-update task stays installed but does nothing while blocking is off "
                  "(remove it with 'unschedule').")
        if flush:
            flush_dns()


def cmd_update(hosts: Path, dry_run: bool, flush: bool) -> None:
    """Refresh the active blocklist with the same source and options. This is what the weekly task runs."""
    current = read_file(hosts) if hosts.exists() else ""
    _, block, _ = split_managed(current)
    if block is None:
        print("Blocking is off - nothing to update. Run 'block' to turn it on.")
        return
    url, compact, allow = stored_settings(block)
    cmd_block(hosts, url, allow, compact, MIN_ENTRIES_DEFAULT, dry_run, flush)


def cmd_restore(hosts: Path, dry_run: bool, flush: bool) -> None:
    restore_hosts_file(hosts, dry_run, flush)
    # A full revert should leave nothing behind, so the weekly task goes too.
    if hosts == default_hosts_path() and remove_schedule(dry_run) and not dry_run:
        print("The weekly auto-update task was removed as well.")


def restore_hosts_file(hosts: Path, dry_run: bool, flush: bool) -> None:
    original, previous = backup_paths(hosts)
    current = read_file(hosts) if hosts.exists() else ""
    if not original.exists():
        _, block, _ = split_managed(current)
        if block is None:
            print("No original backup exists and the hosts file has no HostBlock section - "
                  "it is already in its original state.")
            return
        print("No original backup found - removing the HostBlock section instead.")
        cmd_unblock(hosts, dry_run, flush)
        return

    saved = read_file(original)
    if saved == current:
        print("The hosts file already matches the original backup.")
        if not dry_run:
            original.unlink()
        return
    if commit(hosts, current, saved, dry_run):
        original.unlink()
        print("Restored the original hosts file (exact copy saved before HostBlock was first applied).")
        print(f"Any edits made after that point are in this copy of the replaced file: {previous}")
        if flush:
            flush_dns()


def cmd_status(hosts: Path) -> None:
    print(f"Hosts file  : {hosts}")
    if not hosts.exists():
        print("Status      : hosts file not found")
        return
    try:
        _, block, _ = split_managed(read_file(hosts))
    except HostBlockError as e:
        print(f"Status      : PROBLEM - {e}")
        block = None
    else:
        if block is None:
            print("Status      : not active")
        else:
            info = block_info(block)
            _, compact, allow = stored_settings(block)
            options = (["compact"] if compact else []) + ([f"allow {', '.join(allow)}"] if allow else [])
            print(f"Status      : ACTIVE - {int(info['domains']):,} domains blocked")
            print(f"Source      : {info.get('source', 'unknown')}")
            print(f"Updated     : {info.get('updated', 'unknown')}")
            print(f"Options     : {'; '.join(options) or 'none'}")
    print(f"Auto-update : {schedule_status() or 'off'}")
    original, _ = backup_paths(hosts)
    print(f"Backup      : {original if original.exists() else 'none (no changes made by HostBlock)'}")
    print(f"Privileges  : {'Administrator/root' if is_admin() else 'standard user (read-only)'}")


def cmd_schedule(hosts: Path, day: str, time: str, dry_run: bool) -> None:
    kind = install_schedule(hosts, day, time, dry_run)
    if dry_run:
        return
    print(f"\nWeekly auto-update is ON: every {DAY_NAMES[day]} at {time}. {CATCH_UP[kind]}")
    print("Each run refreshes the blocklist with your current settings and does nothing while blocking is off.")
    print(f"The task runs a protected copy of this script in {install_dir()};")
    print("run 'schedule' again after you update hostblock.py so the copy is refreshed.")
    current = read_file(hosts) if hosts.exists() else ""
    if split_managed(current)[1] is None:
        print("Note: blocking is currently off - run 'block' to turn it on.")


def cmd_unschedule(dry_run: bool) -> None:
    if not remove_schedule(dry_run):
        print("No weekly auto-update task is installed.")
    elif not dry_run:
        print("Weekly auto-update task removed.")


# --------------------------------------------------------------------------- #
# Interactive menu
# --------------------------------------------------------------------------- #

MENU = """
  1) Block ads & trackers (download the latest list and apply/update it)
  2) Remove blocking      (delete only the HostBlock section, keep your other edits)
  3) Restore original     (put back the exact hosts file from before the first block)
  4) Show status
  5) Weekly auto-update   (turn on/off)
  q) Quit
"""


def ask(prompt: str) -> str:
    try:
        return input(prompt).strip().lower()
    except EOFError:
        return "q"


def ask_extensions() -> list[str] | None:
    answer = ask(f"Extra categories to block? ({', '.join(EXTENSIONS)}; comma-separated, Enter for none): ")
    if answer == "q":
        return None
    chosen = [p for p in re.split(r"[,\s]+", answer) if p]
    unknown = [p for p in chosen if p not in EXTENSIONS]
    if unknown:
        print(f"Unknown category: {', '.join(unknown)}")
        return None
    return chosen


def interactive(args: argparse.Namespace, hosts: Path, relaunch_args: list[str]) -> int:
    print(f"{APP_NAME} {VERSION} - block ads & trackers with the hosts file")
    writable = has_write_access(hosts)
    if not writable:
        print("\nYou are not running with Administrator/root rights, so changes are disabled.")
        if ask("Relaunch with elevated rights now? [Y/n] ") in ("", "y", "yes"):
            rc = relaunch_elevated(relaunch_args)
            if rc is not None:
                return rc
            print(elevation_help(relaunch_args))

    while True:
        print()
        cmd_status(hosts)
        print(MENU)
        choice = ask("Choose an option: ")
        if choice in ("q", "quit", "exit"):
            return 0
        if choice not in ("1", "2", "3", "4", "5"):
            continue
        if choice != "4" and not args.dry_run and not has_write_access(hosts):
            print(elevation_help(relaunch_args))
            continue
        print()
        try:
            if choice == "1":
                exts = ask_extensions()
                if exts is None:
                    continue
                block = split_managed(read_file(hosts) if hosts.exists() else "")[1]
                _, compact, allow = stored_settings(block) if block else ("", False, [])
                cmd_block(hosts, resolve_url(None, exts), allow, compact,
                          MIN_ENTRIES_DEFAULT, args.dry_run, not args.no_flush)
            elif choice == "2":
                cmd_unblock(hosts, args.dry_run, not args.no_flush)
            elif choice == "3":
                if ask("Replace the hosts file with the original backup? [y/N] ") in ("y", "yes"):
                    cmd_restore(hosts, args.dry_run, not args.no_flush)
            elif choice == "5":
                if schedule_status():
                    if ask("Turn OFF the weekly auto-update? [y/N] ") in ("y", "yes"):
                        cmd_unschedule(args.dry_run)
                elif ask(f"Turn ON the weekly auto-update (every {DAY_NAMES[DEFAULT_DAY]} at "
                         f"{DEFAULT_TIME})? [Y/n] ") in ("", "y", "yes"):
                    cmd_schedule(hosts, DEFAULT_DAY, DEFAULT_TIME, args.dry_run)
            # choice 4: status is printed at the top of the loop
        except PermissionError as e:
            print(f"Permission denied: {e.filename}")
            print(elevation_help(relaunch_args))
        except HostBlockError as e:
            print(f"Error: {e}")


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def add_common_options(parser: argparse.ArgumentParser, top_level: bool) -> None:
    # Subparsers use SUPPRESS so options work before *or* after the command name.
    def d(value):
        return value if top_level else argparse.SUPPRESS
    parser.add_argument("--hosts-file", default=d(None), metavar="PATH",
                        help="hosts file to manage (default: the system hosts file)")
    parser.add_argument("--dry-run", action="store_true", default=d(False),
                        help="show what would change without writing anything")
    parser.add_argument("--no-flush", action="store_true", default=d(False),
                        help="do not flush the DNS cache after changing the file")
    parser.add_argument("--elevate", action="store_true", default=d(False),
                        help="if not admin/root, relaunch with UAC (Windows) or sudo (macOS/Linux)")
    parser.add_argument("--pause", action="store_true", default=d(False),
                        help="wait for Enter before exiting (keeps a new console window open)")
    parser.add_argument("--log", default=d(None), metavar="PATH",
                        help="also append all output to this file (used by the scheduled task)")


def parse_time(value: str) -> str:
    match = re.fullmatch(r"([01]?\d|2[0-3]):([0-5]\d)", value.strip())
    if not match:
        raise argparse.ArgumentTypeError("use 24-hour HH:MM, for example 03:30 or 18:00")
    return f"{int(match.group(1)):02d}:{match.group(2)}"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hostblock.py",
        description="Block ad, tracking and malware domains via the system hosts file.",
        epilog=("Run without a command for an interactive menu.\n"
                "Every command except status needs Administrator (Windows) or root (macOS/Linux):\n"
                "  Windows:      open Command Prompt with 'Run as administrator', or add --elevate\n"
                "  macOS/Linux:  sudo python3 hostblock.py block"),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    add_common_options(parser, top_level=True)
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_block = sub.add_parser("block", help="download the blocklist and add/update the blocked section")
    source = p_block.add_mutually_exclusive_group()
    source.add_argument("--url", help=f"blocklist URL in hosts format (default: {DEFAULT_URL})")
    source.add_argument("--extensions", nargs="+", choices=EXTENSIONS, metavar="NAME",
                        help=f"also block StevenBlack extra categories: {', '.join(EXTENSIONS)}")
    p_block.add_argument("--allow", action="append", default=[], metavar="DOMAIN",
                         help="never block DOMAIN or its subdomains (repeatable)")
    p_block.add_argument("--compact", action="store_true",
                         help=f"put {COMPACT_PER_LINE} domains per line (smaller file; recommended on Windows)")
    p_block.add_argument("--min-entries", type=int, default=MIN_ENTRIES_DEFAULT, metavar="N",
                         help=f"abort if fewer than N valid domains are found (default: {MIN_ENTRIES_DEFAULT})")
    p_block.add_argument("--schedule", action="store_true",
                         help=f"also install the weekly auto-update ({DAY_NAMES[DEFAULT_DAY]} {DEFAULT_TIME})")
    add_common_options(p_block, top_level=False)

    p_schedule = sub.add_parser("schedule", help="install a weekly task that runs 'update' automatically")
    p_schedule.add_argument("--day", choices=DAYS, default=DEFAULT_DAY,
                            help=f"day of the week (default: {DEFAULT_DAY})")
    p_schedule.add_argument("--time", type=parse_time, default=DEFAULT_TIME, metavar="HH:MM",
                            help=f"24-hour local time (default: {DEFAULT_TIME})")
    add_common_options(p_schedule, top_level=False)

    for name, text in (("unblock", "remove only the HostBlock section, keeping your other edits"),
                       ("restore", "put back the original hosts file and remove the weekly task"),
                       ("update", "refresh the blocklist with the current settings (what the weekly task runs)"),
                       ("unschedule", "remove the weekly auto-update task"),
                       ("status", "show whether blocking and auto-update are active")):
        add_common_options(sub.add_parser(name, help=text), top_level=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    if sys.version_info < (3, 8):
        print("HostBlock needs Python 3.8 or newer.", file=sys.stderr)
        return 1
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(argv)
    hosts = Path(args.hosts_file).expanduser() if args.hosts_file else default_hosts_path()
    relaunch_args = [a for a in argv if a != "--elevate"]
    flush = not args.no_flush

    try:
        if args.log:
            start_log(Path(args.log).expanduser(), argv)
        if args.command is None:
            return interactive(args, hosts, relaunch_args)
        if args.command == "status":
            cmd_status(hosts)
            return 0
        if args.command in ("schedule", "unschedule") or getattr(args, "schedule", False):
            allowed = is_admin()  # system scheduler and install folder need admin/root
        else:
            allowed = has_write_access(hosts)
        if not args.dry_run and not allowed:
            if args.elevate:
                rc = relaunch_elevated(relaunch_args)
                if rc is not None:
                    return rc
            print(elevation_help(relaunch_args), file=sys.stderr)
            return 1
        if args.command == "block":
            cmd_block(hosts, resolve_url(args.url, args.extensions), args.allow,
                      args.compact, args.min_entries, args.dry_run, flush)
            if args.schedule:
                print()
                cmd_schedule(hosts, DEFAULT_DAY, DEFAULT_TIME, args.dry_run)
        elif args.command == "unblock":
            cmd_unblock(hosts, args.dry_run, flush)
        elif args.command == "restore":
            cmd_restore(hosts, args.dry_run, flush)
        elif args.command == "update":
            cmd_update(hosts, args.dry_run, flush)
        elif args.command == "schedule":
            cmd_schedule(hosts, args.day, args.time, args.dry_run)
        elif args.command == "unschedule":
            cmd_unschedule(args.dry_run)
        return 0
    except PermissionError as e:
        print(f"Permission denied: {e.filename}", file=sys.stderr)
        print(elevation_help(relaunch_args), file=sys.stderr)
        return 1
    except HostBlockError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    finally:
        if args.pause:
            try:
                input("\nPress Enter to close this window...")
            except EOFError:
                pass


if __name__ == "__main__":
    sys.exit(main())

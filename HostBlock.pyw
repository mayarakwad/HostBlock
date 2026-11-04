#!/usr/bin/env python3
"""
HostBlock - a simple window for turning ad & tracker blocking on and off.

How to open it
  Windows : double-click HostBlock.pyw. Windows asks for administrator permission.
  macOS   : double-click HostBlock.command (or run: python3 HostBlock.pyw).
            You'll be asked for your password when you make a change.
  Linux   : run: python3 HostBlock.pyw   (needs the python3-tk package).
            You'll be asked for your password when you make a change.

This window is a front end for hostblock.py, which must be in the same folder.
Every change is made by running hostblock.py with administrator rights, so the
same safety checks and backups apply.
"""

from __future__ import annotations

import argparse
import os
import queue
import shlex
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

HERE = Path(__file__).resolve().parent
CLI_SCRIPT = HERE / "hostblock.py"
sys.path.insert(0, str(HERE))

try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import messagebox, ttk
    from tkinter.scrolledtext import ScrolledText
except ImportError:
    sys.stderr.write(
        "The HostBlock window needs Tkinter, which this Python doesn't have.\n"
        "  Debian/Ubuntu:  sudo apt install python3-tk\n"
        "  Fedora:         sudo dnf install python3-tkinter\n"
        "  macOS Homebrew: brew install python-tk   (or use Python from python.org)\n"
        "You can still use the command-line version: python3 hostblock.py\n")
    sys.exit(1)

import hostblock as hb

CATEGORY_LABELS = {
    "fakenews": "Fake news sites",
    "gambling": "Gambling sites",
    "porn": "Adult content",
    "social": "Social media",
}
GREEN, GREY, AMBER, RED = "#1a7f37", "#6e7781", "#b26b00", "#c62828"
NO_WINDOW = hb.NO_WINDOW


# --------------------------------------------------------------------------- #
# Reading the current state (no admin rights needed)
# --------------------------------------------------------------------------- #

@dataclass
class Snapshot:
    active: bool = False
    domains: int = 0
    updated: str = ""
    source: str = hb.DEFAULT_URL
    categories: set[str] | None = field(default_factory=set)  # None = custom list URL
    compact: bool = os.name == "nt"
    allow: list[str] = field(default_factory=list)
    min_entries: int = hb.MIN_ENTRIES_DEFAULT
    scheduled: bool = False
    problem: str | None = None


def categories_from_url(url: str) -> set[str] | None:
    if url == hb.DEFAULT_URL:
        return set()
    prefix, suffix = f"{hb.STEVENBLACK_BASE}/alternates/", "/hosts"
    if url.startswith(prefix) and url.endswith(suffix):
        parts = set(url[len(prefix):-len(suffix)].split("-"))
        if parts <= set(hb.EXTENSIONS):
            return parts
    return None


def read_snapshot(hosts: Path) -> Snapshot:
    snap = Snapshot()
    block = None
    try:
        text = hb.read_file(hosts) if hosts.exists() else ""
        block = hb.split_managed(text)[1]
    except (OSError, hb.HostBlockError) as e:
        snap.problem = str(e)
    if block:
        info = hb.block_info(block)
        snap.active = True
        snap.domains = int(info["domains"])
        snap.updated = info.get("updated", "")
    # While protection is off, use the settings remembered from the last time it was on.
    settings = block or (None if snap.problem else hb.saved_settings(hosts))
    if settings:
        snap.source, snap.compact, snap.allow = hb.stored_settings(settings)
        snap.min_entries = hb.stored_min_entries(settings)
        snap.categories = categories_from_url(snap.source)
    try:
        snap.scheduled = hb.schedule_status() is not None
    except Exception:  # never let a status check keep the window from opening
        pass
    return snap


def describe_updated(stamp: str) -> str:
    try:
        when = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S UTC").replace(tzinfo=timezone.utc)
    except ValueError:
        return ""
    days = (datetime.now().astimezone().date() - when.astimezone().date()).days
    if days <= 0:
        return "list updated today"
    if days == 1:
        return "list updated yesterday"
    return f"list updated {days} days ago"


# --------------------------------------------------------------------------- #
# Running hostblock.py with admin rights
# --------------------------------------------------------------------------- #

def cli_python() -> str:
    exe = Path(sys.executable)
    if os.name == "nt" and exe.name.lower() == "pythonw.exe":
        console = exe.with_name("python.exe")   # needed to capture the tool's output
        if console.exists():
            return str(console)
    return str(exe)


def elevated_command(args: list[str]) -> list[str] | None:
    """Command line that runs hostblock.py with admin rights, or None if this window can't."""
    # -I: ignore PYTHON* environment variables and user site-packages in the admin process.
    base = [cli_python(), "-I", "-X", "utf8", str(CLI_SCRIPT), *args]
    if hb.is_admin():
        return base
    if sys.platform == "darwin":
        shell = (shlex.join(base) + " 2>&1").replace("\\", "\\\\").replace('"', '\\"')
        return ["osascript", "-e",
                f'do shell script "{shell}" with administrator privileges without altering line endings']
    if os.name != "nt" and shutil.which("pkexec"):
        return ["pkexec", *base]
    return None


def relaunch_as_admin() -> bool:
    """Windows: reopen this window with administrator rights (UAC prompt)."""
    import ctypes
    exe = Path(sys.executable)
    windowless = exe.with_name("pythonw.exe")
    params = subprocess.list2cmdline(["-I", str(Path(__file__).resolve()), *sys.argv[1:]])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(windowless if windowless.exists() else exe), params, str(HERE), 1)
    return rc > 32


def friendly_error(output: list[str]) -> str:
    text = "\n".join(output).lower()
    if "authentication agent" in text:  # pkexec found no graphical password prompt
        return ("No password prompt is available on this desktop. Close this window and run:  "
                f"sudo python3 \"{Path(__file__).resolve()}\"")
    error = next((line for line in reversed(output) if "Error:" in line or "Permission denied" in line), "")
    error = error.split("Error:", 1)[-1].strip()
    lowered = error.lower()
    if "could not download" in lowered or ("server returned" in lowered):
        return "Couldn't download the list. Check your internet connection and try again."
    if "permission denied" in lowered:
        return "Your computer refused the change. Make sure you allowed administrator access."
    return error or "Something went wrong. Click 'Show details' to see what happened."


# --------------------------------------------------------------------------- #
# The window
# --------------------------------------------------------------------------- #

class App(tk.Tk):
    def __init__(self, hosts: Path, extra_args: list[str]):
        super().__init__()
        self.hosts, self.extra_args = hosts, extra_args
        self.snap = Snapshot()
        self.busy = False
        self.loading = False
        self.weekly_intent = True          # the user's choice, applied when protection is turned on
        self.first_refresh = True
        # Testing on a copy (--hosts-file): never install the system-wide weekly task for it.
        self.test_mode = bool(extra_args)
        self.events: queue.Queue = queue.Queue()
        self.output: list[str] = []
        self.on_success: Callable[[Snapshot], str] = lambda s: "Done."
        self.cmd_kind = ""
        self.can_change = elevated_command([]) is not None

        self.title("HostBlock")
        icon = HERE / "hostblock.ico"
        if os.name == "nt" and icon.exists():
            try:
                self.iconbitmap(default=str(icon))
            except tk.TclError:
                pass
        self.resizable(False, False)
        self.report_callback_exception = self._on_tk_error
        self._styles()
        self._build()
        self.refresh()
        if self.can_change and not hb.is_admin():
            self.message.configure(text="You'll be asked for your password when you make a change.",
                                   foreground=GREY)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._poll_id = self.after(100, self._poll)

    def on_close(self) -> None:
        if self.busy:
            messagebox.showinfo("Please wait", "HostBlock is still making a change. "
                                "The window can be closed when it has finished.", parent=self)
            return
        self.destroy()

    def _on_tk_error(self, exc, value, tb) -> None:
        import traceback
        self._log("".join(traceback.format_exception(exc, value, tb)))
        self.message.configure(text=f"Something went wrong: {value}", foreground=RED)
        if not self.log.winfo_ismapped():
            self.toggle_details()

    def destroy(self) -> None:
        try:
            self.after_cancel(self._poll_id)
        except (tk.TclError, AttributeError):
            pass
        super().destroy()

    # ----- layout ---------------------------------------------------------- #

    def _styles(self) -> None:
        style = ttk.Style(self)
        if sys.platform.startswith("linux") and "clam" in style.theme_names():
            style.theme_use("clam")
        base = tkfont.nametofont("TkDefaultFont")
        size = abs(int(base.actual("size"))) or 10
        self.f_title = base.copy()
        self.f_title.configure(size=size + 8, weight="bold")
        self.f_big = base.copy()
        self.f_big.configure(size=size + 4, weight="bold")
        self.f_bold = base.copy()
        self.f_bold.configure(weight="bold")
        style.configure("Big.TButton", font=self.f_big, padding=(12, 10))
        style.configure("Card.TFrame", relief="groove", borderwidth=2)
        self.bg = style.lookup("TFrame", "background") or self.cget("background")

    def _build(self) -> None:
        outer = ttk.Frame(self, padding=(22, 18, 22, 16))
        outer.pack(fill="both", expand=True)
        wrap = 400

        ttk.Label(outer, text="HostBlock", font=self.f_title).pack(anchor="w")
        ttk.Label(outer, text="Blocks ads, trackers and harmful websites on this computer.",
                  foreground=GREY).pack(anchor="w", pady=(2, 14))

        # Shown only when this window can't make changes.
        self.banner = ttk.Frame(outer, padding=10, style="Card.TFrame")
        self.banner_label = ttk.Label(self.banner, wraplength=wrap - 20, justify="left")
        self.banner_label.pack(anchor="w")
        self.banner_button = ttk.Button(self.banner, text="Restart as administrator",
                                        command=self.on_restart_admin)

        # Status card
        self.card = ttk.Frame(outer, padding=14, style="Card.TFrame")
        self.card.pack(fill="x")
        self.dot = tk.Canvas(self.card, width=22, height=22, highlightthickness=0, bg=self.bg)
        self.dot.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, 12), pady=(4, 0))
        self.state_label = ttk.Label(self.card, font=self.f_big)
        self.state_label.grid(row=0, column=1, sticky="w")
        self.detail_label = ttk.Label(self.card, foreground=GREY, wraplength=wrap - 60, justify="left")
        self.detail_label.grid(row=1, column=1, sticky="w")

        self.main_button = ttk.Button(outer, style="Big.TButton", command=self.on_main)
        self.main_button.pack(fill="x", pady=(14, 16))

        # Categories
        ttk.Label(outer, text="Also block:", font=self.f_bold).pack(anchor="w")
        cats = ttk.Frame(outer)
        cats.pack(fill="x", pady=(4, 0))
        self.cat_vars: dict[str, tk.BooleanVar] = {}
        self.cat_checks: list[ttk.Checkbutton] = []
        for i, key in enumerate(hb.EXTENSIONS):
            var = tk.BooleanVar(value=False)
            var.trace_add("write", lambda *_: self._update_controls())
            check = ttk.Checkbutton(cats, text=CATEGORY_LABELS[key], variable=var)
            check.grid(row=i // 2, column=i % 2, sticky="w", padx=(0, 28), pady=2)
            self.cat_vars[key] = var
            self.cat_checks.append(check)
        self.custom_note = ttk.Label(outer, foreground=GREY, wraplength=wrap,
                                     text="You're using a custom list set up from the command line.")

        self.weekly_var = tk.BooleanVar(value=True)
        self.weekly_check = ttk.Checkbutton(outer, text="Keep the list up to date automatically (weekly)",
                                            variable=self.weekly_var, command=self.on_weekly)
        self.weekly_check.pack(anchor="w", pady=(14, 14))

        row = ttk.Frame(outer)
        row.pack(fill="x")
        self.update_button = ttk.Button(row, text="Update now", command=self.on_update)
        self.update_button.pack(side="left")
        self.undo_button = ttk.Button(row, text="Undo everything...", command=self.on_undo)
        self.undo_button.pack(side="right")

        ttk.Separator(outer).pack(fill="x", pady=(14, 8))
        self.progress = ttk.Progressbar(outer, mode="indeterminate")
        self.message = ttk.Label(outer, wraplength=wrap, justify="left")
        self.message.pack(anchor="w", fill="x")
        self.details_button = ttk.Button(outer, text="Show details", command=self.toggle_details)
        self.details_button.pack(anchor="w", pady=(8, 0))
        self.log = ScrolledText(outer, height=10, width=48, wrap="word", state="disabled",
                                font="TkFixedFont", relief="flat", borderwidth=1)

    # ----- state ----------------------------------------------------------- #

    def refresh(self) -> None:
        self.snap = s = read_snapshot(self.hosts)
        self.loading = True
        self.dot.delete("all")
        if s.problem:
            color, title = AMBER, "Something needs attention"
            detail = "The hosts file has a problem HostBlock can't fix automatically. " \
                     "Click 'Undo everything' to put it back the way it was."
        elif s.active:
            color, title = GREEN, "Protection is ON"
            detail = "  \u00b7  ".join(filter(None, (f"{s.domains:,} sites blocked", describe_updated(s.updated))))
        else:
            color, title = GREY, "Protection is OFF"
            detail = "Ads and trackers are not being blocked."
        self.dot.create_oval(3, 3, 19, 19, fill=color, outline=color)
        self.state_label.configure(text=title, foreground=color if s.active or s.problem else "")
        self.detail_label.configure(text=detail)
        self.main_button.configure(text="Turn protection OFF" if s.active else "Turn protection ON")

        # Show the categories in use (or remembered); while protection is off, keep whatever
        # the user has ticked since the window opened.
        if s.categories is not None and (s.active or self.first_refresh):
            for key, var in self.cat_vars.items():
                var.set(key in s.categories)
        if s.categories is None:
            self.custom_note.pack(anchor="w", pady=(4, 0), before=self.weekly_check)
        else:
            self.custom_note.pack_forget()
        if s.active or s.scheduled:
            self.weekly_intent = s.scheduled   # follow reality whenever it is known
        self.weekly_var.set(not self.test_mode and (s.scheduled or (not s.active and self.weekly_intent)))
        self.first_refresh = False
        self.loading = False

        if not self.can_change:
            if os.name == "nt":
                self.banner_label.configure(text="HostBlock needs administrator permission to make changes.")
                self.banner_button.pack(anchor="w", pady=(8, 0))
            else:
                self.banner_label.configure(
                    text="To make changes, close this window and open it with administrator rights:\n"
                         f"    sudo python3 \"{Path(__file__).resolve()}\"")
            self.banner.pack(fill="x", pady=(0, 12), before=self.card)
        self._update_controls()

    def _selected_categories(self) -> set[str]:
        return {key for key, var in self.cat_vars.items() if var.get()}

    def _categories_changed(self) -> bool:
        s = self.snap
        return s.active and s.categories is not None and self._selected_categories() != s.categories

    def _update_controls(self) -> None:
        if self.loading:
            return
        s = self.snap
        enabled = self.can_change and not self.busy

        def set_enabled(widget: ttk.Widget, on: bool) -> None:
            widget.state(["!disabled"] if on else ["disabled"])

        self.update_button.configure(text="Apply changes" if self._categories_changed() else "Update now")
        set_enabled(self.main_button, enabled and not s.problem)
        set_enabled(self.update_button, enabled and s.active)
        set_enabled(self.undo_button, enabled)
        set_enabled(self.weekly_check, enabled and not self.test_mode)
        for check in self.cat_checks:
            set_enabled(check, enabled and s.categories is not None)

    # ----- button handlers ------------------------------------------------- #

    def _block_args(self) -> list[str]:
        args = ["block"]
        if self.snap.categories is None:          # custom list set up from the command line
            args += ["--url", self.snap.source]
        elif self._selected_categories():
            args += ["--extensions", *sorted(self._selected_categories())]
        if self.snap.min_entries != hb.MIN_ENTRIES_DEFAULT:
            args += ["--min-entries", str(self.snap.min_entries)]
        if self.snap.compact:
            args.append("--compact")
        for domain in self.snap.allow:
            args += ["--allow", domain]
        return args

    def on_main(self) -> None:
        if self.snap.active:
            self.run(["unblock"], "Turning protection off...",
                     lambda s: "Protection is off. Ads and trackers are no longer blocked.")
            return
        args = self._block_args()
        if self.weekly_var.get() and not self.snap.scheduled and not self.test_mode:
            args.append("--schedule")
        self.run(args, "Downloading the latest list and turning protection on...",
                 lambda s: f"Protection is on: {s.domains:,} sites blocked.")

    def on_update(self) -> None:
        if self._categories_changed():
            self.run(self._block_args(), "Applying your changes...",
                     lambda s: f"Changes applied: {s.domains:,} sites blocked.")
        else:
            self.run(["update"], "Downloading the latest list...",
                     lambda s: f"The list is up to date: {s.domains:,} sites blocked.")

    def on_weekly(self) -> None:
        want = self.weekly_var.get()
        self.weekly_intent = want
        if self.snap.active or (self.snap.scheduled and not want):
            if want:
                self.run(["schedule"], "Turning on weekly updates...",
                         lambda s: f"The list will now update every {hb.DAY_NAMES[hb.DEFAULT_DAY]}.")
            else:
                self.run(["unschedule"], "Turning off weekly updates...",
                         lambda s: "Weekly updates are off.")

    def on_undo(self) -> None:
        if messagebox.askyesno(
                "Undo everything?",
                "This puts your hosts file back exactly as it was before HostBlock was first turned on, "
                "and removes the weekly update.\n\nContinue?",
                icon="warning", parent=self):
            self.run(["restore"], "Undoing all HostBlock changes...",
                     lambda s: "Everything is back to how it was before HostBlock.")

    def on_restart_admin(self) -> None:
        if relaunch_as_admin():
            self.destroy()

    def toggle_details(self) -> None:
        if self.log.winfo_ismapped():
            self.log.pack_forget()
            self.details_button.configure(text="Show details")
        else:
            self.log.pack(fill="both", expand=True, pady=(8, 0))
            self.details_button.configure(text="Hide details")

    # ----- running actions ------------------------------------------------- #

    def run(self, args: list[str], busy_text: str, on_success: Callable[[Snapshot], str]) -> None:
        if self.busy:
            return
        cmd = elevated_command([*args, *self.extra_args])
        if cmd is None:
            self.refresh()
            return
        self.busy, self.on_success, self.output, self.cmd_kind = True, on_success, [], cmd[0]
        self._log(f"\n> hostblock.py {' '.join(args)}\n")
        self.message.configure(text=busy_text, foreground="")
        self.progress.pack(fill="x", pady=(0, 6), before=self.message)
        self.progress.start(12)
        self._update_controls()
        threading.Thread(target=self._worker, args=(cmd,), daemon=True).start()

    def _worker(self, cmd: list[str]) -> None:
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL, **NO_WINDOW)
            for raw in proc.stdout:
                self.events.put(("line", raw.decode("utf-8", errors="replace").rstrip("\r\n")))
            rc = proc.wait()
        except OSError as e:
            self.events.put(("line", f"Error: could not start {cmd[0]}: {e}"))
            rc = -1
        self.events.put(("done", rc))

    def _poll(self) -> None:
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "line":
                    self.output.append(value)
                    self._log(value + "\n")
                else:
                    self._finish(value)
        except queue.Empty:
            pass
        finally:  # keep polling even if handling one event failed
            self._poll_id = self.after(100, self._poll)

    def _finish(self, rc: int) -> None:
        self.busy = False
        self.progress.stop()
        self.progress.pack_forget()
        self.refresh()
        text = "\n".join(self.output)
        warning = any(line.startswith("Warning:") for line in self.output)
        if rc == 0 and warning:
            self.message.configure(text=self.on_success(self.snap) + "  There is a warning below.",
                                   foreground=AMBER)
            if not self.log.winfo_ismapped():
                self.toggle_details()
        elif rc == 0:
            self.message.configure(text=self.on_success(self.snap), foreground=GREEN)
        elif "(-128)" in text or (self.cmd_kind == "pkexec" and rc == 126):  # password prompt dismissed
            self.message.configure(text="Cancelled - nothing was changed.", foreground=GREY)
        else:
            self.message.configure(text=friendly_error(self.output), foreground=RED)
            if not self.log.winfo_ismapped():
                self.toggle_details()

    def _log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text)
        self.log.see("end")
        self.log.configure(state="disabled")


def main() -> None:
    parser = argparse.ArgumentParser(description="HostBlock window")
    parser.add_argument("--hosts-file", metavar="PATH", help="manage this file instead (for testing)")
    args = parser.parse_args()

    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)  # crisp text on high-DPI screens
            # Own taskbar button and icon, instead of being grouped with Python.
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("HostBlock.App")
        except Exception:
            pass
        if not hb.is_admin() and relaunch_as_admin():
            return  # the elevated copy takes over

    hosts = Path(args.hosts_file).resolve() if args.hosts_file else hb.default_hosts_path()
    extra = ["--hosts-file", str(hosts)] if args.hosts_file else []
    try:
        app = App(hosts, extra)
    except Exception:
        # Opened without a console (pythonw), an error would otherwise vanish silently.
        import traceback
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("HostBlock", "HostBlock could not start:\n\n" + traceback.format_exc(limit=4))
        root.destroy()
        return
    app.mainloop()


if __name__ == "__main__":
    main()

import hashlib
import json
import subprocess
import sys
from pathlib import Path
from importlib.metadata import version, PackageNotFoundError

VOL_BOOTSTRAP = "import sys; from volatility3.cli import main; sys.argv[0] = 'vol'; sys.exit(main())"

SYMBOLS_DIR = Path(__file__).resolve().parent.parent / "symbols"

APPINIT_KEY = "Microsoft\\Windows NT\\CurrentVersion\\Windows"

PLUGINS = {
    "info": ["windows.info"],
    "pslist": ["windows.pslist"],
    "psscan": ["windows.psscan"],
    "pstree": ["windows.pstree"],
    "cmdline": ["windows.cmdline"],
    "dlllist": ["windows.dlllist"],
    "netscan": ["windows.netscan"],
    "malfind": ["windows.malware.malfind"],
    "appinit": ["windows.registry.printkey", "--key", APPINIT_KEY],
    "appinit_wow64": ["windows.registry.printkey", "--key", "Wow6432Node\\" + APPINIT_KEY],
}


class PluginError(Exception):
    pass


def volatility_version():
    try:
        return version("volatility3")
    except PackageNotFoundError:
        return "unknown"


def hash_file(path, chunk_size=4 * 1024 * 1024):
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    with open(path, "rb") as handle:
        while chunk := handle.read(chunk_size):
            sha256.update(chunk)
            md5.update(chunk)
    return {"sha256": sha256.hexdigest(), "md5": md5.hexdigest()}


def flatten(rows):
    flat = []
    for row in rows:
        children = row.pop("__children", []) or []
        flat.append(row)
        flat.extend(flatten(children))
    return flat


def run_plugin(dump_path, plugin_args, timeout=1800):
    plugin = plugin_args[0]
    command = [sys.executable, "-c", VOL_BOOTSTRAP, "-q", "-r", "json"]
    if SYMBOLS_DIR.is_dir():
        command += ["-s", str(SYMBOLS_DIR)]
    command += ["-f", str(dump_path), *plugin_args]
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise PluginError(f"{plugin} timed out after {timeout} seconds") from exc

    output = process.stdout
    start = output.find("[")
    if process.returncode != 0 or start == -1:
        details = [line.strip() for line in (process.stderr or output).strip().splitlines() if line.strip()]
        errors = [line for line in details if "Error:" in line or line.startswith("Unable to") or "not supported" in line]
        message = errors[-1] if errors else (details[-1] if details else "no output")
        raise PluginError(f"{plugin} failed: {message}")

    try:
        return flatten(json.loads(output[start:]))
    except json.JSONDecodeError as exc:
        raise PluginError(f"{plugin} returned invalid JSON") from exc

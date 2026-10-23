import json
import platform
import secrets
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .detection import analyze
from .engine import PLUGINS, PluginError, hash_file, run_plugin, volatility_version
from .report import build_report

INFO_FIELDS = {
    "Is64Bit": "64-bit",
    "IsPAE": "PAE",
    "NtMajorVersion": "NT Major Version",
    "NtMinorVersion": "NT Minor Version",
    "NtProductType": "Product Type",
    "NtSystemRoot": "System Root",
    "SystemTime": "System Time at Capture",
    "NTBuildLab": "Build Lab",
    "MajorOperatingSystemVersion": "PE OS Major Version",
    "MinorOperatingSystemVersion": "PE OS Minor Version",
    "KeNumberProcessors": "Processors",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _write_json(path, payload):
    Path(path).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")


def _system_info(rows):
    values = {row.get("Variable"): row.get("Value") for row in rows or []}
    return {label: values[key] for key, label in INFO_FIELDS.items() if values.get(key) not in (None, "")}


def run_case(dump_path, case_dir, case_id, progress=None):
    dump_path = Path(dump_path)
    case_dir = Path(case_dir)
    raw_dir = case_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    steps = len(PLUGINS) + 3

    def report(step, message):
        if progress:
            progress(step, steps, message)

    started = _now()
    report(1, "Hashing evidence (SHA-256, MD5)")
    hashes_before = hash_file(dump_path)

    data = {}
    plugin_log = []
    for index, (key, plugin_args) in enumerate(PLUGINS.items(), start=2):
        plugin = " ".join(plugin_args[:1] + [f'"{a}"' if " " in a else a for a in plugin_args[1:]])
        report(index, f"Running {plugin_args[0]}" + (f" ({key})" if len(plugin_args) > 1 else ""))
        begin = datetime.now(timezone.utc)
        try:
            data[key] = run_plugin(dump_path, plugin_args)
            status, detail = "ok", f"{len(data[key])} rows"
            _write_json(raw_dir / f"{key}.json", data[key])
        except PluginError as exc:
            data[key] = None
            status, detail = "failed", str(exc)
        elapsed = (datetime.now(timezone.utc) - begin).total_seconds()
        plugin_log.append({"plugin": plugin, "status": status, "detail": detail, "seconds": round(elapsed, 1)})

    if data.get("info") is None and data.get("pslist") is None:
        _write_json(case_dir / "plugin_log.json", plugin_log)
        details = "\n".join(f"  {x['plugin']}: {x['detail']}" for x in plugin_log[:2])
        raise RuntimeError(
            "Volatility could not parse this image as a Windows memory dump. "
            "Check that the file is a complete Windows RAM image and that symbol tables can be downloaded.\n"
            + details
        )

    report(len(PLUGINS) + 2, "Running detection rules")
    analysis = analyze(data)

    hashes_after = hash_file(dump_path)
    results = {
        "case_id": case_id,
        "evidence": {
            "file_name": dump_path.name,
            "size_bytes": dump_path.stat().st_size,
            "sha256": hashes_before["sha256"],
            "md5": hashes_before["md5"],
            "integrity_verified": hashes_before == hashes_after,
        },
        "analysis": {
            "started_utc": started,
            "finished_utc": _now(),
            "examiner_host": platform.node(),
            "tool": f"MemTrace {__version__}",
            "engine": f"Volatility {volatility_version()}",
            "python": platform.python_version(),
            "analyst_os": f"{platform.system()} {platform.release()}",
        },
        "system": _system_info(data.get("info")),
        "plugins": plugin_log,
        **analysis,
    }

    _write_json(case_dir / "results.json", results)
    report(len(PLUGINS) + 3, "Generating PDF report")
    build_report(results, case_dir / f"{case_id}_report.pdf")
    return results


def new_case_id():
    return "MT-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2).upper()

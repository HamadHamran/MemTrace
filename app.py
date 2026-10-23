import json
import threading
import traceback
from pathlib import Path

from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from memtrace.pipeline import new_case_id, run_case

BASE_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = BASE_DIR / "evidence"
CASES_DIR = BASE_DIR / "cases"
ALLOWED_EXTENSIONS = {".vmem", ".raw", ".mem", ".dmp", ".bin", ".img", ".lime"}

EVIDENCE_DIR.mkdir(exist_ok=True)
CASES_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = "memtrace-local"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 ** 3

analysis_lock = threading.Lock()


def case_path(case_id):
    path = (CASES_DIR / secure_filename(case_id)).resolve()
    if path.parent != CASES_DIR.resolve() or not path.is_dir():
        abort(404)
    return path


def read_json(path, default=None):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load_status(case_dir):
    status = read_json(case_dir / "status.json")
    if status:
        return status
    results = read_json(case_dir / "results.json")
    if results:
        return {"state": "done", "evidence": results.get("evidence", {}).get("file_name"), "message": "Analysis complete"}
    return None


def write_status(case_dir, **fields):
    status = read_json(case_dir / "status.json", {})
    status.update(fields)
    (case_dir / "status.json").write_text(json.dumps(status, indent=2), encoding="utf-8")


def worker(dump_path, case_dir, case_id):
    def progress(step, total, message):
        write_status(case_dir, state="running", step=step, total=total, message=message)

    with analysis_lock:
        try:
            run_case(dump_path, case_dir, case_id, progress)
            write_status(case_dir, state="done", message="Analysis complete")
        except Exception as exc:
            write_status(case_dir, state="error", message=str(exc), trace=traceback.format_exc()[-2000:])


def start_case(dump_path):
    case_id = new_case_id()
    case_dir = CASES_DIR / case_id
    case_dir.mkdir(parents=True)
    write_status(case_dir, state="queued", step=0, total=1, message="Waiting to start", evidence=dump_path.name)
    threading.Thread(target=worker, args=(dump_path, case_dir, case_id), daemon=True).start()
    return case_id


def list_cases():
    cases = []
    for case_dir in sorted(CASES_DIR.iterdir(), reverse=True):
        if not case_dir.is_dir():
            continue
        status = load_status(case_dir)
        if not status:
            continue
        results = read_json(case_dir / "results.json", {})
        cases.append({
            "id": case_dir.name,
            "state": status.get("state"),
            "evidence": status.get("evidence"),
            "verdict": (results.get("summary") or {}).get("verdict"),
            "score": (results.get("summary") or {}).get("score"),
        })
    return cases


def list_evidence():
    return sorted(
        (f.name for f in EVIDENCE_DIR.iterdir() if f.is_file() and f.suffix.lower() in ALLOWED_EXTENSIONS),
        key=str.lower,
    )


@app.route("/")
def index():
    return render_template("index.html", cases=list_cases(), evidence=list_evidence(), extensions=sorted(ALLOWED_EXTENSIONS))


@app.post("/analyze")
def analyze():
    upload = request.files.get("dump")
    existing = request.form.get("existing", "").strip()

    if upload and upload.filename:
        name = secure_filename(upload.filename)
        if Path(name).suffix.lower() not in ALLOWED_EXTENSIONS:
            flash(f"Unsupported file type. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}")
            return redirect(url_for("index"))
        dump_path = EVIDENCE_DIR / name
        if dump_path.exists():
            flash(f"{name} already exists in the evidence folder. Select it from the list instead.")
            return redirect(url_for("index"))
        upload.save(dump_path)
    elif existing:
        dump_path = EVIDENCE_DIR / secure_filename(existing)
        if not dump_path.is_file():
            flash("Selected evidence file was not found.")
            return redirect(url_for("index"))
    else:
        flash("Upload a memory image or select one from the evidence folder.")
        return redirect(url_for("index"))

    return redirect(url_for("case", case_id=start_case(dump_path)))


@app.route("/case/<case_id>")
def case(case_id):
    case_dir = case_path(case_id)
    status = load_status(case_dir) or {}
    results = read_json(case_dir / "results.json") if status.get("state") == "done" else None
    return render_template("case.html", case_id=case_id, status=status, results=results)


@app.route("/case/<case_id>/status")
def case_status(case_id):
    return jsonify(load_status(case_path(case_id)) or {})


@app.route("/case/<case_id>/report")
def case_report(case_id):
    report = case_path(case_id) / f"{case_id}_report.pdf"
    if not report.is_file():
        abort(404)
    return send_file(report, as_attachment=True, download_name=report.name)


@app.route("/case/<case_id>/results.json")
def case_results(case_id):
    results = case_path(case_id) / "results.json"
    if not results.is_file():
        abort(404)
    return send_file(results, as_attachment=True, download_name=f"{case_id}_results.json")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)

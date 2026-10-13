"""The single-file build: it runs as a CLI and keeps module paths in tracebacks."""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def build(tmp_path):
    out = str(tmp_path / "ida_better_reverse.py")
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "bundle.py"), out], check=True,
                   capture_output=True)
    return out


def test_cli_runs(tmp_path):
    out = build(tmp_path)
    r = subprocess.run([sys.executable, out, "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "--repair" in r.stdout
    r = subprocess.run([sys.executable, out, str(tmp_path / "missing")], capture_output=True, text=True)
    assert r.returncode == 1 and "cannot read" in r.stderr


def test_traceback_names_the_module(tmp_path):
    out = build(tmp_path)
    code = ("import importlib.util, traceback\n"
            "s = importlib.util.spec_from_file_location('bundle', %r)\n"
            "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            "try:\n    m.detect(path=%r)\n"
            "except OSError:\n    traceback.print_exc()\n") % (out, str(tmp_path / "missing"))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert os.path.join("ibr", "core", "detect.py") in r.stderr
    assert 'with open(path, "rb") as f:' in r.stderr

"""The release zip: its layout, the entry file as a CLI and a module, real paths in tracebacks."""
import os
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "src", "ibr")


def build(tmp_path):
    out = str(tmp_path / "ida_better_reverse.zip")
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "package.py"), out], check=True,
                   capture_output=True)
    return out


def unpack(tmp_path):
    user = tmp_path / "idausr"
    with zipfile.ZipFile(build(tmp_path)) as z:
        z.extractall(user)
    return str(user / "plugins" / "ida_better_reverse.py")


def test_layout(tmp_path):
    out = build(tmp_path)
    names = zipfile.ZipFile(out).namelist()
    src = set()
    for dirpath, dirs, files in os.walk(PKG):
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        for fn in files:
            if not fn.endswith(".pyc"):
                rel = os.path.relpath(os.path.join(dirpath, fn), os.path.dirname(PKG))
                src.add("plugins/ida_better_reverse/" + rel.replace(os.sep, "/"))
    assert set(names) == src | {"plugins/ida_better_reverse.py", "plugins/ida_better_reverse/LICENSE"}
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)
    assert all(b"\r\n" not in zipfile.ZipFile(out).read(n) for n in names if n.endswith(".py"))
    assert open(build(tmp_path), "rb").read() == open(out, "rb").read()       # reproducible


def test_cli_runs(tmp_path):
    entry = unpack(tmp_path)
    r = subprocess.run([sys.executable, entry, "--help"], capture_output=True, text=True)
    assert r.returncode == 0 and "--repair" in r.stdout
    r = subprocess.run([sys.executable, entry, str(tmp_path / "missing")], capture_output=True, text=True)
    assert r.returncode == 1 and "cannot read" in r.stderr


def test_module_api(tmp_path):
    entry = unpack(tmp_path)
    code = ("import importlib.util\n"
            "s = importlib.util.spec_from_file_location('ida_better_reverse', %r)\n"
            "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            "import ibr\n"
            "from ibr.core import resources\n"
            "m.set_lang('zh'); print(m.LANG, m.__version__, ibr.__version__)\n"
            "print(callable(m.detect), m.canon('__isoc99_scanf'))\n"
            "print(len(resources.load('fingerprint.bin')))\n"
            "print(ibr.__file__)\n") % entry
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    lang, v1, v2, is_callable, canon, size, path = r.stdout.split()
    assert lang == "zh" and v1 == v2 and is_callable == "True" and canon == "scanf"
    assert int(size) == os.path.getsize(os.path.join(PKG, "data", "fingerprint.bin"))
    assert path.startswith(os.path.join(os.path.dirname(entry), "ida_better_reverse", "ibr"))


def test_traceback_names_the_module(tmp_path):
    entry = unpack(tmp_path)
    code = ("import importlib.util, traceback\n"
            "s = importlib.util.spec_from_file_location('ida_better_reverse', %r)\n"
            "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            "try:\n    m.detect(path=%r)\n"
            "except OSError:\n    traceback.print_exc()\n") % (entry, str(tmp_path / "missing"))
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert os.path.join("plugins", "ida_better_reverse", "ibr", "core", "detect.py") in r.stderr
    assert 'with open(path, "rb") as f:' in r.stderr


def test_old_single_file_does_not_win(tmp_path):
    # 2.3 and earlier install an import hook for `ibr` (marked _ibr_bundle) when IDA loads
    # them; with an old copy still in another plugins/ folder, it must not serve our imports
    entry = unpack(tmp_path)
    code = ("import sys, importlib.abc, importlib.util\n"
            "class Old(importlib.abc.MetaPathFinder):\n"
            "    _ibr_bundle = True\n"
            "    base = 'OLD/ida_better_reverse.py'\n"
            "    def find_spec(self, name, path=None, target=None):\n"
            "        if name == 'ibr' or name.startswith('ibr.'):\n"
            "            raise ImportError('old bundle served ' + name)\n"
            "sys.meta_path.insert(0, Old())\n"
            "s = importlib.util.spec_from_file_location('ida_better_reverse', %r)\n"
            "m = importlib.util.module_from_spec(s); s.loader.exec_module(m)\n"
            "import ibr; print(ibr.__file__)\n") % entry
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "OLD/ida_better_reverse.py" in r.stdout
    assert os.path.join("plugins", "ida_better_reverse", "ibr") in r.stdout.splitlines()[-1]


def test_missing_folder_is_explained(tmp_path):
    lone = tmp_path / "ida_better_reverse.py"
    lone.write_bytes(open(os.path.join(ROOT, "ida_better_reverse.py"), "rb").read())
    r = subprocess.run([sys.executable, str(lone), "--help"], capture_output=True, text=True)
    assert r.returncode != 0 and "ida_better_reverse/ is missing" in r.stderr


def test_checkout_runs_from_src():
    r = subprocess.run([sys.executable, os.path.join(ROOT, "ida_better_reverse.py"), "--help"],
                       capture_output=True, text=True)
    assert r.returncode == 0 and "--repair" in r.stdout

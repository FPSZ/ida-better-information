"""The dependency rule of the ports-and-adapters layout, checked on the import statements."""
import ast
import os

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src", "ibr")
IDA = ("ida", "idaapi", "idautils", "idc", "PyQt5", "PySide6", "sip")
# layer -> layers it may import
ALLOWED = {"core": {"core"}, "app": {"core", "app", "ports"}, "analysis": {"core", "ports", "analysis"},
           "ports": {"ports"}}


def imports(path):
    """(top-level module, ibr layer or None) for every import in the file."""
    tree = ast.parse(open(path, encoding="utf-8").read())
    rel = os.path.relpath(path, PKG).replace(os.sep, "/").split("/")
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out += [(a.name.split(".")[0], None) for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0:
                out.append((node.module.split(".")[0], None))
                continue
            base = rel[:-1][:len(rel) - 1 - (node.level - 1)] if node.level > 1 else rel[:-1]
            target = (base + (node.module or "").split(".")) if node.module else base
            target = [t for t in target if t]
            if not target:                    # `from .. import x` at the package root
                target = [a.name for a in node.names][:1]
            out.append(("ibr", target[0].replace(".py", "")))
    return out


def test_inner_layers_do_not_reach_outwards():
    bad = []
    for dirpath, _, files in os.walk(PKG):
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, PKG).replace(os.sep, "/")
            layer = rel.split("/")[0].replace(".py", "")
            if layer not in ALLOWED:
                continue
            for mod, ibr_layer in imports(path):
                if mod.startswith(IDA) or (ibr_layer is not None and ibr_layer not in ALLOWED[layer]
                                           and ibr_layer != "__init__"):
                    bad.append("%s imports %s" % (rel, ibr_layer or mod))
    assert not bad, bad

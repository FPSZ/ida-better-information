"""Detection result as panel text."""
from .fingerprint import _lib_label
from .i18n import T


def _fmt(r):
    if not r:
        return ""
    conf = {"high": T("high", "高"), "medium": T("medium", "中"),
            "low": T("low", "低")}.get(r.get("confidence"), r.get("confidence"))
    # verdict first: it is the line the user opened the panel for
    lines = ["%s   [%s %s]" % (r.get("best"), T("confidence", "置信度"), conf),
             "%s / %s / %s" % (r.get("os"), r.get("kind"), r.get("arch") or "?")]
    for v, s, h, n in r.get("ranking", []):
        lines.append("  %-12s %5.1f%%  %d/%d" % (_lib_label(v), s * 100, h, n))
    for note in r.get("notes", []):
        lines.append("  . " + note)
    if r.get("build_id"):
        lines.append("build-id: %s" % r["build_id"])
    return "\n".join(lines)

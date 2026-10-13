"""The panel language, saved in the IDA user directory."""
import json
import os

from ...core import i18n

try:
    import ida_diskio
    _CFG = os.path.join(ida_diskio.get_user_idadir(), "ida_better_reverse.cfg")
except Exception:
    _CFG = os.path.join(os.path.expanduser("~"), ".ida_better_reverse.cfg")


def load_lang():
    i18n.set_lang("en")
    # pre-rename installs saved their setting as ida_better_information.cfg
    for cfg in (_CFG, _CFG.replace("better_reverse", "better_information")):
        try:
            i18n.set_lang(json.load(open(cfg)).get("lang", "en"))
            return
        except Exception:
            continue


def save_lang():
    try:
        json.dump({"lang": i18n.LANG}, open(_CFG, "w"))
    except Exception:
        pass

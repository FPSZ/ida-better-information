"""Output language. One setting for the whole process, chosen in the panel."""
LANG = "en"


def set_lang(lang):
    global LANG
    LANG = lang if lang in ("en", "zh") else "en"


def T(en, zh):
    return zh if LANG == "zh" else en


def pick(pair):
    """The (en, zh) pair's entry for the current language."""
    return pair[1] if LANG == "zh" else pair[0]

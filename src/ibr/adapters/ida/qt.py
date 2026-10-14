"""The Qt binding that matches IDA's own Qt (PySide6 from IDA 9.2, PyQt5 before), and the
QWidget behind an IDA widget. A pip-installed PySide6 inside an IDA 9.1 would otherwise
load Qt6 into a Qt5 process."""
import ctypes

import idaapi

QtCore = QtGui = QtWidgets = None
BINDING = None
for _name in (("PySide6", "PyQt5") if getattr(idaapi, "IDA_SDK_VERSION", 0) >= 920
              else ("PyQt5", "PySide6")):
    try:
        QtCore = __import__(_name + ".QtCore", fromlist=["QtCore"])
        QtGui = __import__(_name + ".QtGui", fromlist=["QtGui"])
        QtWidgets = __import__(_name + ".QtWidgets", fromlist=["QtWidgets"])
        BINDING = _name
        break
    except Exception:
        pass


def _ptr(tw):
    if type(tw).__name__ == "SwigPyObject":
        return int(tw)
    get = ctypes.pythonapi.PyCapsule_GetPointer
    get.restype, get.argtypes = ctypes.c_void_p, [ctypes.py_object, ctypes.c_char_p]
    return get(tw, b"$valid$")


def qwidget(tw):
    """The QWidget behind an IDA TWidget, or None."""
    if tw is None or BINDING is None:
        return None
    p = _ptr(tw)
    if BINDING == "PySide6":
        import shiboken6
        return shiboken6.wrapInstance(p, QtWidgets.QWidget)
    from PyQt5 import sip
    return sip.wrapinstance(p, QtWidgets.QWidget)


def dark_theme():
    """IDA is using a dark colour theme (judged by the window background)."""
    if QtWidgets is None:
        return False
    try:
        return QtWidgets.QApplication.palette().color(QtGui.QPalette.Window).lightness() < 128
    except Exception:
        return False

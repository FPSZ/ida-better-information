"""Data files (fingerprint DB, syscall tables), read from ibr/data/."""
import os

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def load(name):
    """Raw bytes of a data file."""
    with open(os.path.join(DATA, name), "rb") as f:
        return f.read()

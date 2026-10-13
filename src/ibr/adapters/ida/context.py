"""Composition root: the one set of adapters and the undo journal for this IDA session."""
from ...core.journal import Journal
from .program import IdaDecompiler, IdaProgram, IdaSignatures

PROG = IdaProgram()
SIGS = IdaSignatures()
DEC = IdaDecompiler()
JOURNAL = Journal()

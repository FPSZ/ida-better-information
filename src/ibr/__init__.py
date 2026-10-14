"""IDA Better Reverse — know your binary before you read a single line.

Layout (ports and adapters):
  core/      pure Python, no IDA imports: detection, decoders, note text, undo journal
  ports.py   what the application needs from a disassembler (database, decompiler, signatures)
  app/       use cases (detect, apply signatures, annotate, undo) written against the ports
  adapters/  IDA (idaapi, Hex-Rays, Qt panel) and the standalone CLI
  analysis/  analyses of the program's own code: data flow, flowchart (more planned)

The release is a zip built by tools/package.py: the entry file ida_better_reverse.py
plus this package, installed as plugins/ida_better_reverse.py and plugins/ida_better_reverse/ibr.
"""
__version__ = "2.4.0"

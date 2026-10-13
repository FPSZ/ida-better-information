"""IDA Better Reverse — know your binary before you read a single line.

Layout (ports and adapters):
  core/      pure Python, no IDA imports: detection, decoders, note text, undo journal
  ports.py   what the application needs from a disassembler (database, decompiler, signatures)
  app/       use cases (detect, apply signatures, annotate, undo) written against the ports
  adapters/  IDA (idaapi, Hex-Rays, Qt panel) and the standalone CLI
  analysis/  reserved for challenge-solving analyses (not implemented yet)

The release is a single file built by tools/bundle.py.
"""
__version__ = "2.3.0"

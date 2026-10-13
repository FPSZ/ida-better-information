"""Interface for AI agents (not implemented yet).

Planned: an MCP server and a JSON command line that drive the same use cases as the
panel (ibr.app), so a model can run the plugin and read its results. It is meant to work
next to an IDA MCP server: that one reads and edits the database at a low level
(decompile, rename, xrefs); this one answers higher-level questions.

Design goals, so that small models can use it too:
  - few tools, each answering one question: overview (runtime, arch, packer, tampering,
    entry/main), interesting functions (ranked, one line each), notes for one function
    (pseudocode with the call-site notes inline), apply (signatures + comments, undoable),
    undo; later the challenge map, algorithm and VM analyses from ibr.analysis
  - compact JSON with a fixed schema, addresses as hex strings, bounded lengths
  - two modes: inside a running IDA (shares the database with the IDA MCP server) and
    headless through idalib (`python ida_better_reverse.py <binary> --agent ...`)
"""

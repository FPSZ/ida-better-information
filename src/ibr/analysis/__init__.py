"""Challenge-solving analyses, each pure (written against ibr.ports, testable without IDA).

  dataflow.py    data flow of one variable inside one function: the lines its value comes
                 from and goes to (prototype, opened with Ctrl-Alt-F from the pseudocode)
  flowchart.py   the function as a program flowchart, the way textbooks draw one, with the
                 variable's lines lit (Space in the data-flow window; laid out by
                 core/chartlayout.py)
  expr.py        expressions as C and as math for the chart: casts and printf's guessed
                 arguments left out, MMX/SSE intrinsics folded (_m_pxor is ^, a shift pair <<<)

Planned:
  triage.py  challenge map: input -> check -> success / failure, compared bytes, anti-debug
  algo.py    algorithm recognition (TEA family, RC4, base64 alphabets, xor loops) with
             parameter extraction and a generated decryption script
  vm.py      custom VM helper: dispatcher loop, bytecode dump, per-opcode handler summary,
             disassembler skeleton
"""

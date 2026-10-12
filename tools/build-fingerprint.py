#!/usr/bin/env python3
# build-fingerprint.py —— 把 db/*.pat 压成 fingerprint.json(每版本一组"函数字节锚点")
# 锚点 = FLAIR pattern 里最长的一段无通配字节(>=10字节),用来在目标程序里按字节查找。
import os, re, json, glob, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB   = os.path.join(HERE, "db")
OUT  = os.path.join(HERE, "fingerprint.json")

MIN_RUN  = 10   # 最短无通配字节数
MAX_ANCH = 24   # 锚点最多取多少字节

def longest_literal_run(pat_token: str) -> bytes:
    """pattern 第一字段形如 '558B..E8........C3';取最长的无'..'连续字节段。"""
    best = b""
    i = 0; cur = bytearray()
    n = len(pat_token)
    while i + 1 < n:
        c = pat_token[i:i+2]
        if c == "..":
            if len(cur) > len(best): best = bytes(cur)
            cur = bytearray()
        else:
            try: cur.append(int(c, 16))
            except ValueError:
                if len(cur) > len(best): best = bytes(cur)
                cur = bytearray()
        i += 2
    if len(cur) > len(best): best = bytes(cur)
    return best[:MAX_ANCH]

def anchors_from_pat(path: str) -> list:
    out = set()
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("---"): continue
            tok = line.split(" ", 1)[0]
            if len(tok) < 2*MIN_RUN: continue
            run = longest_literal_run(tok)
            if len(run) >= MIN_RUN:
                out.add(run.hex())
    return sorted(out)

def main():
    fps = {}
    pats = sorted(glob.glob(os.path.join(DB, "*.pat")))
    if not pats:
        print("no .pat in db/ — run build-pattern-db.sh first"); sys.exit(1)
    for p in pats:
        ver = os.path.splitext(os.path.basename(p))[0]
        a = anchors_from_pat(p)
        fps[ver] = a
        print(f"{ver}: {len(a)} anchors")
    with open(OUT, "w") as f:
        json.dump(fps, f)
    print(f"-> wrote {OUT} ({len(fps)} versions)")

if __name__ == "__main__":
    main()

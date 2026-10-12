#!/usr/bin/env python3
# detect.py —— 识别一个程序用的 C 运行库/编译器版本
#   Linux 动态: GLIBC_2.xx 需求(下限) + build-id + 横幅
#   Linux 静态/stripped: 用 fingerprint.json 的函数字节锚点匹配(glibc + musl),按命中率排名
#   Go (ELF/PE): 读内嵌 go1.xx.y 版本串(精确)
#   Windows PE: Rich header 看编译器/链接器版本,路由到 IDA 的 MSVC/UCRT 签名
# 用法: python detect.py <binary> [--static|--dynamic] [--top N]
import os, re, sys, json, struct

HERE = os.path.dirname(os.path.abspath(__file__))
FP   = os.path.join(HERE, "fingerprint.json")

def _load_fp():
    try:
        with open(FP) as f: return json.load(f)
    except Exception: return {}

def _lib_label(key):
    if key.startswith("musl"): return "musl " + key.split("_", 1)[-1]
    return "glibc " + key

# ---------- Go ----------
def detect_go(data):
    # Go 二进制内嵌版本串;buildinf 魔数 "\xff Go buildinf:" 或 runtime.buildVersion
    is_go = (b"\xff Go buildinf:" in data) or (b"Go build ID:" in data) or (b"runtime.buildVersion" in data)
    m = re.search(rb"go1\.\d{1,2}(?:\.\d{1,3})?", data)
    if is_go or m:
        ver = m.group(0).decode() if m else "unknown"
        return {"lang": "go", "version": ver}
    return None

# ---------- Windows PE ----------
def _decode_rich(data, pe_off):
    try:
        head = data[:pe_off]
        ri = head.rfind(b"Rich")
        if ri < 0: return None
        key = struct.unpack("<I", head[ri+4:ri+8])[0]
        # 向前找 DanS(= 0x536E6144 ^ key)
        di = head.rfind(struct.pack("<I", 0x536E6144 ^ key), 0, ri)
        if di < 0: return None
        comps = []
        off = di + 16  # 跳过 DanS + 3 个填充
        while off + 8 <= ri:
            v = struct.unpack("<I", head[off:off+4])[0] ^ key
            c = struct.unpack("<I", head[off+4:off+8])[0] ^ key
            prodid, build = v >> 16, v & 0xFFFF
            if prodid or build: comps.append((prodid, build, c))
            off += 8
        return comps
    except Exception:
        return None

def detect_pe(data):
    r = {"os": "windows", "arch": None, "linker": None, "rich": None, "notes": []}
    try:
        e_lfanew = struct.unpack("<I", data[0x3C:0x40])[0]
        if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
            r["notes"].append("MZ 但 PE 头异常"); return r
        machine = struct.unpack("<H", data[e_lfanew+4:e_lfanew+6])[0]
        r["arch"] = {0x14c: "x86", 0x8664: "x64", 0xaa64: "arm64"}.get(machine, hex(machine))
        opt = e_lfanew + 24
        r["linker"] = "%d.%d" % (data[opt+2], data[opt+3])
        comps = _decode_rich(data, e_lfanew)
        if comps:
            top = max(comps, key=lambda t: t[1])
            r["rich"] = comps
            r["notes"].append("Rich header 最高构建号 build=%d(越大编译器越新;对照 MSVC 版本表)" % top[1])
        else:
            r["notes"].append("无 Rich header(可能非 MSVC,或被抹)")
        r["notes"].append("Windows 库函数识别:IDA 自带 MSVC/UCRT FLIRT 多数会自动命名。")
    except Exception as e:
        r["notes"].append("PE 解析出错: %s" % e)
    return r

# ---------- Linux ELF ----------
def detect_elf(data, force=None, top=5):
    r = {"os": "linux", "kind": None, "banner": None, "glibc_min": None,
         "build_id": None, "ranking": [], "best": None, "confidence": "low", "notes": []}
    m = re.search(rb"\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00(.{20})", data, re.S)
    if m: r["build_id"] = m.group(1).hex()
    m = re.search(rb"GNU C Library[^\x00\n]{0,80}?(?:version|release)[^\x00\n]{0,20}?(\d+\.\d+)", data)
    if not m: m = re.search(rb"\bglibc[ -](\d+\.\d+)\b", data)
    if m:
        try: r["banner"] = m.group(1).decode()
        except Exception: pass
    reqs = [int(x) for x in re.findall(rb"GLIBC_2\.(\d+)", data)]
    if reqs: r["glibc_min"] = max(reqs)
    has_interp = (b"/ld-linux" in data) or (b"/ld-musl" in data)
    r["kind"] = force or ("dynamic" if has_interp else "static")

    if r["banner"]:
        r["best"] = "glibc " + r["banner"]; r["confidence"] = "high"
        r["notes"].append("命中版本横幅,精确。"); return r
    if r["kind"] == "dynamic":
        if b"/ld-musl" in data:
            r["notes"].append("动态链接 musl(Alpine)。")
            r["best"] = "musl (dynamic)"; r["confidence"] = "medium"; return r
        if r["glibc_min"] is not None:
            r["best"] = "glibc >=2.%s" % r["glibc_min"]; r["confidence"] = "medium"
            r["notes"].append("动态链接:需要 glibc >= 2.%s(下限,非精确)。" % r["glibc_min"])
        if r["build_id"]:
            r["notes"].append("有 build-id,可去 https://libc.rip 按 build-id 查精确版本。")
        return r

    fp = _load_fp()
    if not fp:
        r["notes"].append("fingerprint.json 不存在,先跑 build-fingerprint.py。"); return r
    distinct = set()
    for anchors in fp.values(): distinct.update(anchors)
    present = {}
    for a in distinct:
        try: present[a] = (data.find(bytes.fromhex(a)) != -1)
        except ValueError: present[a] = False
    scored = []
    for ver, anchors in fp.items():
        if not anchors: continue
        hit = sum(1 for a in anchors if present[a])
        scored.append((ver, hit/len(anchors), hit, len(anchors)))
    scored.sort(key=lambda t: t[1], reverse=True)
    r["ranking"] = [(v, round(s, 3), h, n) for (v, s, h, n) in scored[:top]]
    if scored:
        bestver, bests = scored[0][0], scored[0][1]
        second = scored[1][1] if len(scored) > 1 else 0.0
        r["best"] = _lib_label(bestver)
        ratio  = (bests / second) if second > 0 else 999.0
        margin = bests - second
        if   ratio >= 1.15 and margin >= 0.03:  r["confidence"] = "high"
        elif ratio >= 1.06 and margin >= 0.015: r["confidence"] = "medium"
        else:                                   r["confidence"] = "low"
        r["notes"].append("静态:函数字节锚点匹配,排名第一且明显领先即最可能版本。")
        r["notes"].append("领先幅度:比第2名高 %.1f 个百分点(×%.2f)。" % (margin*100, ratio))
        if bests < 0.05:
            r["confidence"] = "low"
            r["notes"].append("命中过低:版本可能不在指纹库内(用 build-pattern-db.sh 增补)。")
        elif r["confidence"] == "low":
            r["notes"].append("前几名太接近,建议对候选都试签名。")
    return r

def detect(path, force=None, top=5):
    with open(path, "rb") as f: data = f.read()
    if data[:2] == b"MZ":
        go = detect_go(data)
        r = detect_pe(data)
        if go: r["best"] = "Go " + go["version"]; r["notes"].insert(0, "Go 程序(PE),版本内嵌。")
        else: r["best"] = "MSVC (见 Rich/linker)"
        r["ranking"] = []; r["kind"] = "pe"; r["confidence"] = "high" if go else "medium"
        return r
    if data[:4] == b"\x7fELF":
        go = detect_go(data)
        if go:
            return {"os": "linux", "kind": "go", "best": "Go " + go["version"], "ranking": [],
                    "confidence": "high", "build_id": None,
                    "notes": ["Go 程序(ELF),版本串内嵌,精确。", "Go 用自带运行库,与 glibc 版本无关。"]}
        return detect_elf(data, force=force, top=top)
    return {"os": "?", "kind": None, "best": None, "ranking": [], "confidence": "low",
            "notes": ["不是 ELF/PE 文件"]}

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    force = "static" if "--static" in sys.argv else ("dynamic" if "--dynamic" in sys.argv else None)
    top = 5
    if "--top" in sys.argv:
        try: top = int(sys.argv[sys.argv.index("--top")+1])
        except Exception: pass
    if not args:
        print("用法: python detect.py <binary> [--static|--dynamic] [--top N]"); sys.exit(1)
    r = detect(args[0], force=force, top=top)
    print("="*60)
    print("目标      :", args[0])
    print("类型      :", r.get("os"), "/", r.get("kind"))
    if r.get("build_id"): print("build-id  :", r["build_id"])
    if r.get("arch"):     print("架构      :", r["arch"], " 链接器:", r.get("linker"))
    if r.get("ranking"):
        print("-"*60); print("版本匹配排名(命中率  命中/总锚点):")
        for v, s, h, n in r["ranking"]:
            print("  %-10s %6.1f%%  %d/%d  %s" % (_lib_label(v), s*100, h, n, "#"*int(s*30)))
    print("-"*60)
    print("结论      :", r.get("best"), "  置信度 =", r.get("confidence"))
    for note in r.get("notes", []): print("  ·", note)
    print("="*60)

if __name__ == "__main__":
    main()

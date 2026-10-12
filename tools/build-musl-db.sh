#!/usr/bin/env bash
# build-musl-db.sh —— 为 musl libc 各版本生成 db/musl_<ver>.pat(Alpine 静态程序识别)
ROOT="D:/CTF/tool/glibc-detect"
FLAIR="D:/CTF/tool/SURBIFByb2Zlc3Npb25hbCA5LjE/tools/flair"
SZ="D:/CTF/tool/7zip/7z.exe"
DB="$ROOT/db"; tmp="$ROOT/_tmp"; mkdir -p "$DB" "$tmp"
log="$ROOT/build-musl.log"; : > "$log"
AU="http://archive.ubuntu.com/ubuntu/pool/universe/m/musl"
OU="http://old-releases.ubuntu.com/ubuntu/pool/universe/m/musl"
JOBS=(
 "1.1.24|$AU/musl-dev_1.1.24-1_amd64.deb"
 "1.2.2|$AU/musl-dev_1.2.2-4_amd64.deb"
 "1.2.3|$OU/musl-dev_1.2.3-1_amd64.deb"
 "1.2.4|$AU/musl-dev_1.2.4-2_amd64.deb"
 "1.2.5|$AU/musl-dev_1.2.5-3build1_amd64.deb"
 "1.2.6|$AU/musl-dev_1.2.6-1_amd64.deb"
)
ok=0; fail=0
for j in "${JOBS[@]}"; do
  ver="${j%%|*}"; url="${j#*|}"; echo "================ musl $ver ================" | tee -a "$log"
  out="$DB/musl_$ver.pat"; [ -s "$out" ] && { echo "skip"|tee -a "$log"; ok=$((ok+1)); continue; }
  d="$tmp/musl_$ver"; rm -rf "$d"; mkdir -p "$d"; cd "$d"
  curl -fL -sS -o p.deb "$url" >>"$log" 2>&1 || { echo "FAIL $ver (download)"|tee -a "$log"; fail=$((fail+1)); continue; }
  "$SZ" x -y -oar p.deb >>"$log" 2>&1
  [ -f ar/data.tar ] || "$SZ" x -y -oar ar/data.tar.* >>"$log" 2>&1
  "$SZ" x -y -odt ar/data.tar >>"$log" 2>&1 || true
  a=$(find dt -name libc.a | head -1); [ -n "$a" ] || { echo "FAIL $ver (no libc.a)"|tee -a "$log"; fail=$((fail+1)); continue; }
  cp -f "$a" libc.a
  "$FLAIR/pelf.exe" libc.a "$out" >>"$log" 2>&1 || { echo "FAIL $ver (pelf)"|tee -a "$log"; fail=$((fail+1)); continue; }
  cd "$ROOT"; rm -rf "$d"
  if [ -s "$out" ]; then echo "OK musl $ver ($(wc -l < "$out") patterns)"|tee -a "$log"; ok=$((ok+1)); else echo "FAIL $ver"|tee -a "$log"; fail=$((fail+1)); fi
done
rm -rf "$tmp"
echo "================ DONE ok=$ok fail=$fail ================" | tee -a "$log"
# 重新编译指纹(glibc + musl 一起)
cd "$ROOT" && python build-fingerprint.py >>"$log" 2>&1
echo "fingerprint rebuilt" | tee -a "$log"

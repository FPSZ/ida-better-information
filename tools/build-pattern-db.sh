#!/usr/bin/env bash
# build-pattern-db.sh —— 为 glibc 2.19~2.44 各版本生成函数字节指纹(.pat),供 detect.py 做静态版本识别
# 纯 Windows: curl 下 libc6-dev .deb + 7-Zip 解 libc.a + FLAIR pelf 提取 pattern
ROOT="D:/CTF/tool/glibc-detect"
FLAIR="D:/CTF/tool/SURBIFByb2Zlc3Npb25hbCA5LjE/tools/flair"
SZ="D:/CTF/tool/7zip/7z.exe"
DB="$ROOT/db"; tmp="$ROOT/_tmp"; mkdir -p "$DB" "$tmp"
log="$ROOT/build-db.log"; : > "$log"
OLD="http://old-releases.ubuntu.com/ubuntu/pool/main/g/glibc"
ARC="http://archive.ubuntu.com/ubuntu/pool/main/g/glibc"
JOBS=(
 "2.19|$OLD/libc6-dev_2.19-10ubuntu2.3_amd64.deb"
 "2.21|$OLD/libc6-dev_2.21-0ubuntu4.3_amd64.deb"
 "2.23|$ARC/libc6-dev_2.23-0ubuntu11.3_amd64.deb"
 "2.24|$OLD/libc6-dev_2.24-9ubuntu2.2_amd64.deb"
 "2.26|$OLD/libc6-dev_2.26-0ubuntu2.1_amd64.deb"
 "2.27|$ARC/libc6-dev_2.27-3ubuntu1.6_amd64.deb"
 "2.28|$OLD/libc6-dev_2.28-0ubuntu1_amd64.deb"
 "2.29|$OLD/libc6-dev_2.29-0ubuntu2_amd64.deb"
 "2.30|$OLD/libc6-dev_2.30-0ubuntu2.2_amd64.deb"
 "2.31|$ARC/libc6-dev_2.31-0ubuntu9.18_amd64.deb"
 "2.32|$OLD/libc6-dev_2.32-0ubuntu3.2_amd64.deb"
 "2.33|$OLD/libc6-dev_2.33-0ubuntu5_amd64.deb"
 "2.34|$OLD/libc6-dev_2.34-0ubuntu3.2_amd64.deb"
 "2.35|$ARC/libc6-dev_2.35-0ubuntu3.15_amd64.deb"
 "2.36|$OLD/libc6-dev_2.36-0ubuntu4_amd64.deb"
 "2.37|$OLD/libc6-dev_2.37-0ubuntu2.2_amd64.deb"
 "2.38|$OLD/libc6-dev_2.38-1ubuntu6.3_amd64.deb"
 "2.39|$ARC/libc6-dev_2.39-0ubuntu8.9_amd64.deb"
 "2.40|$OLD/libc6-dev_2.40-1ubuntu3.1_amd64.deb"
 "2.41|$ARC/libc6-dev_2.41-6ubuntu1.2_amd64.deb"
 "2.42|$ARC/libc6-dev_2.42-0ubuntu3.1_amd64.deb"
 "2.43|$ARC/libc6-dev_2.43-2ubuntu2.4_amd64.deb"
 "2.44|$ARC/libc6-dev_2.44-1ubuntu2_amd64.deb"
)
ok=0; fail=0
for j in "${JOBS[@]}"; do
  ver="${j%%|*}"; url="${j#*|}"; echo "================ $ver ================" | tee -a "$log"
  [ -s "$DB/$ver.pat" ] && { echo "skip (exists)"|tee -a "$log"; ok=$((ok+1)); continue; }
  d="$tmp/$ver"; rm -rf "$d"; mkdir -p "$d"; cd "$d"
  curl -fL -sS -o p.deb "$url" >>"$log" 2>&1 || { echo "FAIL $ver (download)"|tee -a "$log"; fail=$((fail+1)); continue; }
  "$SZ" x -y -oar p.deb >>"$log" 2>&1
  [ -f ar/data.tar ] || "$SZ" x -y -oar ar/data.tar.* >>"$log" 2>&1
  "$SZ" x -y -odt ar/data.tar >>"$log" 2>&1 || true   # 7z 对危险符号链接报非零,忽略
  a=$(find dt -name libc.a | head -1); [ -n "$a" ] || { echo "FAIL $ver (no libc.a)"|tee -a "$log"; fail=$((fail+1)); continue; }
  cp -f "$a" libc.a
  "$FLAIR/pelf.exe" libc.a "$DB/$ver.pat" >>"$log" 2>&1 || { echo "FAIL $ver (pelf)"|tee -a "$log"; fail=$((fail+1)); continue; }
  cd "$ROOT"; rm -rf "$d"
  if [ -s "$DB/$ver.pat" ]; then echo "OK $ver ($(wc -l < "$DB/$ver.pat") patterns)"|tee -a "$log"; ok=$((ok+1)); else echo "FAIL $ver"|tee -a "$log"; fail=$((fail+1)); fi
done
rm -rf "$tmp"
echo "================ DONE ok=$ok fail=$fail ================" | tee -a "$log"
ls -1 "$DB"/*.pat 2>/dev/null | wc -l | xargs echo "pat files:"

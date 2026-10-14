"""Data flow of one variable inside one decompiled function: where its value comes from and
where it goes, everything else left out.

Input is the function's statement tree (ports.Tree). The analysis
  1. turns the tree into a control-flow graph of sites: an expression statement, a
     condition, a loop's init or step, a returned value;
  2. computes reaching definitions, so a read is linked only to the writes that can reach
     it (a variable reused for something else later stays apart);
  3. follows pointers to the memory they point at (a call's result such as malloc, a stack
     array, a global, what an argument points to), so a write through one pointer and a read
     through a copy of it meet on the same object;
  4. links every read to the writes that reach it, and slices from the chosen variable:
     backwards from its writes (where the value comes from), forwards from its writes and
     reads (where it goes).

Memory is tracked per object, not per byte: a store to buf[1] and a load of buf[0] are
linked. A call to an unknown function may read and write whatever its pointer arguments
point to; such sites are marked `may`. Nothing here imports IDA.
"""
import collections
import heapq

from ..core.names import canon

# library calls that write through pointer arguments: argument positions (the _chk variants
# keep the destination where the plain function has it)
WRITES = {
    "read": {1}, "pread": {1}, "recv": {1}, "recvfrom": {1}, "readlink": {1},
    "fread": {0}, "fgets": {0}, "gets": {0}, "getline": {0}, "getdelim": {0}, "getrandom": {0},
    "memcpy": {0}, "memmove": {0}, "mempcpy": {0}, "memset": {0}, "bzero": {0},
    "explicit_bzero": {0}, "qmemcpy": {0},
    "strcpy": {0}, "strncpy": {0}, "stpcpy": {0}, "stpncpy": {0}, "strcat": {0},
    "strncat": {0}, "strlcpy": {0},
    "sprintf": {0}, "snprintf": {0}, "vsprintf": {0}, "vsnprintf": {0},
    "qsort": {0}, "pipe": {0}, "time": {0}, "gettimeofday": {0}, "clock_gettime": {1},
}
# scanf family: everything after the format is written
SCANF = {"scanf": 1, "vscanf": 1, "fscanf": 2, "sscanf": 2, "vfscanf": 2, "vsscanf": 2}
# of those, the ones that read what they write over (append, sort, reuse a line buffer)
_READ_TOO = {"strcat", "strncat", "qsort", "getline", "getdelim"}
# library calls that only read what their pointer arguments point to
READS = set("""printf fprintf dprintf vprintf vfprintf puts fputs putchar putc fputc write send
sendto strlen strnlen strcmp strncmp memcmp strcasecmp strncasecmp strchr strrchr strstr memchr
strspn strcspn strpbrk atoi atol atoll strtol strtoul strtoll strtoull strtod strtof fopen fdopen
open openat creat fclose close free perror system exit abort fwrite fflush fseek ftell rewind
setvbuf setbuf signal sigaction alarm sleep usleep srand rand random ptrace getpid getppid
malloc calloc realloc strdup strndup mmap munmap mprotect stack_chk_fail assert_fail
syslog err errx warn warnx unlink remove access stat fstat lstat chdir puts_unlocked""".split())


class Site:
    """A place in the function that reads or writes values."""
    __slots__ = ("id", "expr", "stmt", "role", "ctx", "defs", "wdefs", "uses", "vrhs",
                 "mr", "mw", "odef", "ouse", "calls", "born", "mayw", "may")

    def __init__(self, sid, expr, stmt, role, ctx):
        self.id, self.expr, self.stmt, self.role, self.ctx = sid, expr, stmt, role, ctx
        self.defs = set()       # variables written as a whole (kill earlier writes)
        self.wdefs = set()      # variables written in part (a field, an element)
        self.uses = set()       # variables read
        self.vrhs = {}          # variable -> what was assigned (for pointer tracking)
        self.mr, self.mw = [], []   # addresses read / written through
        self.odef, self.ouse = set(), set()   # memory objects written / read
        self.calls = []
        self.born = set()       # objects created here whose content does not come from the reads
        self.mayw = set()       # objects an unknown call here may write
        self.may = False        # an unknown call may change memory here

    def gen(self):
        return self.defs | self.wdefs | self.odef

    def reads(self):
        return self.uses | self.ouse


class Flow:
    """The result: the sites to show, in program order, and how they depend on each other.

    sites    kept Site objects
    edges    (writer site id, reader site id) pairs among the kept sites
    role     site id -> "self" (writes or reads the variable), "dst" (where its value goes)
             or "src" (where it comes from); a site that is both, through a loop, gets the
             nearer of the two (a tie is "dst")
    may      some kept site calls an unknown function that may change memory
    cut      the slice was longer than the limit and was cut
    keys     what was followed: ("v", n) a variable, ("stk", n) a variable in memory,
             ("g", ea) a global, other tuples a memory object a pointer points at
    """

    def __init__(self, sites, edges, role, may, cut, keys=frozenset()):
        self.sites, self.edges, self.role, self.may, self.cut = sites, edges, role, may, cut
        self.keys = frozenset(keys)


def _lvalue_kinds():
    return ("var", "obj", "ptr", "idx", "mem")


class _Graph:
    def __init__(self, body):
        self.sites, self.succ = [], []
        self.labels, self.gotos, self.loops = {}, [], []
        self.memvars = set()
        self.ptrvars = set()        # variables that hold addresses: pointer typed, cast to a
                                    # pointer, or handed to a library call as its destination
        self._find_memvars(body)
        entry = self._node(None, None, "join", ())
        self._walk(body, [entry], ())
        for preds, tgt in self.gotos:
            if tgt in self.labels:
                self._link(preds, self.labels[tgt])
        self.pred = [set() for _ in self.sites]
        for a, bs in enumerate(self.succ):
            for b in bs:
                self.pred[b].add(a)
        self.live = _closure([entry], self.succ)    # code after a goto/return/break is dead

    # ---- tree -> sites and control flow ----
    def _find_memvars(self, t):
        """Arrays and variables whose address is taken live in memory, not in a register."""
        stack = [t]
        while stack:
            n = stack.pop()
            if n is None:
                continue
            if n.kind == "var" and n.mem:
                self.memvars.add(n.var)
            if n.kind == "var" and n.ptr:
                self.ptrvars.add(n.var)
            if n.kind == "ref" and n.x is not None and n.x.kind == "var":
                self.memvars.add(n.x.var)
            if n.kind == "cast" and n.ptr and n.x is not None and n.x.kind == "var":
                self.ptrvars.add(n.x.var)
            if n.kind == "call":
                for i in _writes(n):
                    a = _strip(n.args[i]) if i < len(n.args) else None
                    if a is not None and a.kind == "var":
                        self.ptrvars.add(a.var)
            stack.extend((n.x, n.y, n.z, n.init, n.step))
            stack.extend(n.args)
            stack.extend(n.body)

    def _node(self, expr, stmt, role, ctx):
        s = Site(len(self.sites), expr, stmt, role, ctx)
        self.sites.append(s)
        self.succ.append(set())
        if expr is not None:
            self._scan(s, expr)
        return s.id

    def _link(self, preds, n):
        for p in preds:
            self.succ[p].add(n)

    def _walk(self, st, preds, ctx):
        if st is None:
            return preds
        if st.label is not None:
            j = self._node(None, st, "join", ctx)
            self._link(preds, j)
            self.labels[st.label] = j
            preds = [j]
        k, inner = st.kind, ctx + (st,)
        if k == "block":
            for c in st.body:
                preds = self._walk(c, preds, ctx)
            return preds
        if k == "expr":
            n = self._node(st.x, st, "stmt", ctx)
            self._link(preds, n)
            return [n]
        if k == "return":
            n = self._node(st.x, st, "return", ctx)
            self._link(preds, n)
            return []
        if k == "if":
            c = self._node(st.x, st, "cond", ctx)
            self._link(preds, c)
            out = self._walk(st.body[0] if st.body else None, [c], inner)
            return out + (self._walk(st.body[1], [c], inner) if len(st.body) > 1 else [c])
        if k == "while":
            h = self._node(st.x, st, "cond", ctx)
            self._link(preds, h)
            brk = []
            self.loops.append((brk, h))
            out = self._walk(st.body[0] if st.body else None, [h], inner)
            self.loops.pop()
            self._link(out, h)
            return [h] + brk
        if k == "do":
            top = self._node(None, st, "join", ctx)
            cont = self._node(None, st, "join", inner)
            self._link(preds, top)
            brk = []
            self.loops.append((brk, cont))
            out = self._walk(st.body[0] if st.body else None, [top], inner)
            self.loops.pop()
            self._link(out, cont)
            c = self._node(st.x, st, "cond", ctx)
            self._link([cont], c)
            self._link([c], top)
            return [c] + brk
        if k == "for":
            if st.init is not None:
                i = self._node(st.init, st, "init", ctx)
                self._link(preds, i)
                preds = [i]
            h = self._node(st.x, st, "cond", ctx)
            self._link(preds, h)
            cont = self._node(None, st, "join", inner)
            brk = []
            self.loops.append((brk, cont))
            out = self._walk(st.body[0] if st.body else None, [h], inner)
            self.loops.pop()
            self._link(out, cont)
            if st.step is not None:
                s = self._node(st.step, st, "step", inner)
                self._link([cont], s)
                self._link([s], h)
            else:
                self._link([cont], h)
            return [h] + brk
        if k == "switch":
            sw = self._node(st.x, st, "switch", ctx)
            self._link(preds, sw)
            brk, prev = [], []
            self.loops.append((brk, None))
            for case in st.body:
                prev = self._walk(case, [sw] + prev, inner)
            self.loops.pop()
            return prev + brk + [sw]
        if k == "break":
            if self.loops:
                self.loops[-1][0].extend(preds)
            return []
        if k == "continue":
            for _, tgt in reversed(self.loops):
                if tgt is not None:
                    self._link(preds, tgt)
                    break
            return []
        if k == "goto":
            self.gotos.append((preds, st.target))
            return []
        n = self._node(None, st, "join", ctx)
        self._link(preds, n)
        return [n]

    # ---- what one site reads and writes ----
    def _root(self, e):
        """Where an lvalue lives: ("var", n), ("obj", object key) or ("via", address expr)."""
        k = e.kind
        if k == "cast":
            return self._root(e.x)
        if k == "var":
            return ("obj", ("stk", e.var)) if e.var in self.memvars else ("var", e.var)
        if k == "obj":
            return ("obj", ("g", e.obj_ea))
        if k == "ptr":
            return ("via", e.x)
        if k == "mem":
            return ("via", e.x) if e.op == "->" else self._root(e.x)
        if k == "idx":
            return ("via", e.x) if e.x.ptr or not e.x.mem else self._root(e.x)
        return ("via", e)

    def _path(self, s, e):
        """Values read to compute an lvalue's address: indexes, pointers loaded on the way."""
        k = e.kind
        if k == "cast":
            self._path(s, e.x)
        elif k == "ptr":
            self._addr(s, e.x)
        elif k == "mem":
            (self._addr if e.op == "->" else self._path)(s, e.x)
        elif k == "idx":
            (self._addr if (e.x.ptr or not e.x.mem) else self._path)(s, e.x)
            self._rd(s, e.y)

    def _rd_lv(self, s, e):
        """Read the value stored in an lvalue."""
        self._path(s, e)
        r = self._root(e)
        if r[0] == "var":
            s.uses.add(("v", r[1]))
        elif r[0] == "obj":
            s.ouse.add(r[1])
        else:
            s.mr.append(r[1])

    def _wr(self, s, e, rhs):
        k = e.kind
        if k == "cast":
            return self._wr(s, e.x, rhs)
        self._path(s, e)
        r = self._root(e)
        if r[0] == "var":
            if k == "var":
                s.defs.add(("v", r[1]))
                s.vrhs[r[1]] = rhs
            else:
                s.wdefs.add(("v", r[1]))
        elif r[0] == "obj":
            s.odef.add(r[1])
        else:
            s.mw.append(r[1])

    def _addr(self, s, a):
        """An address is computed (nothing is loaded from the final location)."""
        if a is None:
            return
        k = a.kind
        if k == "var":
            if a.var not in self.memvars and not a.ptr and not a.mem:
                s.uses.add(("v", a.var))          # an index or an offset
        elif k in ("cast",):
            self._addr(s, a.x)
        elif k == "bin":
            self._addr(s, a.x)
            self._addr(s, a.y)
        elif k == "ref":
            self._path(s, a.x)
        elif k in ("idx", "mem", "ptr") and a.mem:
            self._path(s, a)                      # an array inside memory: its address
        elif k in ("idx", "mem", "ptr"):
            self._rd_lv(s, a)                     # a pointer loaded from memory
        elif k != "obj":
            self._rd(s, a)

    def _rd(self, s, e):
        """Read the value of an expression."""
        if e is None:
            return
        k = e.kind
        if k in _lvalue_kinds():
            if e.mem:
                self._addr(s, e)                  # an array stands for its address
            else:
                self._rd_lv(s, e)
        elif k == "asg":
            self._rd(s, e.y)
            if e.op:
                self._rd_lv(s, e.x)
            self._wr(s, e.x, e.y if not e.op else ("op", e))
        elif k in ("inc", "dec"):
            self._rd_lv(s, e.x)
            self._wr(s, e.x, ("op", e))
        elif k == "ref":
            self._path(s, e.x)
        elif k == "call":
            for a in e.args:
                if self._is_addr(a):
                    self._addr(s, a)
                else:
                    self._rd(s, a)
            s.calls.append(e)
            s.odef.add(("ret", e.index))          # what a returned pointer points at
            s.born.add(("ret", e.index))
        elif k in ("num", "str", "helper", "fnum"):
            pass
        else:
            for c in (e.x, e.y, e.z):
                self._rd(s, c)
            for c in e.args:
                self._rd(s, c)

    def _scan(self, s, e):
        self._rd(s, e)

    def _is_addr(self, a):
        if a.ptr or a.mem or a.kind in ("ref", "str"):
            return True
        b = _strip(a)
        return b.kind == "var" and b.var in self.ptrvars


def _strip(a):
    while a is not None and a.kind == "cast":
        a = a.x
    return a


def _call_name(e):
    return canon(e.x.name) if e.x is not None and e.x.name else ""


def _writes(e):
    """Argument positions a known call writes through."""
    name = _call_name(e)
    if name in WRITES:
        return WRITES[name]
    if name in SCANF:
        return set(range(SCANF[name], len(e.args)))
    if e.x is not None and e.x.kind == "helper":
        low = name.lower()
        return {0} if ("store" in low or "stos" in low) else set()
    return set()


class _Analysis:
    def __init__(self, body):
        self.g = _Graph(body)
        self.sites = self.g.sites
        self._reaching(var_only=True)
        self._pts_memo = {}
        for s in self.sites:
            self._resolve(s)
        self._reaching(var_only=False)

    def _reaching(self, var_only):
        """Reaching definitions as bit sets: one bit per (site, key) write. Afterwards
        reach(site, key) lists the writer sites whose value can arrive at the site."""
        sites, pred, succ, live = self.sites, self.g.pred, self.g.succ, self.g.live
        bits = {}                       # key -> [(bit, writer site)]
        nbit = 0
        for s in sites:
            for k in (s.defs | s.wdefs if var_only else s.gen()):
                bits.setdefault(k, []).append((nbit, s.id))
                nbit += 1
        mask = {k: sum(1 << b for b, _ in v) for k, v in bits.items()}
        gen, kill = [0] * len(sites), [0] * len(sites)
        for k, v in bits.items():
            for b, sid in v:
                gen[sid] |= 1 << b
                if k in sites[sid].defs:
                    kill[sid] |= mask[k]
        IN, OUT = [0] * len(sites), [0] * len(sites)
        work = collections.deque(sorted(live))
        inq = set(work)
        while work:
            n = work.popleft()
            inq.discard(n)
            x = 0
            for p in pred[n]:
                x |= OUT[p]                 # dead predecessors stay empty
            IN[n] = x
            out = gen[n] | (x & ~kill[n])
            if out != OUT[n]:
                OUT[n] = out
                for m in succ[n]:
                    if m not in inq and m in live:
                        work.append(m)
                        inq.add(m)
        self._in, self._bits = IN, bits

    def reach(self, sid, key):
        """Writer sites of key whose value can arrive at site sid."""
        x = self._in[sid]
        return [w for b, w in self._bits.get(key, ()) if x >> b & 1]

    # ---- pointers ----
    def _pts_var(self, n, s):
        out = set()
        for d in self.reach(s.id, ("v", n)):
            if ("v", n) in self.sites[d].defs:
                out |= self._pts_def(d, n)
        return out or {("arg", n)}

    def _pts_def(self, d, n):
        key = (d, n)
        if key in self._pts_memo:
            return self._pts_memo[key]
        self._pts_memo[key] = set()               # a cycle (p = p + 1 in a loop) adds nothing
        rhs, s = self.sites[d].vrhs.get(n), self.sites[d]
        if isinstance(rhs, tuple):                # p += k, ++p: same objects as before
            r = self._pts_var(n, s)
        elif rhs is None:
            r = {("unk",)}
        else:
            r = self._pts(rhs, s)
        self._pts_memo[key] = r
        return r

    def _pts(self, a, s):
        """Memory objects that address expression a points into, at site s."""
        k = a.kind
        if k == "var":
            if a.var in self.g.memvars:
                return {("stk", a.var)} if a.mem else {("via", ("stk", a.var))}
            return self._pts_var(a.var, s)
        if k == "obj":
            return {("g", a.obj_ea)} if (a.mem or not a.ptr) else {("via", ("g", a.obj_ea))}
        if k == "cast":
            return self._pts(a.x, s)
        if k == "ref":
            return self._objs_of(a.x, s)
        if k == "bin":
            ops = [c for c in (a.x, a.y) if c is not None and c.kind not in ("num", "fnum")]
            out = set()
            for c in [c for c in ops if c.ptr or c.mem or c.kind == "ref"] or ops:
                out |= self._pts(c, s)
            return out or {("unk",)}
        if k in ("idx", "mem", "ptr"):
            if a.mem:                             # address of an array inside memory
                return self._objs_of(a, s)
            return {("via", o) for o in self._objs_of(a, s)}   # a pointer loaded from memory
        if k == "call":
            return {("ret", a.index)}
        if k == "str":
            return {("str", a.index)}
        if k == "num":
            return {("abs", a.value)}
        if k == "asg":
            return self._pts(a.y, s)
        if k == "tern":
            return self._pts(a.y, s) | self._pts(a.z, s)
        if k == "comma":
            return self._pts(a.y, s)
        return {("unk",)}

    def _objs_of(self, lv, s):
        """Objects an lvalue lives in."""
        r = self.g._root(lv)
        if r[0] == "var":
            return {("reg", r[1])}
        if r[0] == "obj":
            return {r[1]}
        return self._pts(r[1], s)

    def _resolve(self, s):
        for a in s.mr:
            s.ouse |= self._pts(a, s)
        for a in s.mw:
            s.odef |= self._pts(a, s)
        for e in s.calls:
            name = _call_name(e)
            known = (name in WRITES or name in SCANF or name in READS
                     or (e.x is not None and e.x.kind == "helper"))
            writes = _writes(e) if known else set(range(len(e.args)))
            if name in ("strdup", "strndup", "realloc"):
                s.born.discard(("ret", e.index))  # the new block is filled from the argument
            for i, a in enumerate(e.args):
                if not (self.g._is_addr(a) or (known and i in writes)):
                    continue
                objs = self._pts(a, s)
                if not (known and i in writes and name not in _READ_TOO):
                    s.ouse |= objs                # fread's buffer is only written
                if i in writes:
                    s.odef |= objs
                    if not known:
                        s.mayw |= objs
                        s.may = True


def analyze(body):
    """The per-function part of the work, reusable for every variable of the function."""
    return _Analysis(body)


def var_flow(body, var=None, obj_ea=None, limit=200, an=None, may=False):
    """Flow of local variable number `var` (or of the global at obj_ea) in a function body.
    `an` is analyze(body), when the caller keeps it. may: also follow where an unknown call
    may have written the value (encrypt(buf, out): on to whatever reads out)."""
    an = an or _Analysis(body)
    sites = an.sites
    pointer = var is not None and var in an.g.ptrvars and var not in an.g.memvars
    if var is not None:
        keys = {("stk", var) if var in an.g.memvars else ("v", var)}
        if pointer:                         # follow what the pointer points at
            for s in sites:
                if ("v", var) in s.defs:
                    keys |= an._pts_def(s.id, var)
                elif _mentions(s, var):
                    keys |= an._pts_var(var, s)
            keys = {k for k in keys if k[0] not in ("unk", "abs")}
    else:
        keys = {("g", obj_ea)}
    addr = {("v", n) for n in an.g.ptrvars}    # addresses are followed through points-to
    writers = [s.id for s in sites if keys & s.gen()]
    readers = [s.id for s in sites if keys & s.reads()
               or (pointer and s.id not in writers and _mentions(s, var))]
    # reader -> {writer: keys whose values it reads from that writer}, and the reverse
    deps = [dict() for _ in sites]
    users = [dict() for _ in sites]
    for s in sites:
        for k in s.reads() - addr:
            for d in an.reach(s.id, k):
                if d != s.id:
                    deps[s.id].setdefault(d, set()).add(k)
                    users[d].setdefault(s.id, set()).add(k)
    back = _back(writers, deps, sites, keys)
    fwd = _forward(writers + readers, users, sites, keys, set(readers), may)
    kept = set(back) | set(fwd)
    cut = False
    if len(kept) > limit:
        near = _nearest(set(writers + readers), deps, users, limit)
        kept, cut = near, True
    role = {}
    for i in kept:
        if i in writers or i in readers:
            role[i] = "self"
        elif i in fwd and (i not in back or fwd[i] <= back[i]):
            role[i] = "dst"
        else:
            role[i] = "src"
    edges = sorted((d, r) for r in kept for d in deps[r] if d in kept and d != r)
    out = [sites[i] for i in sorted(kept)]
    return Flow(out, edges, role, any(s.may for s in out), cut, keys)


def _back(seeds, deps, sites, target):
    """Where the values come from. A site reached only for an object it creates (malloc,
    fopen), or only for memory an unknown call may write, is shown but not followed
    further: its other inputs do not make up the content."""
    def opaque(d, keys):
        return keys <= sites[d].born | sites[d].mayw
    dist = {n: 0 for n in seeds}
    heap = [(0, n) for n in seeds if not opaque(n, target & sites[n].gen())]
    done = set()
    while heap:
        c, n = heapq.heappop(heap)
        if n in done:
            continue
        done.add(n)
        for d, keys in deps[n].items():
            if c + _cost(keys) < dist.get(d, 1e9):
                dist[d] = c + _cost(keys)
                if not opaque(d, keys):
                    heapq.heappush(heap, (dist[d], d))
    return dist


# memory of the function's own (a global, a stack buffer, a block it allocated): what an
# unknown call may write there is followed with may=True; memory reached through an argument
# (argv's strings) is not
_OWN = ("g", "stk", "ret")


def _forward(seeds, users, sites, target=None, readers=None, may=False):
    """Where the values go. A write that an unknown call only may do is not followed (with
    may: it is, into the function's own memory). From a
    site that writes the variable without reading it, only the variable is followed: what
    else it makes (fread's count) does not come from the variable."""
    dist = {n: 0 for n in seeds}
    heap = [(0, n) for n in seeds]
    only = {n for n in seeds if target is not None and readers is not None and n not in readers}
    while heap:
        c, n = heapq.heappop(heap)
        if c > dist[n]:
            continue
        for r, keys in users[n].items():
            if n in only and c == 0 and not keys & target:
                continue
            if keys <= sites[n].mayw and not (may and any(k[0] in _OWN for k in keys)):
                continue
            if c + _cost(keys) < dist.get(r, 1e9):
                dist[r] = c + _cost(keys)
                heapq.heappush(heap, (dist[r], r))
    return dist


def _cost(keys):
    """A step through a variable is exact; one through memory is per object, so it counts
    for more when a site is reached both ways."""
    return 1 if any(k[0] == "v" for k in keys) else 1.5


def _mentions(s, var):
    """The site's expression names the variable (a pointer used as an address counts)."""
    stack = [s.expr]
    while stack:
        n = stack.pop()
        if n is None:
            continue
        if n.kind == "var" and n.var == var:
            return True
        stack.extend((n.x, n.y, n.z, n.init, n.step))
        stack.extend(n.args)
    return False


def _closure(seeds, nxt):
    seen, stack = set(seeds), list(seeds)
    while stack:
        n = stack.pop()
        for m in nxt[n]:
            if m not in seen:
                seen.add(m)
                stack.append(m)
    return seen


def _nearest(seeds, deps, users, limit):
    """The `limit` sites closest to the seeds, either direction."""
    seen, frontier = set(seeds), list(seeds)
    while frontier and len(seen) < limit:
        nxt = []
        for n in frontier:
            for m in list(deps[n]) + list(users[n]):
                if m not in seen and len(seen) < limit:
                    seen.add(m)
                    nxt.append(m)
        frontier = nxt
    return seen


def flow_graph(flow):
    """What to draw for a Flow: (site ids, edges). Only edges that go forward in program
    order are kept (a loop feeding its own start again would bend back across the picture),
    and an edge is dropped when a longer path already connects the same two sites, so the
    drawing settles into clear layers: sources above, the variable, destinations below."""
    ids = [s.id for s in flow.sites if s.role != "join"]
    keep = set(ids)
    succ = {n: set() for n in ids}
    for a, b in flow.edges:
        if a in keep and b in keep and a < b:
            succ[a].add(b)
    edges = []
    for a in ids:
        for b in sorted(succ[a]):
            stack = [c for c in succ[a] if c != b and c < b]
            seen = set(stack)
            longer = False
            while stack:
                c = stack.pop()
                if c == b:
                    longer = True
                    break
                for d in succ[c]:
                    if d not in seen and d <= b:
                        seen.add(d)
                        stack.append(d)
            if not longer:
                edges.append((a, b))
    return ids, edges

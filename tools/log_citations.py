#!/usr/bin/env python3
"""CIRISEdge#875 — issue citations in operator-visible log lines.

Operator-visible = `tracing::warn!` / `tracing::error!` (and bare `warn!` / `error!`) and
`drop_inbound(...)`, which logs at WARN. Inside those string literals an issue citation
must say whether it is history (the issue is closed; the line explains why a gate exists)
or tracked (the issue is open work): `history: CIRISEdge#N` / `tracked: CIRISEdge#N`.

  python3 -I tools/log_citations.py list            # every cited (repo, number)
  python3 -I tools/log_citations.py rewrite STATES  # STATES = TSV repo\\tnum\\tOPEN|CLOSED
  python3 -I tools/log_citations.py check           # exit 1 on a bare citation
The `check` mode is what `tests/log_citations.rs` runs in CI (state-free); the state of
each issue is applied by `rewrite`, from a states file produced with `gh`.
"""
import re, sys, glob, collections

MACRO = re.compile(r'(?<![A-Za-z_])(?:tracing::)?(?:warn|error)!\s*\(|(?<![A-Za-z_])drop_inbound\s*\(')
STR = re.compile(r'"(?:[^"\\]|\\.)*"', re.S)
# `CIRISEdge#N`, `CIRISPersist#N`, … or a repo-less `#N` (read as CIRISEdge#N).
CITE = re.compile(r'(?P<pre>(?:history|tracked):\s*)?(?:(?P<repo>CIRIS[A-Za-z]+)|(?<![A-Za-z0-9_]))#(?P<num>\d{2,5})\b')
def repo_of(m):
    return m.group('repo') or 'CIRISEdge'


def bodies(src):
    for m in MACRO.finditer(src):
        i = m.end() - 1
        depth, j = 0, i
        while j < len(src):
            c = src[j]
            if c == '"':
                k = STR.match(src, j)
                j = k.end() if k else j + 1
                continue
            if c == '(':
                depth += 1
            elif c == ')':
                depth -= 1
                if depth == 0:
                    break
            j += 1
        yield i, j

def files():
    return [f for f in glob.glob('src/**/*.rs', recursive=True)]

def walk(fn):
    for f in files():
        src = open(f).read()
        out, last, changed = [], 0, False
        for i, j in bodies(src):
            if i < last:
                continue  # nested inside a body already rewritten
            body = src[i:j]
            new = STR.sub(lambda s: fn(f, s.group(0)), body)
            if new != body:
                changed = True
            out.append(src[last:i]); out.append(new); last = j
        out.append(src[last:])
        yield f, ''.join(out), changed

def main():
    mode = sys.argv[1]
    if mode == 'list':
        seen = collections.Counter()
        for f, _, _ in walk(lambda f, lit: (seen.update((repo_of(m), m.group('num')) for m in CITE.finditer(lit)), lit)[1]):
            pass
        for (r, n), c in sorted(seen.items()):
            print(f"{r}\t{n}\t{c}")
    elif mode == 'rewrite':
        states = {}
        for line in open(sys.argv[2]):
            r, n, st = line.rstrip('\n').split('\t')
            states[(r, n)] = st
        def fix(f, lit):
            def one(m):
                if m.group('pre'):
                    return m.group(0)
                st = states.get((repo_of(m), m.group('num')))
                tag = 'history' if st == 'CLOSED' else 'tracked'
                return f"{tag}: {repo_of(m)}#{m.group('num')}"
            return CITE.sub(one, lit)
        n = 0
        for f, new, changed in walk(fix):
            if changed:
                open(f, 'w').write(new); n += 1
        print(f"rewrote {n} files")
    elif mode == 'check':
        bad = []
        def chk(f, lit):
            for m in CITE.finditer(lit):
                if not m.group('pre'):
                    bad.append(f"{f}: bare {repo_of(m)}#{m.group('num')}")
            return lit
        for _ in walk(chk):
            pass
        for b in bad:
            print(b)
        sys.exit(1 if bad else 0)

if __name__ == '__main__':
    main()

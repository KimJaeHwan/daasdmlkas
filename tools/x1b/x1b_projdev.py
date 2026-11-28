"""dev: project two snapshots and show residual differences by pattern"""
import gzip, json, re, sys
from collections import Counter
from pathlib import Path
root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / "src"), str(root / "tools" / "graph_fidelity")]
from paired_projection import project_document
def walk(a, b, path, out):
    if type(a) is not type(b): out.append((path, a, b)); return
    if isinstance(a, dict):
        for k in set(a)|set(b):
            if k not in a or k not in b: out.append((f"{path}.{k}", a.get(k,"<absent>"), b.get(k,"<absent>")))
            else: walk(a[k], b[k], f"{path}.{k}", out)
    elif isinstance(a, list):
        for i,(x,y) in enumerate(zip(a,b)): walk(x,y,f"{path}[{i}]",out)
        if len(a)!=len(b): out.append((f"{path}.length",len(a),len(b)))
    elif a != b: out.append((path,a,b))
A = project_document(json.load(gzip.open(sys.argv[1], "rt"))); B = project_document(json.load(gzip.open(sys.argv[2], "rt")))
bad = [n for n in A["digests"] if A["digests"][n] != B["digests"].get(n)]
print("sections differing", len(bad), "of", len(A["digests"]))
out = []
for n in bad: walk(A["sections"][n], B["sections"][n], n, out)
pat = Counter(); ex = {}
for p, x, y in out:
    k = re.sub(r"\[\d+\]", "[]", re.sub(r"^function:[^.]*", "F", p)); pat[k] += 1; ex.setdefault(k, (str(x)[:110], str(y)[:110]))
for k, n in pat.most_common(25): print(n, k, "|", ex[k][0], "|", ex[k][1])

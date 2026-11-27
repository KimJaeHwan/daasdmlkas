"""Print the first FORM_MISMATCH contexts of ImportSites.transfer on one Bundle (debug probe, no source edits)."""
import sys
import traceback
from pathlib import Path

WT = Path(sys.argv[1])
sys.path[:0] = [str(WT / "src"), str(WT / "tools/decode_check")]
import code_facts as g  # noqa: E402
import decode_check as dc  # noqa: E402

real = g.ImportSites.transfer
shown = [0]


def transfer(self, i, n):
    try:
        return real(self, i, n)
    except g.Unread as error:
        if error.reason == "FORM_MISMATCH" and shown[0] < 6:
            shown[0] += 1
            r, p = self.b.rows[i], self.b.proofs[i]
            line = traceback.extract_tb(error.__traceback__)[-1].lineno
            print("FORM_MISMATCH line", line, r["offset"], "len", r["length"], "form", p.form, "sig", p.signature,
                  "op", self.raw[i]["ops"][n]["opcode"], "kind", r["transfer"]["kind"])
        raise


g.ImportSites.transfer = transfer
out = Path(sys.argv[3])
dc.run(Path(sys.argv[2]), WT / "ghidra" / "GhidraV2CallNaming.java", True, False, out / "fp.evidence5.json",
       True, True, out / "fp.facts.json")

"""run_dfbench.py with call-clobber debt disabled (P0-0 only), for comparison."""
import os
import runpy
import sys

import tdo_v2.normalize as normalize

os.environ["TDO_V2_CHI_RECORDS"] = "legacy"   # (the producer this patch disables: docs 25.83 D5')
normalize.derive_call_clobber_reads = lambda *args, **kwargs: ()
sys.argv = [sys.argv[0].replace("run_no_clobber", "run_dfbench"), *sys.argv[1:]]
runpy.run_path(sys.argv[0], run_name="__main__")

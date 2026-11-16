// TDO_v2 export -preScript (S1, design_scc_conditions r10 section 2): disable Ghidra's
// two non-returning-function analyzers before auto-analysis, so every CALL keeps the
// fallthrough the ISA defines. "Discovered" guesses non-returning callees from what
// follows their call sites (e.g. a deliberate int3 after a print call); "Known" is a
// name list -- both are conventions, not facts. Whether a callee returns is the
// engine's proof (summary_noreturn), never the graph's. GhidraV2BundleExport.java
// verifies the result per call before it writes call_fallthrough "isa".
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class GhidraV2DisableNoReturn extends GhidraScript {
    private static final String[] NAMES = {
        "Non-Returning Functions - Discovered", "Non-Returning Functions - Known"};

    @Override
    protected void run() throws Exception {
        Map<String, String> before = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : NAMES) {
            if (!before.containsKey(name)) {
                throw new IllegalStateException("Ghidra analysis option not found: " + name);
            }
            setAnalysisOption(currentProgram, name, "false");
        }
        Map<String, String> after = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : NAMES) {
            if (!"false".equals(after.get(name))) {
                throw new IllegalStateException("Ghidra analysis option not disabled: " + name);
            }
            println("[GhidraV2DisableNoReturn] " + name + ": " + before.get(name) + " -> " + after.get(name));
        }
    }
}

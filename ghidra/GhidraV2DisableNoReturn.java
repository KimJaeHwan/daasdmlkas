// TDO_v2 export -preScript (S1, design_scc_conditions r10 section 2, docs 25.100):
// disable Ghidra's analyzers that change a CALL's flow from guesses or names before
// auto-analysis, so every CALL keeps the fallthrough the ISA defines.
// "Non-Returning Functions - Discovered" guesses non-returning callees from what
// follows their call sites (e.g. a deliberate int3 after a print call); "- Known" is a
// name list; "Call-Fixup Installer" replaces calls to listed names (the compiler
// spec's call fixups, e.g. longjmp) with fixed p-code, which can end the call's flow
// (a CALL_RETURN override); "DWARF.Import Functions" brings function signatures from
// debug info, whose noreturn attribute (a source declaration) also sets CALL_RETURN on
// call sites -- DWARF data types are still imported. All four are conventions or
// declarations, not facts: whether a callee returns is the engine's proof
// (summary_noreturn), never the graph's.
// GhidraV2BundleExport.java verifies the result per call before it writes
// call_fallthrough "isa". An analyzer not registered for the program's format is
// skipped (it never runs).
import java.util.Map;

import ghidra.app.script.GhidraScript;

public class GhidraV2DisableNoReturn extends GhidraScript {
    private static final String[] NAMES = {
        "Non-Returning Functions - Discovered", "Non-Returning Functions - Known", "Call-Fixup Installer",
        "DWARF.Import Functions"};

    @Override
    protected void run() throws Exception {
        Map<String, String> before = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : NAMES) {
            if (before.containsKey(name)) {
                setAnalysisOption(currentProgram, name, "false");
            }
        }
        Map<String, String> after = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : NAMES) {
            if (!before.containsKey(name)) {
                println("[GhidraV2DisableNoReturn] " + name + ": not registered for this program");
                continue;
            }
            if (!"false".equals(after.get(name))) {
                throw new IllegalStateException("Ghidra analysis option not disabled: " + name);
            }
            println("[GhidraV2DisableNoReturn] " + name + ": " + before.get(name) + " -> " + after.get(name));
        }
    }
}

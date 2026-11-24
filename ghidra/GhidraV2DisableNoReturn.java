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

import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.Program;

public class GhidraV2DisableNoReturn extends HeadlessScript {
    // (G3b-7b r9) the headless-session key GhidraV2BundleExport.freshImportAttested reads
    // (tests/intra/test_gt_b7b_exception_handlers.py pins both files)
    private static final String FRESH_IMPORT_KEY = "tdo_v2.fresh_import";
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
        // (G3b-7b r9; proof-inputs review Astra r1 P1-1 / r2 P1-1, Fable r2 P2-1)
        // attest a fresh import: this headless run is in -import mode with
        // analysis on, and the program is not analyzed (loaders may create
        // functions -- ELF entry, PE delay-load proxies -- and disassemble --
        // the ELF .plt: Astra r9 P1). A -process run (a prepared project,
        // whose memory and listing are editable database state) never gets
        // the token, and with it no proof facts; a Ghidra database restored by
        // -import (GZF) of another file fails the exporter's SHA-256 check
        // against the configured original. A guard against mistakes (a wrong
        // mode, a prepared project, a direct exporter call), not against a
        // producer who builds the program state by hand -- that producer can
        // write any Bundle (the Bundle is the trust boundary).
        boolean analyzed = currentProgram.getOptions(Program.PROGRAM_INFO)
            .getBoolean(Program.ANALYZED_OPTION_NAME, false);
        if (isImporting() && isHeadlessAnalysisEnabled() && !analyzed) {
            storeHeadlessValue(FRESH_IMPORT_KEY, freshImportToken());
            println("[GhidraV2DisableNoReturn] fresh import attested");
        }
        else {
            storeHeadlessValue(FRESH_IMPORT_KEY, null);   // (no stale token: Fable r9 P3)
            println("[GhidraV2DisableNoReturn] not a fresh import: no token");
        }
    }

    private String freshImportToken() {
        return currentProgram.getDomainFile().getPathname() + "#" + System.identityHashCode(currentProgram);
    }
}

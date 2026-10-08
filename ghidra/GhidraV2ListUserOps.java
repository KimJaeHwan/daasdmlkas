// Prints the language's user-defined p-code op names by CALLOTHER index:
// "USEROP <language id> <major>.<minor> <index> <name>" (one per line).
// Used to build models/pcodeops/*.json (tools/bundle_export/userop_table.py).
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Language;

public class GhidraV2ListUserOps extends GhidraScript {
    @Override
    protected void run() throws Exception {
        Language language = currentProgram.getLanguage();
        String id = language.getLanguageID().getIdAsString();
        String version = language.getVersion() + "." + language.getMinorVersion();
        for (int index = 0; index < language.getNumberOfUserDefinedOpNames(); index++) {
            println("USEROP " + id + " " + version + " " + index + " " + language.getUserDefinedOpName(index));
        }
    }
}

// X-1b evidence: list the external entry point symbols (what the exporter's image-info exports reads)
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

public class DumpExports extends GhidraScript {
    @Override
    public void run() throws Exception {
        SymbolTable symbols = currentProgram.getSymbolTable();
        AddressIterator entries = symbols.getExternalEntryPointIterator();
        int count = 0;
        while (entries.hasNext()) {
            Address entry = entries.next();
            for (Symbol symbol : symbols.getSymbols(entry)) {
                println("EXPORT " + entry + " " + symbol.getName() + " " + symbol.getSource());
                count++;
            }
        }
        println("EXPORTS " + count);
    }
}

// Stack-switch evidence for a whole program (design section 24.1, decisions 6-7).
//
// Scans EVERY function of an analyzed program -- and the instructions outside
// every function -- for an operation that may set the stack pointer to
// something other than "the stack pointer + a number": the same MUST rule as
// tdo_v2.may_alias.stack_switches (stack coefficient 1 / 0 / unknown per
// register or temporary; a stack switch: fibers, coroutines -- such a program
// may run on a stack in static data, so the globals-disjoint-from-stack
// assumption does not hold for it). Writes one JSON evidence file: the
// program's executable SHA-256, how much was scanned, and every switch (or
// operation the scan could not follow: "UNCHECKED") found.
//
// (X-1, design_x1 r3 4.1) A thin wrapper: the scan is GhidraV2StackSwitchScanner,
// which the exporter also calls on its locked program. The conservative mode
// writes version-2 evidence (detector v5: the s3-off verdict, equal to v4, and
// the S3-aware s3-on verdict); a standalone file is "unbound" (no exported row
// map): its consumers read only its s3-off verdict. legacy-v3 writes version 1.
//
// Arguments: --output PATH --expected-sha256 HEX [--mode conservative|legacy-v3]
// Refuses a program that is not analyzed, or whose recorded executable
// SHA-256 differs from the expected one. Run with -process -noanalysis -readOnly.
//@category TDO

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

import com.google.gson.GsonBuilder;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Program;

public class GhidraV2StackSwitchScan extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = null;
        String expected = null;
        boolean conservative = true;
        for (int index = 0; index + 1 < args.length; index += 2) {
            switch (args[index]) {
                case "--output" -> output = Path.of(args[index + 1]).toAbsolutePath().normalize();
                case "--expected-sha256" -> expected = args[index + 1].toLowerCase(Locale.ROOT);
                case "--mode" -> conservative = switch (args[index + 1]) {
                    case "conservative" -> true;
                    case "legacy-v3" -> false;
                    default -> throw new IllegalArgumentException("unknown stack scan mode " + args[index + 1]);
                };
                default -> throw new IllegalArgumentException("unknown argument " + args[index]);
            }
        }
        if (output == null || expected == null || args.length % 2 != 0) {
            throw new IllegalArgumentException(
                "--output PATH --expected-sha256 HEX [--mode conservative|legacy-v3]");
        }
        if (!currentProgram.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
            throw new IllegalStateException("the program is not analyzed: analyze it in the Ghidra project first");
        }
        String claim = currentProgram.getExecutableSHA256();
        if (claim == null || !expected.equals(claim.trim().toLowerCase(Locale.ROOT))) {
            throw new IOException("the program's executable SHA-256 is not the expected one");
        }
        GhidraV2StackSwitchScanner scanner = new GhidraV2StackSwitchScanner(currentProgram, monitor, conservative);
        Map<String, Object> evidence = conservative ? scanner.evidence(expected, null)
            : scanner.legacyEvidence(expected);
        Files.writeString(output, new GsonBuilder().setPrettyPrinting().create().toJson(evidence) + "\n",
            StandardCharsets.UTF_8);
        println("stack-switch scan: " + evidence.get("functions_scanned") + " functions, " +
            evidence.get("instructions_scanned") + " instructions (" + evidence.get("instructions_outside_functions") +
            " outside functions) -> " + output);
    }
}

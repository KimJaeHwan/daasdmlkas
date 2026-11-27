// Configured V2 extraction exporter executed inside one locked Ghidra Program.

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashSet;
import java.util.TreeMap;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.app.plugin.exceptionhandlers.gcc.RegionDescriptor;
import ghidra.app.plugin.exceptionhandlers.gcc.sections.EhFrameSection;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteRecord;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDACallSiteTable;
import ghidra.app.plugin.exceptionhandlers.gcc.structures.gccexcepttable.LSDATable;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.address.AddressIterator;

public class GhidraV2BundleExport extends HeadlessScript {
    private static final int FORMAT_VERSION = 2;
    private static final String MANIFEST_SCHEMA_ID =
        "tdo-v2-configured-bundle-manifest-v2";
    private static final String SEAL_SCHEMA_ID =
        "tdo-v2-configured-bundle-seal-v2";
    private static final String PROFILE_AUTHORITY_MODE =
        "EXPLICIT_AND_PROGRAM_DEFAULT";
    private static final int CHUNK_BYTES = 1024 * 1024;
    private static final int MAX_SELECTED_FUNCTIONS = 4096;
    private static final BigInteger U64_LIMIT = BigInteger.ONE.shiftLeft(64);
    private static final Gson GSON = new GsonBuilder()
        .disableHtmlEscaping()
        .serializeNulls()
        .create();
    private List<ExceptionRegion> exceptionRegions = List.of();
    // (S1) every native call of every exported function keeps its ISA
    // fallthrough: a fresh analysis with Ghidra's two non-returning analyzers
    // disabled (GhidraV2DisableNoReturn.java as -preScript), verified per call
    // in callContinuations; never for a prepared project (-noanalysis)
    // (the same list as GhidraV2DisableNoReturn.NAMES -- tests/intra/test_call_fallthrough_contract.py pins it)
    private static final String[] FLOW_GUESS_OPTIONS = {
        "Non-Returning Functions - Discovered", "Non-Returning Functions - Known", "Call-Fixup Installer",
        "DWARF.Import Functions"};
    private boolean callFallthroughIsa;
    // (G3b-7b r9) the -preScript's fresh-import key (GhidraV2DisableNoReturn.FRESH_IMPORT_KEY)
    private static final String FRESH_IMPORT_KEY = "tdo_v2.fresh_import";
    // (G3b-7b r9e / r9f) the x86-64 long-mode decode: the only language where a
    // 66 prefix on a near transfer is read differently by Intel and AMD, and the
    // one the exception-handlers fact requires
    private static final String LONG_MODE = "x86:LE:64:default";
    // contract violations of every exported function, reported together
    // (X-1b, owner 2026-11-27) functions whose S1 contract does not hold: S1 withheld for them only
    private final List<String> s1Withheld = new ArrayList<>();
    private final AddressSet recoveredExceptionCode = new AddressSet();
    // (G3b-7b-1) the x64 PE exception directory: RUNTIME_FUNCTION begin RVA ->
    // {end RVA, 1 when its unwind info or a chained one names a handler};
    // null when the image is not a plain AMD64 PE32+ whose directory reads
    // completely (then no function gets the "no exception handler" fact)
    private TreeMap<Long, long[]> peUnwindEntries;
    private long peImageSize;

    private static final class Entry implements Comparable<Entry> {
        final BigInteger spaceId;
        final BigInteger byteOffset;

        Entry(BigInteger spaceId, BigInteger byteOffset) {
            this.spaceId = u64(spaceId, "entry space ID");
            this.byteOffset = u64(byteOffset, "entry byte offset");
        }

        @Override
        public int compareTo(Entry other) {
            int result = spaceId.compareTo(other.spaceId);
            return result != 0 ? result : byteOffset.compareTo(other.byteOffset);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Entry row && compareTo(row) == 0;
        }

        @Override
        public int hashCode() {
            return 31 * spaceId.hashCode() + byteOffset.hashCode();
        }
    }

    private static final class Options {
        Path outputRoot;
        String generation;
        Path original;
        BigInteger originalSize;
        String originalSha256;
        String bundleExporterSha256;
        String profileExporterSha256;
        String namingExporterSha256;
        String effectExporterSha256;
        String scannerSha256;   // (X-1) GhidraV2StackSwitchScanner.java
        Path receiptPath;
        String receiptNonce;
        final List<Entry> entries = new ArrayList<>();
        final List<String> functionNames = new ArrayList<>();
        // functions exported themselves but not followed into (a library's
        // functions with an internal model: the derivation cuts there)
        final List<String> stopNames = new ArrayList<>();
        // the program must already be analyzed (a prepared project, -noanalysis)
        boolean requireAnalyzed;
    }

    private static final class ExceptionCallSite {
        final AddressRange protectedRange;
        final Address landingPad;

        ExceptionCallSite(AddressRange protectedRange, Address landingPad) {
            this.protectedRange = protectedRange;
            this.landingPad = landingPad;
        }
    }

    private static final class ExceptionRegion {
        final AddressRange functionRange;
        final List<ExceptionCallSite> callSites;
        final boolean exactFunctionExtent;

        ExceptionRegion(
                AddressRange functionRange,
                List<ExceptionCallSite> callSites,
                boolean exactFunctionExtent) {
            this.functionRange = functionRange;
            this.callSites = List.copyOf(callSites);
            this.exactFunctionExtent = exactFunctionExtent;
        }
    }

    // (X-1, design_x1 r2 part 1) the producer profile every exported function
    // declares: raw per-row override state and recorded landing pads (and,
    // Bundle-wide, the sealed stack-switch evidence)
    private static final String PRODUCER_PROFILE = "x1-producer-v1";
    // (X-1, design_x1 r4 4.2) the exported row map the scanner's verifiable digest covers
    private final Map<Address, List<Address>> exportedRows = new LinkedHashMap<>();
    // (Astra X-1a r1 P1-7) each exported row's attested digest line, taken when it was collected
    private final Map<Address, byte[]> collectedLines = new HashMap<>();   // (X-1b: line digests)

    private static final class ObservedFunction {
        final AddressSet body;
        final Map<Address, Set<Address>> exceptionalTargets;
        // (X-1) every recorded landing pad per body row of a protected range,
        // before the call-p-code filter that ``exceptionalTargets`` applies
        final Map<Address, Set<Address>> recordedPads;

        ObservedFunction(AddressSet body, Map<Address, Set<Address>> exceptionalTargets,
                Map<Address, Set<Address>> recordedPads) {
            this.body = body;
            this.exceptionalTargets = exceptionalTargets;
            this.recordedPads = recordedPads;
        }
    }

    @Override
    protected void run() throws Exception {
        Options options = parseOptions(getScriptArgs());
        if (options.requireAnalyzed && !currentProgram.getOptions(Program.PROGRAM_INFO)
                .getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
            throw new IllegalStateException(
                "the program is not analyzed: analyze it in the Ghidra project first");
        }
        callFallthroughIsa = !options.requireAnalyzed;
        if (callFallthroughIsa && !freshImportAttested()) {
            throw new IllegalStateException("a fresh export imports the binary and analyzes it in this run " +
                "(GhidraV2DisableNoReturn.java as -preScript attests it; tools/bundle_export/export_bundle.py " +
                "does): export a prepared project with --require-analyzed");
        }
        String recorded = currentProgram.getExecutableSHA256();
        if (callFallthroughIsa && (recorded == null || !recorded.trim().toLowerCase().equals(options.originalSha256))) {
            // (Fable proof-inputs r3 P2-1) -import also loads containers holding a
            // Ghidra database (e.g. a packed program): a fresh import is the
            // configured original file itself, as Ghidra recorded it
            throw new IllegalStateException("a fresh import records the configured original's SHA-256 " +
                "(Ghidra: " + recorded + ")");
        }
        if (callFallthroughIsa && analysisTimeoutOccurred()) {
            // (Astra proof-inputs r2 P1-1) an unfinished analysis proves nothing: no proof facts
            printerr("[GhidraV2BundleExport] WARNING: analysis timed out: no call_fallthrough / exception_handlers facts");
            callFallthroughIsa = false;
        }
        if (callFallthroughIsa && !decodeModeMatchesFile(options)) {
            // (Astra r12) a decode mode other than the file's machine (e.g. an AMD64
            // image imported as x86:LE:64:compat32) gives other lengths: no proof facts
            printerr("[GhidraV2BundleExport] WARNING: decode mode " + currentProgram.getLanguageID() +
                " does not match the file's machine: no call_fallthrough / exception_handlers facts");
            callFallthroughIsa = false;
        }
        if (callFallthroughIsa && !flowGuessesOff()) {
            throw new IllegalStateException("a fresh export needs Ghidra's non-returning and call-fixup analyzers off: " +
                "run GhidraV2DisableNoReturn.java as -preScript (tools/bundle_export/export_bundle.py does)");
        }
        exceptionRegions = captureExceptionRegions();
        if (options.requireAnalyzed && !recoveredExceptionCode.isEmpty()) {
            throw new IllegalStateException("exception landing pads need disassembly and analysis the " +
                "prepared project lacks: analyze them in the project, or export by import");
        }
        analyzeRecoveredExceptionCode();
        peUnwindEntries = capturePeUnwindEntries();
        // Keep exact metadata-directed analysis in this transient read-only
        // program view, then freeze it for publication. Headless discards the
        // view after the export because the project itself remains read-only.
        end(true);
        if (!currentProgram.lock("tdo-v2 configured extraction")) {
            throw new IOException("Ghidra program view could not be frozen");
        }
        try {
            publish(options);
        }
        finally {
            currentProgram.unlock();
        }
    }

    private List<ExceptionRegion> captureExceptionRegions() throws Exception {
        List<ExceptionRegion> result = new ArrayList<>();
        for (RegionDescriptor descriptor :
                new EhFrameSection(monitor, currentProgram).analyze(0)) {
            monitor.checkCancelled();
            AddressRange functionRange = descriptor.getRange();
            if (functionRange == null) {
                throw new IOException("exception descriptor has no protected function range");
            }
            List<ExceptionCallSite> callSites = new ArrayList<>();
            LSDACallSiteTable table = descriptor.getCallSiteTable();
            if (table != null) {
                for (LSDACallSiteRecord record : table.getCallSiteRecords()) {
                    if (record.getLandingPadOffset() == 0) {
                        continue;
                    }
                    AddressRange protectedRange = record.getCallSite();
                    Address landingPad = record.getLandingPad();
                    if (protectedRange == null || landingPad == null ||
                            landingPad == Address.NO_ADDRESS) {
                        throw new IOException("exception call site is incomplete");
                    }
                    callSites.add(new ExceptionCallSite(protectedRange, landingPad));
                }
            }
            result.add(new ExceptionRegion(functionRange, callSites, false));
        }
        result.addAll(captureArmExceptionRegions());
        return List.copyOf(result);
    }

    private List<ExceptionRegion> captureArmExceptionRegions() throws Exception {
        MemoryBlock index = currentProgram.getMemory().getBlock(".ARM.exidx");
        MemoryBlock tables = currentProgram.getMemory().getBlock(".ARM.extab");
        if (index == null && tables == null) {
            return List.of();
        }
        if (index == null || index.getSize() % 8 != 0) {
            throw new IOException("ARM exception sections are incomplete");
        }
        long entryCount = index.getSize() / 8;
        if (entryCount < 1 || entryCount > Integer.MAX_VALUE) {
            throw new IOException("ARM exception index has an invalid entry count");
        }
        boolean bigEndian = currentProgram.getLanguage().isBigEndian();
        List<Address> functionStarts = new ArrayList<>((int) entryCount);
        List<Integer> unwindWords = new ArrayList<>((int) entryCount);
        for (int ordinal = 0; ordinal < (int) entryCount; ordinal++) {
            monitor.checkCancelled();
            Address row = index.getStart().add((long) ordinal * 8);
            functionStarts.add(decodePrel31(
                row, currentProgram.getMemory().getInt(row, bigEndian)));
            unwindWords.add(currentProgram.getMemory().getInt(row.add(4), bigEndian));
        }

        boolean hasExternalTableRecord = false;
        for (int unwindWord : unwindWords) {
            if (unwindWord != 1 && (unwindWord & 0x80000000) == 0) {
                hasExternalTableRecord = true;
                break;
            }
        }
        if (!hasExternalTableRecord) {
            return List.of();
        }
        if (tables == null || entryCount < 2) {
            throw new IOException("ARM external exception tables are incomplete");
        }

        List<ExceptionRegion> result = new ArrayList<>();
        for (int ordinal = 0; ordinal + 1 < functionStarts.size(); ordinal++) {
            monitor.checkCancelled();
            Address functionStart = functionStarts.get(ordinal);
            Address functionEnd = functionStarts.get(ordinal + 1);
            if (!functionStart.getAddressSpace().equals(functionEnd.getAddressSpace()) ||
                    functionStart.compareTo(functionEnd) >= 0) {
                throw new IOException("ARM exception index is not strictly ordered");
            }
            int unwindWord = unwindWords.get(ordinal);
            if (unwindWord == 1 || (unwindWord & 0x80000000) != 0) {
                continue;
            }
            Address unwindWordAddress = index.getStart().add((long) ordinal * 8 + 4);
            Address extabAddress = decodePrel31(unwindWordAddress, unwindWord);
            if (!tables.contains(extabAddress) || !tables.contains(extabAddress.add(4))) {
                throw new IOException("ARM exception index points outside .ARM.extab");
            }
            int personalityWord = currentProgram.getMemory().getInt(
                extabAddress, bigEndian);
            if ((personalityWord & 0x80000000) != 0) {
                continue;
            }
            int unwindHeader = currentProgram.getMemory().getInt(
                extabAddress.add(4), bigEndian);
            int additionalWords = (unwindHeader >>> 24) & 0xff;
            Address lsdaAddress = extabAddress.add(8L + (long) additionalWords * 4);
            if (!tables.contains(lsdaAddress)) {
                throw new IOException("ARM language-specific data lies outside .ARM.extab");
            }

            RegionDescriptor descriptor = new RegionDescriptor(tables);
            AddressRange functionRange = new AddressRangeImpl(
                functionStart, functionEnd.subtract(1));
            descriptor.setIPRange(functionRange);
            descriptor.setLSDAAddress(lsdaAddress);
            LSDATable table = new LSDATable(monitor, currentProgram);
            table.create(lsdaAddress, descriptor);
            descriptor.setLSDATable(table);

            List<ExceptionCallSite> callSites = new ArrayList<>();
            LSDACallSiteTable callSiteTable = descriptor.getCallSiteTable();
            if (callSiteTable != null) {
                for (LSDACallSiteRecord record : callSiteTable.getCallSiteRecords()) {
                    if (record.getLandingPadOffset() == 0) {
                        continue;
                    }
                    AddressRange protectedRange = record.getCallSite();
                    Address landingPad = record.getLandingPad();
                    if (protectedRange == null || landingPad == null ||
                            landingPad == Address.NO_ADDRESS) {
                        throw new IOException("ARM exception call site is incomplete");
                    }
                    disassembleExceptionLanding(
                        landingPad, protectedRange.getMinAddress(), functionRange);
                    callSites.add(new ExceptionCallSite(protectedRange, landingPad));
                }
            }
            result.add(new ExceptionRegion(functionRange, callSites, true));
        }
        int terminalUnwindWord = unwindWords.get(unwindWords.size() - 1);
        if (terminalUnwindWord != 1 && (terminalUnwindWord & 0x80000000) == 0) {
            throw new IOException("ARM external exception record has no function end");
        }
        return List.copyOf(result);
    }

    private void disassembleExceptionLanding(
            Address landingPad,
            Address contextSource,
            AddressRange functionRange) throws Exception {
        if (currentProgram.getListing().getInstructionAt(landingPad) != null) {
            return;
        }
        RegisterValue context = currentProgram.getProgramContext()
            .getDisassemblyContext(contextSource);
        if (context == null || !context.hasAnyValue()) {
            throw new IOException("exception landing pad has no exact processor context");
        }
        DisassembleCommand command = new DisassembleCommand(
            landingPad, new AddressSet(functionRange), true);
        command.setInitialContext(context);
        command.enableCodeAnalysis(false);
        if (!command.applyTo(currentProgram, monitor) ||
                currentProgram.getListing().getInstructionAt(landingPad) == null) {
            throw new IOException("exception landing pad could not be disassembled");
        }
        recoveredExceptionCode.add(functionRange);
    }

    private void analyzeRecoveredExceptionCode() throws Exception {
        if (recoveredExceptionCode.isEmpty()) {
            return;
        }
        AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
        manager.reAnalyzeAll(recoveredExceptionCode);
        manager.startAnalysis(monitor);
    }

    private static Address decodePrel31(Address place, int encoded) throws Exception {
        long displacement = (long) ((encoded << 1) >> 1);
        return place.add(displacement);
    }

    private Options parseOptions(String[] args) {
        Options values = new Options();
        for (int index = 0; index < args.length;) {
            String arg = args[index];
            if ("--entry".equals(arg)) {
                if (index + 2 >= args.length) {
                    throw new IllegalArgumentException("--entry requires decimal space ID and byte offset");
                }
                values.entries.add(new Entry(decimal(args[index + 1]), decimal(args[index + 2])));
                index += 3;
                continue;
            }
            if ("--require-analyzed".equals(arg)) {
                values.requireAnalyzed = true;
                index += 1;
                continue;
            }
            if ("--stop-at-name".equals(arg)) {
                if (index + 1 >= args.length || args[index + 1].isEmpty() ||
                        args[index + 1].indexOf('\0') >= 0) {
                    throw new IllegalArgumentException("--stop-at-name requires exact symbol text");
                }
                values.stopNames.add(args[index + 1]);
                index += 2;
                continue;
            }
            if ("--function-name".equals(arg)) {
                if (index + 1 >= args.length) {
                    throw new IllegalArgumentException("--function-name requires exact text");
                }
                String name = args[index + 1];
                if (name.isEmpty() || name.indexOf('\0') >= 0 ||
                        name.getBytes(StandardCharsets.UTF_8).length > 4096) {
                    throw new IllegalArgumentException("configured function name is invalid");
                }
                values.functionNames.add(name);
                index += 2;
                continue;
            }
            if (index + 1 >= args.length) {
                throw new IllegalArgumentException("incomplete configured exporter argument: " + arg);
            }
            String value = args[index + 1];
            switch (arg) {
                case "--output-root" -> {
                    requireUnset(values.outputRoot, arg);
                    values.outputRoot = Path.of(value).toAbsolutePath().normalize();
                }
                case "--generation" -> {
                    requireUnset(values.generation, arg);
                    values.generation = lowerHex(value, "generation");
                }
                case "--original-executable" -> {
                    requireUnset(values.original, arg);
                    values.original = Path.of(value).toAbsolutePath().normalize();
                }
                case "--original-size" -> {
                    requireUnset(values.originalSize, arg);
                    values.originalSize = decimal(value);
                }
                case "--original-sha256" -> {
                    requireUnset(values.originalSha256, arg);
                    values.originalSha256 = lowerHex(value, "original SHA-256");
                }
                case "--bundle-exporter-sha256" -> {
                    requireUnset(values.bundleExporterSha256, arg);
                    values.bundleExporterSha256 = lowerHex(
                        value, "bundle exporter source SHA-256");
                }
                case "--profile-exporter-sha256" -> {
                    requireUnset(values.profileExporterSha256, arg);
                    values.profileExporterSha256 = lowerHex(
                        value, "profile exporter source SHA-256");
                }
                case "--naming-exporter-sha256" -> {
                    requireUnset(values.namingExporterSha256, arg);
                    values.namingExporterSha256 = lowerHex(
                        value, "naming exporter source SHA-256");
                }
                case "--effect-exporter-sha256" -> {
                    requireUnset(values.effectExporterSha256, arg);
                    values.effectExporterSha256 = lowerHex(
                        value, "effect exporter source SHA-256");
                }
                case "--scanner-sha256" -> {
                    requireUnset(values.scannerSha256, arg);
                    values.scannerSha256 = lowerHex(value, "stack-switch scanner source SHA-256");
                }
                case "--receipt-path" -> {
                    requireUnset(values.receiptPath, arg);
                    values.receiptPath = Path.of(value).toAbsolutePath().normalize();
                }
                case "--receipt-nonce" -> {
                    requireUnset(values.receiptNonce, arg);
                    values.receiptNonce = lowerHex(value, "receipt nonce");
                }
                default -> throw new IllegalArgumentException("unknown configured exporter argument: " + arg);
            }
            index += 2;
        }
        if (values.outputRoot == null || values.generation == null || values.original == null ||
            values.originalSize == null || values.originalSha256 == null ||
            values.bundleExporterSha256 == null || values.profileExporterSha256 == null ||
            values.namingExporterSha256 == null || values.effectExporterSha256 == null ||
            values.scannerSha256 == null ||
            values.receiptPath == null || values.receiptNonce == null) {
            throw new IllegalArgumentException("configured exporter arguments are incomplete");
        }
        if (values.originalSize.signum() == 0) {
            throw new IllegalArgumentException("original executable must be nonempty");
        }
        if (values.entries.isEmpty() == values.functionNames.isEmpty()) {
            throw new IllegalArgumentException(
                "select exactly one of function entries or function names");
        }
        if (values.entries.size() > MAX_SELECTED_FUNCTIONS ||
                values.functionNames.size() > MAX_SELECTED_FUNCTIONS) {
            throw new IllegalArgumentException("configured function selection is empty or exceeds its bound");
        }
        if (new LinkedHashSet<>(values.entries).size() != values.entries.size()) {
            throw new IllegalArgumentException("function entries must be unique");
        }
        if (new LinkedHashSet<>(values.functionNames).size() != values.functionNames.size()) {
            throw new IllegalArgumentException("function names must be unique");
        }
        values.entries.sort(Comparator.naturalOrder());
        return values;
    }

    private static void requireUnset(Object value, String name) {
        if (value != null) {
            throw new IllegalArgumentException("duplicate configured exporter argument: " + name);
        }
    }

    private static BigInteger decimal(String value) {
        if (value.isEmpty() || !value.chars().allMatch(Character::isDigit)) {
            throw new IllegalArgumentException("configured integers must be unsigned decimal");
        }
        return u64(new BigInteger(value, 10), "configured integer");
    }

    private static BigInteger u64(BigInteger value, String label) {
        if (value.signum() < 0 || value.compareTo(U64_LIMIT) >= 0) {
            throw new IllegalArgumentException(label + " exceeds unsigned 64-bit");
        }
        return value;
    }

    private static BigInteger u64(long value, String label) {
        if (value < 0) {
            throw new IllegalArgumentException(label + " is negative");
        }
        return BigInteger.valueOf(value);
    }

    private static String lowerHex(String value, String label) {
        if (value.length() != 64 || !value.chars().allMatch(
            character -> character >= '0' && character <= '9' || character >= 'a' && character <= 'f')) {
            throw new IllegalArgumentException(label + " must be 64 lowercase hexadecimal characters");
        }
        return value;
    }

    private static BigInteger spaceId(AddressSpace space) {
        return BigInteger.valueOf(Integer.toUnsignedLong(space.getSpaceID()));
    }

    private static BigInteger byteOffset(Address address) {
        return u64(address.getOffsetAsBigInteger(), "address byte offset");
    }

    private static Map<String, Object> coordinate(Address address) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("space_id", spaceId(address.getAddressSpace()));
        result.put("byte_offset", byteOffset(address));
        return result;
    }

    private Map<String, Object> programCandidate() {
        Map<String, Object> translation = new LinkedHashMap<>();
        translation.put("language_id", currentProgram.getLanguageID().getIdAsString());
        translation.put("major_version", u64(currentProgram.getLanguage().getVersion(), "language version"));
        translation.put("minor_version", u64(currentProgram.getLanguage().getMinorVersion(), "language minor version"));

        List<Map<String, Object>> spaces = new ArrayList<>();
        for (AddressSpace space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("space_id", spaceId(space));
            row.put("address_size_bits", u64(space.getSize(), "address-space size"));
            row.put("addressable_unit_bytes", u64(space.getAddressableUnitSize(), "addressable unit"));
            row.put("is_constant_space", space.isConstantSpace());
            row.put("is_register_space", space.isRegisterSpace());
            row.put("is_unique_space", space.isUniqueSpace());
            row.put("is_memory_space", space.isMemorySpace());
            row.put("is_overlay_space", space.isOverlaySpace());
            row.put("is_external_space", space.isExternalSpace());
            row.put("is_loaded_memory_space", space.isLoadedMemorySpace());
            row.put("is_non_loaded_memory_space", space.isNonLoadedMemorySpace());
            row.put("has_signed_offset", space.hasSignedOffset());
            spaces.add(row);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address_space_classification_revision", 2);
        result.put("translation_namespace", translation);
        result.put("address_spaces", spaces);
        result.put("image_base", coordinate(currentProgram.getImageBase()));
        result.put("register_evidence", registerEvidence());
        return result;
    }

    /**
     * The language's register file as an ISA fact (revision 1, docs 25.86):
     * every non-context register whose storage is whole bytes in the register
     * space (no bit fields, no memory-mapped registers), overlapping aliases
     * kept, in (space, offset, size, name) order. Nothing from the compiler
     * spec.
     */
    private Map<String, Object> registerEvidence() {
        List<Register> kept = new ArrayList<>();
        for (Register register : currentProgram.getLanguage().getRegisters()) {
            if (register.isProcessorContext() || !register.getAddress().getAddressSpace().isRegisterSpace()
                    || register.getLeastSignificantBit() != 0
                    || register.getBitLength() != 8 * register.getNumBytes()) {
                continue;
            }
            kept.add(register);
        }
        kept.sort(Comparator.<Register, BigInteger>comparing(item -> spaceId(item.getAddress().getAddressSpace()))
            .thenComparing(item -> byteOffset(item.getAddress()))
            .thenComparingInt(Register::getNumBytes)
            .thenComparing(Register::getName));
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Register register : kept) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("name", register.getName());
            row.put("space_id", spaceId(register.getAddress().getAddressSpace()));
            row.put("byte_offset", byteOffset(register.getAddress()));
            row.put("byte_size", u64(register.getNumBytes(), "register size"));
            rows.add(row);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("revision", 1);
        result.put("registers", rows);
        return result;
    }

    private void publish(Options options) throws Exception {
        if (!Files.isDirectory(options.outputRoot)) {
            throw new IOException("configured output root must already exist");
        }
        Path stage = options.outputRoot.resolve(options.generation + ".staging");
        Path published = options.outputRoot.resolve(options.generation);
        if (Files.exists(stage) || Files.exists(published)) {
            throw new IOException("configured generation already exists");
        }
        Files.createDirectory(stage);
        try {
            List<Map<String, Object>> members = new ArrayList<>();
            members.add(copyOriginal(options, stage.resolve("original.bin")));
            Map<String, Object> programMember = writeJsonMember(
                "program", stage.resolve("program.json"), programCandidate());
            members.add(programMember);

            List<Map<String, Object>> blocks;
            List<Map<String, Object>> functions;
            Map<String, Object> imageInfoMember;
            Map<String, Object> profileMember;
            try (GhidraV2CallInterfaceProfile.CaptureSession profileSession =
                    GhidraV2CallInterfaceProfile.captureSession(
                        currentProgram, monitor, PROFILE_AUTHORITY_MODE,
                        options.profileExporterSha256, options.originalSha256,
                        options.generation, MANIFEST_SCHEMA_ID, SEAL_SCHEMA_ID,
                        memberText(programMember, "id"),
                        memberText(programMember, "sha256"))) {
                profileMember = writeJsonMember(
                    "call-interface-profile",
                    stage.resolve("call-interface-profile.json"),
                    profileSession.profileJson());
                members.add(profileMember);
                blocks = blockRows(stage, members);
                imageInfoMember = writeJsonMember(
                    "image-info", stage.resolve("image-info.json"), imageInfo());
                members.add(imageInfoMember);
                functions = functionRows(
                    options, stage, members, profileSession, profileMember,
                    runtimeClasses(options));
            }
            // (X-1, design_x1 r3 4.1 / 4.2, r4 4.2) the stack-switch scan runs here,
            // read-only on the locked program (no transaction); its evidence is
            // sealed as the last member. The listing digest is computed when the
            // observations are collected, inside the scan and before sealing: any
            // difference (or a scan failure) fails the export.
            Map<String, Object> collected = GhidraV2StackSwitchScanner.listingDigest(
                currentProgram, exportedRows, collectedLines, monitor);
            Map<String, Object> scanEvidence = new GhidraV2StackSwitchScanner(currentProgram, monitor, true)
                .evidence(options.originalSha256, exportedRows);
            Map<String, Object> sealing = GhidraV2StackSwitchScanner.listingDigest(
                currentProgram, exportedRows, null, monitor);
            @SuppressWarnings("unchecked")
            Map<String, Object> scanned = (Map<String, Object>) scanEvidence.get("listing_digest");
            GhidraV2StackSwitchScanner.requireSameListing(collected, scanned, sealing);
            Map<String, Object> evidenceMember = writeJsonMember(
                "stack-switch-evidence", stage.resolve("stack-switch-evidence.json"), scanEvidence);
            members.add(evidenceMember);

            Map<String, Object> manifest = new LinkedHashMap<>();
            manifest.put("schema_version", FORMAT_VERSION);
            manifest.put("generation_id", options.generation);
            manifest.put("original_member_id", "original");
            manifest.put("program_member_id", "program");
            manifest.put(
                "call_interface_profile_member", memberText(profileMember, "id"));
            manifest.put("members", members);
            manifest.put("blocks", blocks);
            manifest.put("functions", functions);
            manifest.put("image_info_member", memberText(imageInfoMember, "id"));
            manifest.put("producer_profile", PRODUCER_PROFILE);
            manifest.put("stack_switch_evidence_member", memberText(evidenceMember, "id"));
            byte[] manifestBytes = jsonBytes(manifest);
            writeFile(stage.resolve("manifest.json"), manifestBytes);

            Map<String, Object> seal = new LinkedHashMap<>();
            seal.put("schema_version", FORMAT_VERSION);
            seal.put("generation_id", options.generation);
            seal.put("manifest_size", manifestBytes.length);
            seal.put("manifest_sha256", digest(manifestBytes));
            writeFile(stage.resolve("seal.json"), jsonBytes(seal));
            forceDirectory(stage);
            try {
                Files.move(stage, published, StandardCopyOption.ATOMIC_MOVE);
            }
            catch (AtomicMoveNotSupportedException exception) {
                throw new IOException("configured publication requires an atomic rename", exception);
            }
            forceDirectory(options.outputRoot);
            byte[] receipt = (options.generation + "\n" + options.receiptNonce + "\n")
                .getBytes(StandardCharsets.US_ASCII);
            writeFile(options.receiptPath, receipt);
        }
        catch (Throwable failure) {
            if (Files.exists(stage)) {
                deleteTree(stage);
            }
            if (failure instanceof Exception exception) {
                throw exception;
            }
            if (failure instanceof Error error) {
                throw error;
            }
            throw new RuntimeException(failure);
        }
    }

    private Map<String, Object> copyOriginal(Options options, Path output) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        BigInteger size = BigInteger.ZERO;
        try (InputStream input = new BufferedInputStream(Files.newInputStream(options.original));
             OutputStream stream = new BufferedOutputStream(Files.newOutputStream(output,
                 StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
            byte[] buffer = new byte[CHUNK_BYTES];
            for (int count; (count = input.read(buffer)) != -1;) {
                monitor.checkCancelled();
                if (count == 0) {
                    continue;
                }
                stream.write(buffer, 0, count);
                digest.update(buffer, 0, count);
                size = size.add(BigInteger.valueOf(count));
            }
        }
        forceFile(output);
        String actual = hex(digest.digest());
        if (!size.equals(options.originalSize) || !actual.equals(options.originalSha256)) {
            throw new IOException("original executable changed after orchestration");
        }
        String claim = currentProgram.getExecutableSHA256();
        if (claim != null && !claim.isBlank() && !actual.equals(claim.trim().toLowerCase())) {
            throw new IOException("Ghidra executable SHA-256 disagrees with configured original");
        }
        return member("original", output, size, actual);
    }

    private List<Map<String, Object>> blockRows(
            Path stage, List<Map<String, Object>> members) throws Exception {
        List<Map<String, Object>> result = new ArrayList<>();
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (int index = 0; index < blocks.length; index++) {
            monitor.checkCancelled();
            MemoryBlock block = blocks[index];
            boolean loaded = block.isLoaded();
            boolean initialized = block.isInitialized();
            boolean overlay = block.getStart().getAddressSpace().isOverlaySpace();
            boolean external = block.isExternalBlock();
            boolean mapped = block.getType() != MemoryBlockType.DEFAULT;
            BigInteger size = u64(block.getSize(), "memory-block size");
            String memberId = null;
            if (loaded && initialized && !overlay && !external && !mapped) {
                memberId = String.format("memory-%06d", index);
                Path path = stage.resolve(memberId + ".bin");
                String hash = writeMemory(block, path, size);
                members.add(member(memberId, path, size, hash));
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", String.format("block-%06d", index));
            row.put("space_id", spaceId(block.getStart().getAddressSpace()));
            row.put("byte_start", byteOffset(block.getStart()));
            row.put("byte_size", size);
            row.put("is_loaded", loaded);
            row.put("is_initialized", initialized);
            row.put("is_overlay", overlay);
            row.put("is_external", external);
            row.put("is_mapped", mapped);
            row.put("member_id", memberId);
            result.add(row);
        }
        return result;
    }

    /**
     * Image facts beside the sealed memory blocks (schema tdo-v2-image-info-1):
     * per-block permissions and names, imported symbols with the memory slots
     * Ghidra binds to them (IAT entries, .refptr-style pointers) and their thunks,
     * exported entry points, and relocated addresses. Order is canonical.
     */
    private Map<String, Object> imageInfo() throws Exception {
        List<Map<String, Object>> permissions = new ArrayList<>();
        MemoryBlock[] blocks = currentProgram.getMemory().getBlocks();
        for (int index = 0; index < blocks.length; index++) {
            MemoryBlock block = blocks[index];
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("block_id", String.format("block-%06d", index));
            row.put("name", block.getName());
            row.put("read", block.isRead());
            row.put("write", block.isWrite());
            row.put("execute", block.isExecute());
            row.put("volatile", block.isVolatile());
            permissions.add(row);
        }

        List<Map<String, Object>> imports = new ArrayList<>();
        ExternalManager externals = currentProgram.getExternalManager();
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (Symbol symbol : symbols.getExternalSymbols()) {
            monitor.checkCancelled();
            ExternalLocation location = externals.getExternalLocation(symbol);
            if (location == null) {
                continue;
            }
            List<Map<String, Object>> slots = new ArrayList<>();
            List<Map<String, Object>> thunks = new ArrayList<>();
            for (Reference reference : currentProgram.getReferenceManager().getReferencesTo(symbol.getAddress())) {
                Address from = reference.getFromAddress();
                if (!from.isMemoryAddress()) {
                    continue;
                }
                Function function = currentProgram.getFunctionManager().getFunctionAt(from);
                if (function != null && importThunk(function)) {
                    thunks.add(coordinate(from));
                }
                else if (currentProgram.getListing().getInstructionAt(from) == null) {
                    slots.add(coordinate(from));  // a data slot holding the import's address
                }
            }
            for (Function thunk : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!importThunk(thunk)) {
                    continue;
                }
                Function target = thunk.getThunkedFunction(true);
                if (target.getEntryPoint().equals(symbol.getAddress())) {
                    Map<String, Object> entry = coordinate(thunk.getEntryPoint());
                    if (!thunks.contains(entry)) {
                        thunks.add(entry);
                    }
                }
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("library", location.getLibraryName());
            row.put("name", location.getLabel());
            row.put("original_name", location.getOriginalImportedName());
            row.put("slots", sortedCoordinates(slots));
            row.put("thunks", sortedCoordinates(thunks));
            imports.add(row);
        }
        imports.sort(Comparator.comparing((Map<String, Object> row) -> String.valueOf(row.get("library")))
            .thenComparing(row -> String.valueOf(row.get("name"))));

        List<Map<String, Object>> exports = new ArrayList<>();
        AddressIterator entries = symbols.getExternalEntryPointIterator();
        while (entries.hasNext()) {
            Address entry = entries.next();
            for (Symbol symbol : symbols.getSymbols(entry)) {
                Map<String, Object> row = coordinate(entry);
                row.put("name", symbol.getName());
                row.put("primary", symbol.isPrimary());
                exports.add(row);
            }
        }
        exports.sort(Comparator.comparing((Map<String, Object> row) -> (BigInteger)row.get("byte_offset"))
            .thenComparing(row -> String.valueOf(row.get("name"))));

        List<Map<String, Object>> relocations = new ArrayList<>();
        java.util.Iterator<Relocation> iterator = currentProgram.getRelocationTable().getRelocations();
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Relocation relocation = iterator.next();
            Map<String, Object> row = coordinate(relocation.getAddress());
            row.put("byte_size", u64(relocation.getLength(), "relocation length"));
            relocations.add(row);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("schema", "tdo-v2-image-info-1");
        result.put("executable_format", currentProgram.getExecutableFormat());
        result.put("block_permissions", permissions);
        result.put("imports", imports);
        result.put("exports", exports);
        result.put("relocations", relocations);
        return result;
    }

    private static List<Map<String, Object>> sortedCoordinates(List<Map<String, Object>> rows) {
        List<Map<String, Object>> result = new ArrayList<>(rows);
        result.sort(Comparator.comparing((Map<String, Object> row) -> (BigInteger)row.get("space_id"))
            .thenComparing(row -> (BigInteger)row.get("byte_offset")));
        return result;
    }

    private String writeMemory(MemoryBlock block, Path path, BigInteger expectedSize) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long size = expectedSize.longValueExact();
        long offset = 0;
        try (OutputStream output = new BufferedOutputStream(Files.newOutputStream(path,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE))) {
            while (offset < size) {
                monitor.checkCancelled();
                int count = (int)Math.min(CHUNK_BYTES, size - offset);
                byte[] buffer = new byte[count];
                int read = block.getBytes(block.getStart().add(offset), buffer);
                if (read != count) {
                    throw new IOException("Ghidra memory read ended early");
                }
                output.write(buffer);
                digest.update(buffer);
                offset += read;
            }
        }
        forceFile(path);
        return hex(digest.digest());
    }

    private List<Map<String, Object>> functionRows(
            Options options, Path stage, List<Map<String, Object>> members,
            GhidraV2CallInterfaceProfile.CaptureSession profileSession,
            Map<String, Object> profileMember,
            List<Map<String, Object>> runtimeClasses) throws Exception {
        List<Function> functions = selectFunctions(options.entries, options.functionNames,
            options.stopNames);
        List<Map<String, Object>> result = new ArrayList<>();
        for (int index = 0; index < functions.size(); index++) {
            monitor.checkCancelled();
            String id = String.format("function-%06d", index);
            String namingId = String.format("call-names-%06d", index);
            String effectId = String.format("call-effects-%06d", index);
            Function function = functions.get(index);
            Address entry = function.getEntryPoint();
            ObservedFunction observed = observedFunction(function);

            Map<String, Object> observationMember = writeJsonMember(
                id, stage.resolve(id + ".json"), functionCandidate(function, observed));
            members.add(observationMember);
            Map<String, Object> namingMember = writeJsonMember(
                namingId, stage.resolve(namingId + ".json"),
                GhidraV2CallNaming.capture(
                    currentProgram, function, monitor, options.namingExporterSha256,
                    options.generation, MANIFEST_SCHEMA_ID, SEAL_SCHEMA_ID,
                    memberText(observationMember, "id"),
                    memberText(observationMember, "sha256"),
                    spaceId(entry.getAddressSpace()), byteOffset(entry), observed.body));
            members.add(namingMember);
            Map<String, Object> effectMember = writeJsonMember(
                effectId, stage.resolve(effectId + ".json"),
                GhidraV2CallEffect.capture(
                    currentProgram, function, profileSession, monitor,
                    options.effectExporterSha256, options.generation,
                    MANIFEST_SCHEMA_ID, SEAL_SCHEMA_ID,
                    memberText(observationMember, "id"),
                    memberText(observationMember, "sha256"),
                    memberText(profileMember, "id"),
                    memberText(profileMember, "sha256"), runtimeClasses,
                    observed.body));
            members.add(effectMember);
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", id);
            row.put("observation_member", memberText(observationMember, "id"));
            row.put("call_names_member", memberText(namingMember, "id"));
            row.put("call_effects_member", memberText(effectMember, "id"));
            result.add(row);
        }
        if (!s1Withheld.isEmpty()) {
            println("[GhidraV2BundleExport] S1 withheld for " + s1Withheld.size() + " function(s): " +
                String.join("; ", s1Withheld));
        }
        return result;
    }

    private static List<Map<String, Object>> runtimeClasses(Options options) {
        List<Map<String, Object>> result = new ArrayList<>();
        result.add(runtimeClass("GhidraV2BundleExport", options.bundleExporterSha256));
        result.add(runtimeClass("GhidraV2CallEffect", options.effectExporterSha256));
        result.add(runtimeClass(
            "GhidraV2CallInterfaceProfile", options.profileExporterSha256));
        result.add(runtimeClass("GhidraV2CallNaming", options.namingExporterSha256));
        return result;
    }

    private static Map<String, Object> runtimeClass(String id, String sha256) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("class_id", id);
        result.put("class_sha256", lowerHex(sha256, "runtime class SHA-256"));
        return result;
    }

    private static String memberText(Map<String, Object> member, String key) {
        Object value = member.get(key);
        if (!(value instanceof String text) || text.isEmpty()) {
            throw new IllegalStateException("published member identity is incomplete");
        }
        if ("sha256".equals(key)) {
            return lowerHex(text, "published member SHA-256");
        }
        return text;
    }

    private Set<Function> stopFunctions(List<String> names) throws Exception {
        Set<Function> stops = new LinkedHashSet<>();
        SymbolTable symbols = currentProgram.getSymbolTable();
        for (String name : names) {
            List<String> found = new ArrayList<>();
            for (Symbol symbol : symbols.getSymbols(name)) {
                Function function = currentProgram.getFunctionManager()
                    .getFunctionAt(symbol.getAddress());
                if (function == null) {
                    continue;
                }
                // a thunk export (jmp to the body): the boundary is its terminal (G-T
                // G2: an internal thunk is itself exported and walked -- its only
                // callee is that terminal, which the walk does not enter)
                Function terminal = function.isThunk() ? resolvedThunkTerminal(function) : function;
                if (terminal == null) {
                    throw new IllegalArgumentException("stop-at " + name + ": unresolved thunk");
                }
                stops.add(terminal);
                found.add(terminal.getEntryPoint().toString());
            }
            if (found.isEmpty()) {
                throw new IllegalArgumentException("stop-at " + name + ": no function has this symbol");
            }
            println("stop-at " + name + ": " + found.size() + " function(s) " + found +
                (found.size() > 1 ? " (WARNING: several)" : ""));
        }
        return stops;
    }

    private List<Function> selectFunctions(List<Entry> entries, List<String> functionNames,
            List<String> stopNames) throws Exception {
        Set<Function> stops = stopFunctions(stopNames);
        List<Function> result = new ArrayList<>();
        Map<BigInteger, AddressSpace> spaces = new HashMap<>();
        for (AddressSpace space : currentProgram.getAddressFactory().getAllAddressSpaces()) {
            spaces.put(spaceId(space), space);
        }
        for (Entry entry : entries) {
            AddressSpace space = spaces.get(entry.spaceId);
            if (space == null) {
                throw new IllegalArgumentException("configured entry uses an unknown address space");
            }
            Address address = space.getAddress(entry.byteOffset.longValue());
            if (!byteOffset(address).equals(entry.byteOffset)) {
                throw new IllegalArgumentException("configured entry is not addressable in its space");
            }
            Function function = currentProgram.getFunctionManager().getFunctionAt(address);
            if (function == null) {
                throw new IllegalArgumentException("configured entry has no exact Ghidra function");
            }
            result.add(function);
        }
        if (!functionNames.isEmpty()) {
            Map<String, List<Function>> byName = new HashMap<>();
            FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) {
                Function function = iterator.next();
                byName.computeIfAbsent(function.getName(), ignored -> new ArrayList<>())
                    .add(function);
            }
            for (String name : functionNames) {
                List<Function> matches = byName.getOrDefault(name, List.of());
                if (matches.size() != 1) {
                    throw new IllegalArgumentException(
                        "configured function name is missing or ambiguous: " + name);
                }
                if (result.contains(matches.get(0))) {
                    throw new IllegalArgumentException(
                        "configured function names resolve to a duplicate entry");
                }
                result.add(matches.get(0));
            }
        }
        if (!result.isEmpty()) {
            // names or entries: the transitive call/reference closure (not
            // followed into a stop function other than a selected one)
            Set<Function> selected = new LinkedHashSet<>(result);
            Set<Function> targets = new LinkedHashSet<>(result);
            for (int index = 0; index < result.size(); index++) {
                monitor.checkCancelled();
                if (stops.contains(result.get(index)) && !targets.contains(result.get(index))) {
                    continue;
                }
                ObservedFunction observed = observedFunction(result.get(index));
                Set<Function> closureSet = new LinkedHashSet<>(
                    result.get(index).getCalledFunctions(monitor));
                for (Function called : List.copyOf(closureSet)) {
                    Function terminal = resolvedThunkTerminal(called);
                    if (terminal != null) {
                        closureSet.add(terminal);
                    }
                }
                closureSet.addAll(referencedFunctions(observed.body));
                if (callFallthroughIsa) {
                    // (S1) follow fallthroughs into other functions (exit kinds 2-3)
                    InstructionIterator rows = currentProgram.getListing()
                        .getInstructions(observed.body, true);
                    while (rows.hasNext()) {
                        Instruction row = rows.next();
                        Address fallthrough = row.getFallThrough();
                        Function owner = fallthrough == null ? null :
                            fallthroughOwner(fallthrough, result.get(index));
                        if (owner != null) {
                            closureSet.add(owner);
                        }
                    }
                }
                List<Function> closure = new ArrayList<>(closureSet);
                // (G-T G2) an import thunk stays out (image facts map its address
                // to the import, ``imports[].thunks``); a thunk into internal code
                // is an ordinary Bundle function, so a call to it has a target
                closure.removeIf(function ->
                    function.isExternal() || importThunk(function) ||
                    !hasObservedInstructions(function));
                closure.sort(Comparator
                    .comparing((Function function) ->
                        spaceIdOf(function.getEntryPoint()))
                    .thenComparing(function ->
                        byteOffset(function.getEntryPoint())));
                for (Function function : closure) {
                    if (selected.add(function)) {
                        if (result.size() == MAX_SELECTED_FUNCTIONS) {
                            throw new IllegalArgumentException(
                                "function reference closure exceeds its bound");
                        }
                        result.add(function);
                    }
                }
            }
        }
        return result;
    }

    /**
     * (G-T G2) The one "import thunk" classification: a thunk whose final
     * target ({@code getThunkedFunction(true)}) is external. Both the image
     * facts' {@code imports[].thunks} and the closure filter use it, so the
     * thunks listed for an import and the thunks left out of the Bundle are
     * the same set.
     */
    private static boolean importThunk(Function function) {
        if (!function.isThunk()) {
            return false;
        }
        Function target = function.getThunkedFunction(true);
        return target != null && target.isExternal();
    }

    private Function resolvedThunkTerminal(Function start) throws Exception {
        Set<Address> seen = new LinkedHashSet<>();
        Function current = start;
        while (current != null) {
            monitor.checkCancelled();
            if (current.getProgram() != currentProgram || current.isDeleted() ||
                    !seen.add(current.getEntryPoint()) ||
                    seen.size() > MAX_SELECTED_FUNCTIONS) {
                return null;
            }
            if (!current.isThunk()) {
                return current;
            }
            current = current.getThunkedFunction(false);
        }
        return null;
    }

    private Set<Function> referencedFunctions(AddressSetView body) throws Exception {
        Set<Function> result = new LinkedHashSet<>();
        AddressSpace defaultSpace = currentProgram.getAddressFactory()
            .getDefaultAddressSpace();
        InstructionIterator instructions = currentProgram.getListing()
            .getInstructions(body, true);
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            for (Reference reference : instruction.getReferencesFrom()) {
                Address referenceTarget = reference.getToAddress();
                Function target = currentProgram.getFunctionManager()
                    .getFunctionAt(referenceTarget);
                if (target == null && referenceTarget != null &&
                        !reference.getReferenceType().isFlow() &&
                        !reference.getReferenceType().isRead() &&
                        !reference.getReferenceType().isWrite()) {
                    target = currentProgram.getFunctionManager()
                        .getFunctionContaining(referenceTarget);
                }
                if (target != null) {
                    result.add(target);
                }
            }
            for (PcodeOp operation : instruction.getPcode()) {
                for (Varnode input : operation.getInputs()) {
                    if (!input.isConstant()) {
                        continue;
                    }
                    Address address;
                    try {
                        address = defaultSpace.getAddress(input.getOffset());
                    } catch (RuntimeException ignored) {
                        continue;
                    }
                    Function target = currentProgram.getFunctionManager()
                        .getFunctionAt(address);
                    if (target != null) {
                        result.add(target);
                    }
                }
            }
        }
        return result;
    }

    private boolean hasObservedInstructions(Function function) {
        return currentProgram.getListing().getInstructions(function.getBody(), true).hasNext();
    }

    private ObservedFunction observedFunction(Function function) throws Exception {
        AddressSet body = new AddressSet(function.getBody());
        List<ExceptionRegion> ownedRegions = new ArrayList<>();
        for (ExceptionRegion region : exceptionRegions) {
            monitor.checkCancelled();
            if (!region.functionRange.contains(function.getEntryPoint())) {
                continue;
            }
            ownedRegions.add(region);
            InstructionIterator instructions = currentProgram.getListing()
                .getInstructions(new AddressSet(region.functionRange), true);
            while (instructions.hasNext()) {
                Instruction instruction = instructions.next();
                Function owner = currentProgram.getFunctionManager()
                    .getFunctionContaining(instruction.getAddress());
                if (region.exactFunctionExtent || owner == null || owner == function) {
                    body.add(instruction.getAddress(), instruction.getMaxAddress());
                }
            }
        }

        Map<Address, Set<Address>> exceptionalTargets = new HashMap<>();
        Map<Address, Set<Address>> recordedPads = new HashMap<>();
        for (ExceptionRegion region : ownedRegions) {
            for (ExceptionCallSite callSite : region.callSites) {
                if (!body.contains(callSite.landingPad)) {
                    throw new IOException(
                        "exception landing pad has no observed instruction: function=" +
                        function.getEntryPoint() + ", landing=" + callSite.landingPad +
                        ", range=" + region.functionRange + ", exact=" +
                        region.exactFunctionExtent + ", listing=" +
                        currentProgram.getListing().getInstructionAt(callSite.landingPad));
                }
                InstructionIterator instructions = currentProgram.getListing()
                    .getInstructions(new AddressSet(callSite.protectedRange), true);
                while (instructions.hasNext()) {
                    Instruction instruction = instructions.next();
                    if (body.contains(instruction.getAddress())) {
                        recordedPads
                            .computeIfAbsent(
                                instruction.getAddress(), ignored -> new LinkedHashSet<>())
                            .add(callSite.landingPad);
                    }
                    if (!body.contains(instruction.getAddress()) ||
                            !hasCallOperation(instruction)) {
                        continue;
                    }
                    exceptionalTargets
                        .computeIfAbsent(
                            instruction.getAddress(), ignored -> new LinkedHashSet<>())
                        .add(callSite.landingPad);
                }
            }
        }
        return new ObservedFunction(body, exceptionalTargets, recordedPads);
    }

    // (G3b-7b r9; proof-inputs review: Astra r1 P1-1 / P1-2, r2 P1-1, Fable r1
    // P1-3) proof facts (S1, the exception-handlers fact) read Ghidra memory
    // and listing, which a prepared project may have changed (patched bytes,
    // earlier analysis with other settings, edits): they need this run's own
    // import, attested by the -preScript's headless-session token for this
    // program object. The token is consumed: one export per attestation.
    private boolean freshImportAttested() throws Exception {
        String token = currentProgram.getDomainFile().getPathname() + "#" + System.identityHashCode(currentProgram);
        boolean attested = token.equals(getStoredHeadlessValue(FRESH_IMPORT_KEY));
        storeHeadlessValue(FRESH_IMPORT_KEY, null);
        return attested;
    }

    /** (G3b-7b r9g, Astra r12) the decode mode is the one the original file's
     *  own machine field names -- read from the configured original, not the
     *  database: an AMD64 PE / x86-64 ELF decodes as x86:LE:64:default, an i386
     *  PE / ELF as x86:LE:32:default. Other machines are not checked here (the
     *  ISA-decode premise, docs 25.115). Unreadable header: doubt. */
    private boolean decodeModeMatchesFile(Options options) {
        int machine;
        boolean pe;
        try (FileChannel channel = FileChannel.open(options.original, java.nio.file.StandardOpenOption.READ)) {
            java.nio.ByteBuffer head = java.nio.ByteBuffer.allocate(0x40).order(java.nio.ByteOrder.LITTLE_ENDIAN);
            int count = Math.max(channel.read(head, 0), 0);
            if (count >= 0x40 && head.get(0) == 'M' && head.get(1) == 'Z') {
                // (Astra r13 P2) e_lfanew anywhere in the file, not only in its first 4 KiB
                long header = head.getInt(0x3C) & 0xffffffffL;
                java.nio.ByteBuffer signature = java.nio.ByteBuffer.allocate(6).order(java.nio.ByteOrder.LITTLE_ENDIAN);
                if (channel.read(signature, header) != 6 || signature.getInt(0) != 0x4550) {
                    return false;
                }
                machine = signature.getShort(4) & 0xffff;
                pe = true;
            }
            else if (count >= 20 && head.get(0) == 0x7f && head.get(1) == 'E' && head.get(2) == 'L' &&
                    head.get(3) == 'F' && head.get(5) == 1) {
                // (the ELF class is not checked: an x32 image with EM_X86_64 also decodes in long mode)
                machine = head.getShort(18) & 0xffff;
                pe = false;
            }
            else {
                return true;
            }
        }
        catch (IOException error) {
            return false;
        }
        String expected = pe ? (machine == 0x8664 ? LONG_MODE : machine == 0x14c ? "x86:LE:32:default" : null)
            : (machine == 62 ? LONG_MODE : machine == 3 ? "x86:LE:32:default" : null);
        return expected == null || expected.equals(currentProgram.getLanguageID().getIdAsString());
    }

    private boolean flowGuessesOff() {
        Map<String, String> values = getCurrentAnalysisOptionsAndValues(currentProgram);
        for (String name : FLOW_GUESS_OPTIONS) {
            // (an analyzer not registered for this program's format never runs)
            if (values.containsKey(name) && !"false".equals(values.get(name))) {
                return false;
            }
        }
        return true;
    }

    // Ghidra's interrupt lifting, exactly: v = CALLOTHER(constants...); CALLIND v;
    // optionally RETURN constant (INT3) -- the same shape as the engine's
    // _scope_contracts.is_interrupt_shape; anything else holding a CALL / CALLIND
    // is a native call
    private static boolean isInterruptShape(PcodeOp[] pcode) {
        if (pcode.length < 2 || pcode.length > 3 ||
                pcode[0].getOpcode() != PcodeOp.CALLOTHER || pcode[1].getOpcode() != PcodeOp.CALLIND) {
            return false;
        }
        Varnode output = pcode[0].getOutput();
        if (output == null || pcode[1].getNumInputs() < 1 || !output.equals(pcode[1].getInput(0))) {
            return false;
        }
        for (Varnode input : pcode[0].getInputs()) {
            if (!input.isConstant()) {
                return false;
            }
        }
        return pcode.length == 2 || pcode[2].getOpcode() == PcodeOp.RETURN &&
            pcode[2].getNumInputs() >= 1 && pcode[2].getInput(0).isConstant();
    }

    private static boolean isNativeCall(Instruction instruction) {
        PcodeOp[] pcode = instruction.getPcode();
        if (isInterruptShape(pcode)) {
            return false;
        }
        for (PcodeOp operation : pcode) {
            if (operation.getOpcode() == PcodeOp.CALL || operation.getOpcode() == PcodeOp.CALLIND) {
                return true;
            }
        }
        return false;
    }

    // the function Ghidra places a fallthrough address in: its entry (2), an
    // instruction inside it (3); null when neither (4) or when it is ``self``
    private Function fallthroughOwner(Address target, Function self) {
        FunctionManager functions = currentProgram.getFunctionManager();
        Function entryOf = functions.getFunctionAt(target);
        if (entryOf != null) {
            return entryOf == self ? null : entryOf;
        }
        Function owner = functions.getFunctionContaining(target);
        if (owner == null || owner == self ||
                currentProgram.getListing().getInstructionAt(target) == null) {
            return null;
        }
        return owner;
    }

    // (S1) the rows of one function whose fallthrough leaves it -- a call's ISA
    // continuation, or any row falling out (padding after a non-returning call
    // into the next function) -- and a shared entry of another function inside
    // it, classified: 2 the entry of another function, 3 an instruction inside
    // another function, 4 nothing analysable. Records a violation for a native
    // call whose fallthrough is not its ISA one and for a fallthrough decoded
    // across another instruction (reported for the whole program at the end).
    private List<Map<String, Object>> fallthroughExits(Function function, List<Instruction> rows,
            List<String> violations) {
        Set<Address> local = new LinkedHashSet<>();
        for (Instruction row : rows) {
            local.add(row.getAddress());
        }
        List<Map<String, Object>> result = new ArrayList<>();
        for (Instruction row : rows) {
            Address fallthrough = row.getFallThrough();
            if (isNativeCall(row)) {
                Address isa = row.getDefaultFallThrough();
                if (row.getFlowOverride() != FlowOverride.NONE || fallthrough == null ||
                        !fallthrough.equals(isa)) {
                    violations.add(row.getAddress() +
                        " (fallthrough " + fallthrough + ", ISA " + isa + ", override " +
                        row.getFlowOverride() + ")");
                    continue;
                }
            }
            if (fallthrough == null) {
                continue;
            }
            Function owner = fallthroughOwner(fallthrough, function);
            if (local.contains(fallthrough)) {
                if (owner == null || !owner.getEntryPoint().equals(fallthrough)) {
                    continue;   // an ordinary local successor
                }
                // a local successor that is another function's entry (shared code): kind 2
            }
            else {
                Instruction cover = currentProgram.getListing().getInstructionContaining(fallthrough);
                if (cover != null && !cover.getAddress().equals(fallthrough)) {
                    violations.add(row.getAddress() +
                        " (fallthrough " + fallthrough + " inside the instruction at " + cover.getAddress() + ")");
                    continue;
                }
            }
            int kind = owner == null ? 4 : owner.getEntryPoint().equals(fallthrough) ? 2 : 3;
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("source", coordinate(row.getAddress()));
            item.put("target", coordinate(fallthrough));
            item.put("kind", kind);
            item.put("function", owner == null ? null : coordinate(owner.getEntryPoint()));
            result.add(item);
        }
        return result;
    }

    private static boolean hasCallOperation(Instruction instruction) {
        for (PcodeOp operation : instruction.getPcode()) {
            if (operation.getOpcode() == PcodeOp.CALL ||
                    operation.getOpcode() == PcodeOp.CALLIND) {
                return true;
            }
        }
        return false;
    }

    private Map<String, Object> functionCandidate(
            Function function, ObservedFunction observed) throws Exception {
        List<Map<String, Object>> instructions = new ArrayList<>();
        List<Instruction> rows = new ArrayList<>();
        InstructionIterator iterator = currentProgram.getListing()
            .getInstructions(observed.body, true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            rows.add(instruction);
            exportedRows.computeIfAbsent(function.getEntryPoint(), ignored -> new ArrayList<>())
                .add(instruction.getAddress());
            // (Astra X-1a r3 #3) one read of the lift: serialized and attested alike
            PcodeOp[] lift = instruction.getPcode();
            collectedLines.put(instruction.getAddress(),
                GhidraV2StackSwitchScanner.lineDigest(GhidraV2StackSwitchScanner.attestedLine(instruction, lift)));
            Map<String, Object> row = instruction(
                instruction,
                observed.exceptionalTargets.getOrDefault(
                    instruction.getAddress(), Set.of()), lift);
            row.put("override", overrideEvidence(instruction));
            row.put("recorded_landing_pads", sortedCoordinates(
                observed.recordedPads.getOrDefault(instruction.getAddress(), Set.of())));
            instructions.add(row);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("entry", coordinate(function.getEntryPoint()));
        result.put("instructions", instructions);
        result.put("producer_profile", PRODUCER_PROFILE);
        // (G3b-7b r9e, Astra r10 / r11) a row whose length the CPU, not Ghidra's
        // decode, fixes (a 66-prefixed near control transfer) makes Ghidra's
        // fallthrough / return PC no ISA fact: the function gets neither S1 nor
        // the exception fact (it exports as from a prepared project)
        boolean isa = callFallthroughIsa && (!LONG_MODE.equals(currentProgram.getLanguageID().getIdAsString())
            || rows.stream().noneMatch(GhidraV2BundleExport::cpuDependentLength));   // (Fable r11: x86-64 only)
        List<Map<String, Object>> exits = null;
        if (isa) {
            // (X-1b, owner 2026-11-27) a native call without its ISA continuation (e.g. a CALL_RETURN override
            // on a call to a non-returning callee) or a fallthrough into another instruction withholds S1 for
            // THIS function -- it exports as from a prepared project; the rest of the Bundle keeps S1
            List<String> violations = new ArrayList<>();
            exits = fallthroughExits(function, rows, violations);
            if (!violations.isEmpty()) {
                isa = false;
                s1Withheld.add(function.getEntryPoint() + ": " + String.join(", ", violations));
            }
        }
        if (isa) {
            result.put("call_fallthrough", "isa");
            // (G3b-7b r9, Astra proof-inputs r3 P1-2) the attested fresh import:
            // the engine uses the exception fact only with this
            result.put("proof_input", "attested-fresh-import-v1");
            result.put("fallthrough_exits", exits);
        }
        if (isa && noStaticExceptionHandler(function, observed, rows)) {   // (r9: fresh import only)
            result.put("exception_handlers", "none");
        }
        return result;
    }

    /** (G3b-7b-1) x64 unwinding finds a handler only through the image's
     *  exception directory, by a frame's PC: a row of the body (a fault) or a
     *  call's ISA return address. No entry covering such a PC names a handler
     *  (directly or through a chain), every such PC lies inside the image, no
     *  call row carries a flow override, every call row keeps its ISA
     *  fallthrough (``getFallThrough() == address + parsed length``: a removed
     *  or moved fallthrough could hide the return edge into the entry), no call
     *  row has a non-call flow reference to the entry, and the body is exactly
     *  the exported rows (no undefined byte that could hold an unlisted call
     *  whose return PC goes unchecked) -- then the function has no landing pad
     *  and a listed entry on its call rows is the call's own. The return PC is
     *  a pure PC lookup in the table. A call row is any row with a CALL /
     *  CALLIND p-code operation or an x86 CALL instruction (Ghidra lifts
     *  ``call $+5`` as a push and a BRANCH, yet it stores a return PC). No
     *  branch or flow reference of a row may land inside the body but off a
     *  row start (a call decoded there would have an unchecked return PC).
     *  Body and fallthroughs are compared in the image's own address space
     *  (never an overlay). Any doubt: no fact. */
    private boolean noStaticExceptionHandler(
            Function function, ObservedFunction observed, List<Instruction> rows) {
        if (peUnwindEntries == null || !observed.exceptionalTargets.isEmpty()) {
            return false;
        }
        Address base = currentProgram.getImageBase();
        Address entry = function.getEntryPoint();
        AddressSet listed = new AddressSet();
        for (Instruction row : rows) {
            listed.add(row.getAddress(), row.getMaxAddress());
        }
        if (!listed.equals(observed.body)) {
            return false;
        }
        try {
            for (AddressRange range : observed.body) {
                if (!range.getAddressSpace().equals(base.getAddressSpace())) {
                    return false;
                }
                long low = range.getMinAddress().subtract(base);
                long high = range.getMaxAddress().subtract(base) + 1;
                if (handlerIn(low, high)) {
                    return false;
                }
            }
            for (Instruction row : rows) {
                if (computedJump(row)) {
                    return false;   // (Astra r6 / r7: it may land off a row start and run an unchecked call)
                }
                if (row.getLength() != row.getParsedLength()) {
                    return false;   // (a listing length override: the exported length is not the ISA one)
                }
                if (isaFallsThrough(row)) {
                    // (Astra r5 / r8) every row the ISA lets fall through keeps
                    // that fallthrough as it is: a removed or moved one could
                    // hide the CPU's next PC (an entry edge, or a byte off a
                    // row start running an unchecked call). A row the ISA ends
                    // (JMP, RET, INT3) has none to keep.
                    Address fallthrough = row.getFallThrough();
                    if (fallthrough == null || !fallthrough.equals(row.getAddress().add(row.getParsedLength()))) {
                        return false;
                    }
                }
                // (an x86 CALL mnemonic: condition (a) established an x86-64 image)
                if (!hasCallOperation(row) && !row.getMnemonicString().toUpperCase().startsWith("CALL")) {
                    continue;
                }
                if (row.getFlowOverride() != FlowOverride.NONE) {
                    return false;
                }
                for (Reference reference : row.getReferencesFrom()) {
                    if (reference.getReferenceType().isFlow() && !reference.getReferenceType().isCall() &&
                            entry.equals(reference.getToAddress())) {
                        return false;
                    }
                }
                long back = row.getAddress().subtract(base) + row.getParsedLength();
                if (handlerIn(back, back + 1)) {
                    return false;
                }
            }
            for (Instruction row : rows) {   // (last: the p-code is read again per row)
                if (landsOffRowStart(row, observed.body)) {
                    return false;
                }
            }
        }
        catch (RuntimeException error) {   // (an address outside the image's space)
            return false;
        }
        return true;
    }

    /** The instruction's own (prototype) flow falls through, whatever the
     *  listing's overrides say. */
    private static boolean isaFallsThrough(Instruction row) {
        return row.getPrototype().getFlowType(row.getInstructionContext()).hasFallthrough();
    }

    /** An x86 control transfer (a row holding BRANCH / CBRANCH / BRANCHIND /
     *  CALL / CALLIND / RETURN p-code) with an operand-size (66) prefix: in
     *  64-bit mode Intel ignores it for near CALL / JMP / Jcc / RET while
     *  Ghidra's x86-64 spec decodes the 16-bit form (as AMD does), so the
     *  row's length -- and its return / next PC -- depends on the CPU. Other
     *  66-prefixed rows (``66 90``) keep their length. Function-local: a row of
     *  another function never changes this function's frame PCs. Unreadable
     *  bytes count as doubt. */
    private static boolean cpuDependentLength(Instruction row) {
        // (Astra r12 P2) the instruction's own flow, not its p-code: a 16-bit
        // CMOVcc lifts its condition as an internal CBRANCH but transfers nothing
        FlowType flow = row.getPrototype().getFlowType(row.getInstructionContext());
        if (!flow.isJump() && !flow.isCall() && !flow.isTerminal() && !hasCallOperation(row)) {
            return false;
        }
        byte[] bytes;
        try {
            bytes = row.getBytes();
        }
        catch (MemoryAccessException error) {
            return true;
        }
        Set<Integer> seen = new java.util.HashSet<>();
        for (byte value : bytes) {
            int b = value & 0xff;
            boolean prefix = b == 0x66 || b == 0xF0 || b == 0x67 || b == 0xF2 || b == 0xF3 || b == 0x2E || b == 0x3E ||
                b == 0x26 || b == 0x36 || b == 0x64 || b == 0x65 || (b >= 0x40 && b <= 0x4F);
            if (!prefix) {
                return false;
            }
            // (Astra r10 / r12) 66: Intel and AMD differ; a repeated prefix (67 67):
            // decoders differ on what the repeat selects
            if (b == 0x66 || !seen.add(b)) {
                return true;
            }
        }
        return false;
    }

    /** A BRANCHIND row: its flow references need not list every destination
     *  (none, or a partly recovered table), so one could reach a byte off a
     *  row start and run an unchecked call. */
    private static boolean computedJump(Instruction row) {
        for (PcodeOp operation : row.getPcode()) {
            if (operation.getOpcode() == PcodeOp.BRANCHIND) {
                return true;
            }
        }
        return false;
    }

    /** A flow reference or an address-operand p-code branch / call of the row
     *  that lands inside the body but not on an instruction start. */
    private boolean landsOffRowStart(Instruction row, AddressSetView body) {
        List<Address> targets = new ArrayList<>();
        for (Reference reference : row.getReferencesFrom()) {
            if (reference.getReferenceType().isFlow()) {
                targets.add(reference.getToAddress());
            }
        }
        targets.addAll(Arrays.asList(row.getFlows()));
        for (PcodeOp operation : row.getPcode()) {
            int opcode = operation.getOpcode();
            if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH || opcode == PcodeOp.CALL) &&
                    operation.getNumInputs() > 0 && operation.getInput(0).isAddress()) {
                targets.add(operation.getInput(0).getAddress());
            }
        }
        for (Address target : targets) {
            if (target != null && body.contains(target) &&
                    currentProgram.getListing().getInstructionAt(target) == null) {
                return true;
            }
        }
        return false;
    }

    /** True when [low, high) is not provably handler-free: outside the image,
     *  or overlapping a RUNTIME_FUNCTION whose chain names a handler. */
    private boolean handlerIn(long low, long high) {
        if (low < 0 || high <= low || high > peImageSize) {
            return true;
        }
        Long start = peUnwindEntries.floorKey(low);
        for (long[] entry : peUnwindEntries.subMap(start == null ? low : start, true, high, false).values()) {
            if (entry[0] > low && entry[1] == 1) {
                return true;
            }
        }
        return false;
    }

    // (G3b-7b r9h) every image byte capturePeUnwindEntries reads (headers, load
    // config, exception directory, unwind records); null outside it
    private AddressSet proofReads;

    private TreeMap<Long, long[]> capturePeUnwindEntries() throws Exception {
        proofReads = new AddressSet();
        try {
            Address base = currentProgram.getImageBase();
            if (!"Portable Executable (PE)".equals(currentProgram.getExecutableFormat()) ||
                    // (Astra r11) the 64-bit decode mode exactly: x86:LE:64:compat32 shares
                    // processor and address size but decodes with longMode 0
                    !LONG_MODE.equals(currentProgram.getLanguageID().getIdAsString()) ||
                    u16At(base, 0) != 0x5A4D) {
                return null;
            }
            long header = u32At(base, 0x3C);
            if (u32At(base, header) != 0x4550L || u16At(base, header + 4) != 0x8664) {
                return null;   // (PE signature; COFF machine AMD64 -- not ARM64 / IA64)
            }
            long optional = header + 24;
            long optionalSize = u16At(base, header + 20);
            long directories = u32At(base, optional + 108);
            if (u16At(base, optional) != 0x20B || directories < 11 || directories > 16 ||
                    optionalSize < 112 + 8 * directories) {
                return null;   // (PE32+, data directories through the load config)
            }
            long imageSize = u32At(base, optional + 56);
            long loadConfig = u32At(base, optional + 112 + 10 * 8);
            long loadConfigSize = u32At(base, optional + 112 + 10 * 8 + 4);
            if (loadConfig != 0 || loadConfigSize != 0) {
                if (loadConfig == 0 || loadConfigSize < 4 || loadConfig + loadConfigSize > imageSize) {
                    return null;
                }
                long declared = u32At(base, loadConfig);
                if (declared < 4 || loadConfig + declared > imageSize) {
                    return null;   // (the structure's own size inside the image)
                }
                if (declared >= 0xC8 + 8) {
                    if (loadConfigSize < 0xC8 + 8) {
                        return null;   // (a directory smaller than the CHPE field it declares)
                    }
                    if (u32At(base, loadConfig + 0xC8) != 0 || u32At(base, loadConfig + 0xCC) != 0) {
                        return null;   // (CHPE metadata: an ARM64EC / ARM64X hybrid)
                    }
                }
            }
            long table = u32At(base, optional + 112 + 3 * 8);
            long size = u32At(base, optional + 112 + 3 * 8 + 4);
            if (table == 0 || size == 0 || size % 12 != 0 || table % 4 != 0 || table + size > imageSize) {
                return null;   // (no or malformed directory: no fact -- an absent one is a later precision item)
            }
            TreeMap<Long, long[]> entries = new TreeMap<>();
            long previousEnd = 0;
            for (long offset = table; offset < table + size; offset += 12) {
                monitor.checkCancelled();
                long begin = u32At(base, offset);
                long end = u32At(base, offset + 4);
                long unwind = u32At(base, offset + 8);
                if (begin >= end || end > imageSize || begin < previousEnd) {
                    return null;   // (sorted, disjoint, inside the image)
                }
                previousEnd = end;
                Boolean handler = chainHasHandler(base, unwind, imageSize);
                if (handler == null) {
                    return null;
                }
                entries.put(begin, new long[] {end, handler ? 1 : 0});
            }
            AddressSet writes = loaderWrites(base, optional, directories, imageSize, loadConfig, loadConfigSize);
            if (writes == null || writes.intersects(proofReads)) {
                // (Astra r13 / r14) a base relocation writing a byte the proof read
                // (e.g. an UnwindData RVA): loaded at another base, the loader
                // rewrites it and the table answers for other records -- no fact
                // for the image (image-level, not per function)
                return null;
            }
            peImageSize = imageSize;
            return entries;
        }
        catch (MemoryAccessException | RuntimeException error) {   // (never an export error)
            return null;
        }
        finally {
            proofReads = null;
        }
    }

    /** (Astra r13 / r14, Fable r13) the bytes the image's base relocations
     *  write, parsed from its own .reloc directory (not Ghidra's relocation
     *  table, which records PE base relocations as skipped, length 0): HIGH /
     *  LOW 2 bytes, HIGHLOW 4, HIGHADJ 2 (its parameter slot consumed), DIR64
     *  8, ABSOLUTE none (padding), any other type 8 (doubt). These reads are
     *  not proof reads. Null when the directory is malformed. */
    private AddressSet relocationWrites(Address base, long optional, long directories, long imageSize) {
        AddressSet writes = new AddressSet();
        if (directories <= 5) {
            return writes;
        }
        ghidra.program.model.mem.Memory memory = currentProgram.getMemory();
        try {
            long rva = memory.getInt(base.add(optional + 112 + 5 * 8), false) & 0xFFFFFFFFL;
            long size = memory.getInt(base.add(optional + 112 + 5 * 8 + 4), false) & 0xFFFFFFFFL;
            if (rva == 0 || size == 0) {
                return writes;
            }
            if (rva + size > imageSize) {
                return null;
            }
            long at = rva;
            while (at + 8 <= rva + size) {
                long page = memory.getInt(base.add(at), false) & 0xFFFFFFFFL;
                long block = memory.getInt(base.add(at + 4), false) & 0xFFFFFFFFL;
                if (block < 8 || (block - 8) % 2 != 0 || at + block > rva + size) {
                    return null;   // (Astra r16: the body splits into whole 2-byte entries)
                }
                for (long k = 8; k + 2 <= block; k += 2) {
                    int entry = memory.getShort(base.add(at + k), false) & 0xFFFF;
                    int type = entry >>> 12;
                    long target = page + (entry & 0xFFF);
                    int width = switch (type) {
                        case 0 -> 0;
                        case 1, 2 -> 2;
                        case 3 -> 4;
                        case 4 -> 2;
                        case 10 -> 8;
                        default -> 8;
                    };
                    if (type == 4) {
                        if (k + 4 > block) {
                            return null;   // (HIGHADJ without its parameter slot)
                        }
                        k += 2;   // (HIGHADJ: the next slot is its parameter)
                    }
                    if (width > 0) {
                        writes.add(base.add(target), base.add(target + width - 1));
                    }
                }
                at += block;
            }
            if (at != rva + size) {
                return null;   // (Astra r15 / Fable r14: trailing bytes -- the directory is consumed exactly)
            }
            // (Fable r14 / Astra r15) the loader applies blocks in order: a write into
            // the table itself or its data-directory entry changes what it applies next
            if (writes.intersects(base.add(rva), base.add(rva + size - 1)) ||
                    writes.intersects(base.add(optional + 112 + 5 * 8), base.add(optional + 112 + 5 * 8 + 7))) {
                return null;
            }
            return writes;
        }
        catch (MemoryAccessException | RuntimeException error) {
            return null;
        }
    }

    /** (G3b-7b r9j, Astra r15) every image byte the Windows loader (or the
     *  delay-load helper) writes, as far as the image declares them: base
     *  relocations, the TLS AddressOfIndex slot, the IAT directory and each
     *  import's FirstThunk array, each delay-load IAT, the security cookie and
     *  the CFG check / dispatch function pointer slots. Other load-time writes
     *  (dynamic value relocations, runtime patching) are the named load-image
     *  premise (docs 25.115), as is a write whose destination an earlier
     *  relocation rewrote (owner decision 2026-11-24: the loader is read at
     *  face value -- first-order writes only). These reads bypass proofReads on
     *  purpose. Null when any of them is malformed. */
    private AddressSet loaderWrites(Address base, long optional, long directories, long imageSize,
            long loadConfig, long loadConfigSize) {
        AddressSet writes = relocationWrites(base, optional, directories, imageSize);
        if (writes == null) {
            return null;
        }
        ghidra.program.model.mem.Memory memory = currentProgram.getMemory();
        try {
            long preferred = memory.getLong(base.add(optional + 24), false);
            // TLS: the loader stores the module's TLS index at AddressOfIndex (a VA)
            if (directories > 9) {
                long tls = memory.getInt(base.add(optional + 112 + 9 * 8), false) & 0xFFFFFFFFL;
                if (tls != 0) {
                    if (!slot(writes, base, memory.getLong(base.add(tls + 0x10), false), preferred, imageSize, 4)) {
                        return null;
                    }
                }
            }
            // IAT directory, and every import descriptor's FirstThunk array
            if (directories > 12) {
                long iat = memory.getInt(base.add(optional + 112 + 12 * 8), false) & 0xFFFFFFFFL;
                long iatSize = memory.getInt(base.add(optional + 112 + 12 * 8 + 4), false) & 0xFFFFFFFFL;
                if (iat != 0 && iatSize != 0) {
                    if (iat + iatSize > imageSize) {
                        return null;
                    }
                    writes.add(base.add(iat), base.add(iat + iatSize - 1));
                }
            }
            if (directories > 1) {
                long imports = memory.getInt(base.add(optional + 112 + 8), false) & 0xFFFFFFFFL;
                for (long at = imports; imports != 0; at += 20) {
                    if (at + 20 > imageSize) {
                        return null;
                    }
                    long lookup = memory.getInt(base.add(at), false) & 0xFFFFFFFFL;
                    long first = memory.getInt(base.add(at + 16), false) & 0xFFFFFFFFL;
                    long name = memory.getInt(base.add(at + 12), false) & 0xFFFFFFFFL;
                    if (first == 0 && name == 0 && lookup == 0) {
                        break;
                    }
                    if (!thunks(writes, base, first, lookup, imageSize)) {
                        return null;
                    }
                }
            }
            // delay-load IATs (written by the delay-load helper at first call)
            if (directories > 13) {
                long delay = memory.getInt(base.add(optional + 112 + 13 * 8), false) & 0xFFFFFFFFL;
                for (long at = delay; delay != 0; at += 32) {
                    if (at + 32 > imageSize) {
                        return null;
                    }
                    long attributes = memory.getInt(base.add(at), false) & 0xFFFFFFFFL;
                    long name = memory.getInt(base.add(at + 4), false) & 0xFFFFFFFFL;
                    long handle = memory.getInt(base.add(at + 8), false) & 0xFFFFFFFFL;
                    long table = memory.getInt(base.add(at + 12), false) & 0xFFFFFFFFL;
                    long names = memory.getInt(base.add(at + 16), false) & 0xFFFFFFFFL;
                    if (attributes == 0 && name == 0 && table == 0) {
                        break;
                    }
                    if ((attributes & 1) == 0 || !thunks(writes, base, table, names, imageSize)) {
                        return null;   // (fields not marked RVA-based: the old VA layout -- doubt)
                    }
                    if (handle != 0) {   // (Fable r15: the helper stores the module handle there)
                        if (handle + 8 > imageSize) {
                            return null;
                        }
                        writes.add(base.add(handle), base.add(handle + 7));
                    }
                }
            }
            // load config (Fable r15): any 8-byte field of the declared structure whose
            // value is a VA inside the image may be a slot the loader fills (security
            // cookie, CFG / XFG / RFG / cast-guard pointers ...) -- counted as an
            // 8-byte write, whatever the structure version
            if (loadConfig != 0) {
                long declared = memory.getInt(base.add(loadConfig), false) & 0xFFFFFFFFL;
                long limit = Math.min(declared, loadConfigSize);
                for (long offset = 0; offset + 8 <= limit; offset += 8) {
                    long va = memory.getLong(base.add(loadConfig + offset), false);
                    long rva = va - preferred;
                    if (Long.compareUnsigned(va, preferred) >= 0 && Long.compareUnsigned(rva, imageSize) < 0) {
                        writes.add(base.add(rva), base.add(Math.min(rva + 7, imageSize - 1)));
                    }
                }
            }
            return writes;
        }
        catch (MemoryAccessException | RuntimeException error) {
            return null;
        }
    }

    /** Add the ``length`` bytes at the VA ``va`` (an RVA after the preferred
     *  base); false when it lies outside the image. */
    private static boolean slot(AddressSet writes, Address base, long va, long preferred, long imageSize, int length) {
        long rva = va - preferred;
        if (va == 0) {
            return true;
        }
        if (rva < 0 || rva + length > imageSize) {
            return false;
        }
        writes.add(base.add(rva), base.add(rva + length - 1));
        return true;
    }

    /** (Astra r16) the loader fills one 8-byte IAT slot per entry of the lookup
     *  table (OriginalFirstThunk / the delay import name table) up to its zero
     *  terminator -- of the IAT itself when there is no separate lookup table:
     *  add that many slots at ``iat``, the terminator's slot included. False when
     *  an array leaves the image, has more than 65536 entries, or a lookup table
     *  comes without an IAT. */
    private boolean thunks(AddressSet writes, Address base, long iat, long lookup, long imageSize)
            throws MemoryAccessException {
        if (iat == 0) {
            return lookup == 0;
        }
        long table = lookup != 0 ? lookup : iat;
        for (int k = 0; k < 65536; k++) {
            long at = table + 8L * k;
            if (at + 8 > imageSize) {
                return false;
            }
            if (currentProgram.getMemory().getLong(base.add(at), false) == 0) {
                long end = iat + 8L * (k + 1);
                if (end > imageSize) {
                    return false;
                }
                writes.add(base.add(iat), base.add(end - 1));
                return true;
            }
        }
        return false;
    }

    /** True when the unwind info at ``unwind`` or a chained one names a
     *  handler (UNW_FLAG_EHANDLER / UHANDLER); null when it is not readable as
     *  x64 unwind info: an indirect entry, misalignment, a version other than
     *  1 / 2, undefined flag bits, CHAININFO together with a handler flag, a
     *  record (codes, handler RVA or chained entry) outside the image or not in
     *  initialized memory, a cycle, more than 32 links. */
    private Boolean chainHasHandler(Address base, long unwind, long imageSize) throws MemoryAccessException {
        Set<Long> seen = new HashSet<>();
        boolean handler = false;
        long current = unwind;
        while (true) {
            if (current % 4 != 0 || current + 4 > imageSize || !seen.add(current) || seen.size() > 32) {
                return null;
            }
            int head = u8At(base, current);
            int version = head & 7;
            int flags = head >> 3;
            if ((version != 1 && version != 2) || (flags & ~7) != 0 || ((flags & 4) != 0 && (flags & 3) != 0)) {
                return null;
            }
            int codes = u8At(base, current + 2);
            long tail = current + 4 + 2L * (codes + (codes & 1));
            long length = (tail - current) + ((flags & 3) != 0 ? 4 : 0) + ((flags & 4) != 0 ? 12 : 0);
            if (current + length > imageSize) {
                return null;
            }
            byte[] record = new byte[(int) length];
            proofReads.add(base.add(current), base.add(current + length - 1));
            if (currentProgram.getMemory().getBytes(base.add(current), record) != record.length) {
                return null;   // (every declared byte in initialized memory)
            }
            if ((flags & 3) != 0) {
                handler = true;
            }
            if ((flags & 4) == 0) {
                return handler;
            }
            long chainedBegin = u32At(base, tail);
            long chainedEnd = u32At(base, tail + 4);
            if (chainedBegin >= chainedEnd || chainedEnd > imageSize) {
                return null;
            }
            current = u32At(base, tail + 8);
        }
    }

    private long u32At(Address base, long rva) throws MemoryAccessException {
        read(base, rva, 4);
        return currentProgram.getMemory().getInt(base.add(rva), false) & 0xFFFFFFFFL;
    }

    private int u16At(Address base, long rva) throws MemoryAccessException {
        read(base, rva, 2);
        return currentProgram.getMemory().getShort(base.add(rva), false) & 0xFFFF;
    }

    private int u8At(Address base, long rva) throws MemoryAccessException {
        read(base, rva, 1);
        return currentProgram.getMemory().getByte(base.add(rva)) & 0xFF;
    }

    private void read(Address base, long rva, int length) {
        if (proofReads != null) {
            proofReads.add(base.add(rva), base.add(rva + length - 1));
        }
    }

    private Map<String, Object> instruction(
            Instruction instruction, Set<Address> exceptionalTargets, PcodeOp[] pcode) {
        FlowType flowType = instruction.getFlowType();
        Address fallthrough = instruction.getFallThrough();
        Set<Address> targets = new LinkedHashSet<>(Arrays.asList(instruction.getFlows()));
        targets.addAll(exceptionalTargets);
        List<Address> sortedTargets = new ArrayList<>(targets);
        sortedTargets.sort(Comparator.comparing(GhidraV2BundleExport::spaceIdOf)
            .thenComparing(GhidraV2BundleExport::byteOffset));
        List<Map<String, Object>> flows = new ArrayList<>();
        for (Address target : sortedTargets) {
            flows.add(coordinate(target));
        }
        Map<Address, boolean[]> dataTargets = new HashMap<>();
        Map<Address, Address> referencedFunctionEntries = new HashMap<>();
        for (Reference reference : instruction.getReferencesFrom()) {
            Address target = reference.getToAddress();
            if (!reference.getReferenceType().isFlow() && target != null &&
                    isCommittedMemoryTarget(target)) {
                boolean[] access = dataTargets.computeIfAbsent(
                    target, ignored -> new boolean[2]);
                access[0] |= reference.getReferenceType().isRead();
                access[1] |= reference.getReferenceType().isWrite();
                if (!reference.getReferenceType().isRead() &&
                        !reference.getReferenceType().isWrite()) {
                    Function owner = currentProgram.getFunctionManager()
                        .getFunctionContaining(target);
                    if (owner != null) {
                        referencedFunctionEntries.put(
                            target, owner.getEntryPoint());
                    }
                }
            }
        }
        List<Address> sortedDataTargets = new ArrayList<>(dataTargets.keySet());
        sortedDataTargets.sort(Comparator.comparing(GhidraV2BundleExport::spaceIdOf)
            .thenComparing(GhidraV2BundleExport::byteOffset));
        List<Map<String, Object>> dataReferences = new ArrayList<>();
        for (Address target : sortedDataTargets) {
            Map<String, Object> row = coordinate(target);
            boolean[] access = dataTargets.get(target);
            row.put("is_read", access[0]);
            row.put("is_write", access[1]);
            Address functionEntry = referencedFunctionEntries.get(target);
            row.put("referenced_function_entry_present", functionEntry != null);
            row.put(
                "referenced_function_entry",
                functionEntry == null ? null : coordinate(functionEntry));
            dataReferences.add(row);
        }
        List<Map<String, Object>> operations = new ArrayList<>();
        for (int ordinal = 0; ordinal < pcode.length; ordinal++) {
            operations.add(operation(pcode[ordinal], ordinal));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("address", coordinate(instruction.getAddress()));
        result.put("fallthrough_present", fallthrough != null);
        result.put("fallthrough", fallthrough == null ? null : coordinate(fallthrough));
        result.put("flow_targets", flows);
        result.put("data_references", dataReferences);
        Map<String, Object> flow = new LinkedHashMap<>();
        flow.put("is_flow", flowType.isFlow());
        flow.put("has_fallthrough", flowType.hasFallthrough());
        flow.put("is_call", flowType.isCall());
        flow.put("is_jump", flowType.isJump());
        flow.put("is_terminal", flowType.isTerminal());
        flow.put("is_computed", flowType.isComputed());
        flow.put("is_conditional", flowType.isConditional());
        flow.put("is_unconditional", flowType.isUnConditional());
        flow.put("is_override", flowType.isOverride());
        result.put("flow_type", flow);
        result.put("operations", operations);
        result.put("length", instruction.getLength());
        return result;
    }

    /** (X-1, design_x1 r2 part 2) the row's own override state, raw: Ghidra's
     *  instruction-level flow override, fallthrough override, length override
     *  and override-type references. A claim of the producer about itself
     *  (premise producer-override-report; TBR G1 attests the effect). Not
     *  {@code FlowType.isOverride()}, which describes the computed flow type. */
    private Map<String, Object> overrideEvidence(Instruction instruction) {
        List<Reference> overrides = new ArrayList<>();
        for (Reference reference : instruction.getReferencesFrom()) {
            if (reference.getReferenceType().isOverride() && reference.getToAddress() != null) {
                overrides.add(reference);
            }
        }
        overrides.sort(Comparator
            .comparing((Reference reference) -> spaceIdOf(reference.getToAddress()))
            .thenComparing(reference -> byteOffset(reference.getToAddress()))
            .thenComparing(reference -> reference.getReferenceType().getName())
            .thenComparing(reference -> reference.isPrimary()));
        List<Map<String, Object>> references = new ArrayList<>();
        for (Reference reference : overrides) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("address", coordinate(reference.getToAddress()));
            item.put("type", reference.getReferenceType().getName());
            // (TBR) an override reference takes effect only as the single primary one of its type
            item.put("primary", reference.isPrimary());
            references.add(item);
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("flow_override", instruction.getFlowOverride().name());
        result.put("fallthrough_overridden", instruction.isFallThroughOverridden());
        result.put("length_overridden", instruction.isLengthOverridden());
        result.put("override_references", references);
        return result;
    }

    private List<Map<String, Object>> sortedCoordinates(Set<Address> addresses) {
        List<Address> sorted = new ArrayList<>(addresses);
        sorted.sort(Comparator.comparing(GhidraV2BundleExport::spaceIdOf)
            .thenComparing(GhidraV2BundleExport::byteOffset));
        List<Map<String, Object>> result = new ArrayList<>();
        for (Address address : sorted) {
            result.add(coordinate(address));
        }
        return result;
    }

    private boolean isCommittedMemoryTarget(Address target) {
        MemoryBlock block = currentProgram.getMemory().getBlock(target);
        return block != null &&
            block.isLoaded() &&
            !block.getStart().getAddressSpace().isOverlaySpace() &&
            !block.isExternalBlock() &&
            block.getType() == MemoryBlockType.DEFAULT;
    }

    private static BigInteger spaceIdOf(Address address) {
        return spaceId(address.getAddressSpace());
    }

    private static Map<String, Object> operation(PcodeOp operation, int ordinal) {
        List<Map<String, Object>> inputs = new ArrayList<>();
        for (Varnode value : operation.getInputs()) {
            inputs.add(varnode(value));
        }
        Varnode output = operation.getOutput();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ordinal", ordinal);
        result.put("opcode", operation.getMnemonic());
        result.put("inputs", inputs);
        result.put("output_present", output != null);
        result.put("output", output == null ? null : varnode(output));
        return result;
    }

    private static Map<String, Object> varnode(Varnode value) {
        Address address = value.getAddress();
        AddressSpace space = address.getAddressSpace();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("kind_code", kindCode(space));
        result.put("space_id", spaceId(space));
        result.put("byte_offset", byteOffset(address));
        result.put("byte_size", u64(value.getSize(), "varnode size"));
        return result;
    }

    private static int kindCode(AddressSpace space) {
        boolean constant = space.isConstantSpace();
        boolean register = space.isRegisterSpace();
        boolean unique = space.isUniqueSpace();
        boolean memory = space.isMemorySpace();
        boolean loaded = space.isLoadedMemorySpace();
        boolean nonLoaded = space.isNonLoadedMemorySpace();
        boolean overlay = space.isOverlaySpace();
        boolean external = space.isExternalSpace();
        int classes = (constant ? 1 : 0) + (register ? 1 : 0) +
            (unique ? 1 : 0) + (memory ? 1 : 0);
        if (classes == 1 && !loaded && !nonLoaded && !overlay && !external) {
            if (constant) return 1;
            if (register) return 2;
            if (unique) return 3;
        }
        if (classes == 1 && memory && loaded && !nonLoaded && !overlay &&
                !external && !space.hasSignedOffset()) {
            return 4;
        }
        return 7;
    }

    private static Map<String, Object> writeJsonMember(String id, Path path, Object value) throws Exception {
        byte[] bytes = jsonBytes(value);
        writeFile(path, bytes);
        return member(id, path, BigInteger.valueOf(bytes.length), digest(bytes));
    }

    private static Map<String, Object> member(
            String id, Path path, BigInteger size, String sha256) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("id", id);
        result.put("path", path.getFileName().toString());
        result.put("size", size);
        result.put("sha256", sha256);
        return result;
    }

    private static byte[] jsonBytes(Object value) {
        return GSON.toJson(value).getBytes(StandardCharsets.UTF_8);
    }

    private static void writeFile(Path path, byte[] bytes) throws Exception {
        Files.write(path, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        forceFile(path);
    }

    private static void forceFile(Path path) throws Exception {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.WRITE)) {
            channel.force(true);
        }
    }

    private static void forceDirectory(Path path) throws Exception {
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ)) {
            channel.force(true);
        }
    }

    private static String digest(byte[] value) throws Exception {
        return hex(MessageDigest.getInstance("SHA-256").digest(value));
    }

    private static String hex(byte[] value) {
        StringBuilder result = new StringBuilder(value.length * 2);
        for (byte item : value) {
            result.append(String.format("%02x", item & 0xff));
        }
        return result.toString();
    }

    private static void deleteTree(Path root) throws IOException {
        try (var paths = Files.walk(root)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.deleteIfExists(path);
            }
        }
    }
}

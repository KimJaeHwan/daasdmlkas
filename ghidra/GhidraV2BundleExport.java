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

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
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
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;

public class GhidraV2BundleExport extends GhidraScript {
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
    private final AddressSet recoveredExceptionCode = new AddressSet();

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
        Path receiptPath;
        String receiptNonce;
        final List<Entry> entries = new ArrayList<>();
        final List<String> functionNames = new ArrayList<>();
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

    private static final class ObservedFunction {
        final AddressSet body;
        final Map<Address, Set<Address>> exceptionalTargets;

        ObservedFunction(AddressSet body, Map<Address, Set<Address>> exceptionalTargets) {
            this.body = body;
            this.exceptionalTargets = exceptionalTargets;
        }
    }

    @Override
    protected void run() throws Exception {
        Options options = parseOptions(getScriptArgs());
        exceptionRegions = captureExceptionRegions();
        analyzeRecoveredExceptionCode();
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
                functions = functionRows(
                    options, stage, members, profileSession, profileMember,
                    runtimeClasses(options));
            }

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
        List<Function> functions = selectFunctions(options.entries, options.functionNames);
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

    private List<Function> selectFunctions(List<Entry> entries, List<String> functionNames)
            throws Exception {
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

            Set<Function> selected = new LinkedHashSet<>(result);
            for (int index = 0; index < result.size(); index++) {
                monitor.checkCancelled();
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
                List<Function> closure = new ArrayList<>(closureSet);
                closure.removeIf(function ->
                    function.isExternal() || function.isThunk() ||
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
        return new ObservedFunction(body, exceptionalTargets);
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
        InstructionIterator iterator = currentProgram.getListing()
            .getInstructions(observed.body, true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = iterator.next();
            instructions.add(instruction(
                instruction,
                observed.exceptionalTargets.getOrDefault(
                    instruction.getAddress(), Set.of())));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("entry", coordinate(function.getEntryPoint()));
        result.put("instructions", instructions);
        return result;
    }

    private Map<String, Object> instruction(
            Instruction instruction, Set<Address> exceptionalTargets) {
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
        PcodeOp[] pcode = instruction.getPcode();
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

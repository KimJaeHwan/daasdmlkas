// Isolated Ghidra 12.0.4 call-naming capture; publication remains elsewhere.
import java.math.BigInteger; import java.nio.charset.StandardCharsets; import java.security.MessageDigest;
import java.util.ArrayList; import java.util.Arrays; import java.util.Comparator;
import java.util.HashMap; import java.util.LinkedHashMap; import java.util.List;
import java.util.Map; import java.util.TreeSet;
import ghidra.framework.Application; import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView; import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction; import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program; import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode; import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType; import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator; import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;
final class GhidraV2CallNaming {
    private static final String SCHEMA_ID = "tdo-v2-call-naming-sidecar-v1";
    private static final String MANIFEST_SCHEMA_ID = "tdo-v2-configured-bundle-manifest-v2";
    private static final String SEAL_SCHEMA_ID = "tdo-v2-configured-bundle-seal-v2";
    private static final String GHIDRA_VERSION = "12.0.4", COMPLETE = "COMPLETE";
    private static final String TARGET_DOMAIN = "tdo-v2-call-naming-target-v1";
    private static final String ROW_DOMAIN = "tdo-v2-call-naming-row-v1";
    private static final String CONTENT_DOMAIN = "tdo-v2-call-naming-content-v1";
    private static final int SCHEMA_VERSION = 1, EXPORTER_REVISION = 1, MAX_ROWS = 16_384;
    private static final int MAX_THUNK_EDGES = 64, MAX_TARGETS = MAX_THUNK_EDGES + 1;
    private static final int MAX_ALIASES = 16, MAX_SCANNED_SYMBOLS = 64, MAX_ALIAS_BYTES = 4_096;
    private static final long MAX_AGGREGATE_ALIAS_BYTES = 1024L * 1024L;
    private static final long MAX_MEMBER_BYTES = 64L * 1024L * 1024L, MAX_JSON_TOKENS = 8_388_608L;
    private static final long MAX_JSON_CONTAINERS = 1_048_576L, MAX_JSON_OBJECT_MEMBERS = 1_048_576L;
    private static final long MAX_JSON_ARRAY_ELEMENTS = 4_194_304L;
    private static final long MAX_JSON_DECODED_STRING_BYTES = 16L * 1024L * 1024L;
    private static final int MAX_JSON_DEPTH = 32, MAX_JSON_NUMERIC_BYTES = 20;
    private static final int MAX_JSON_RAW_STRING_BYTES = 24_576;
    private static final long DEADLINE_NANOS = 60L * 1_000_000_000L;
    private static final int CANCEL_INTERVAL = 64 * 1024;
    private static final BigInteger U64_LIMIT = BigInteger.ONE.shiftLeft(64);
    private GhidraV2CallNaming() { }
    static Map<String, Object> capture(
            Program program,
            Function function,
            TaskMonitor monitor,
            String exporterSourceSha256,
            String generationId,
            String manifestSchemaId,
            String sealSchemaId,
            String observationMemberId,
            String observationMemberSha256,
            BigInteger functionEntrySpaceId,
            BigInteger functionEntryByteOffset) throws Exception {
        return capture(program, function, monitor, exporterSourceSha256,
            generationId, manifestSchemaId, sealSchemaId, observationMemberId,
            observationMemberSha256, functionEntrySpaceId,
            functionEntryByteOffset, function.getBody());
    }
    static Map<String, Object> capture(
            Program program,
            Function function,
            TaskMonitor monitor,
            String exporterSourceSha256,
            String generationId,
            String manifestSchemaId,
            String sealSchemaId,
            String observationMemberId,
            String observationMemberSha256,
            BigInteger functionEntrySpaceId,
            BigInteger functionEntryByteOffset,
            AddressSetView observedBody) throws Exception {
        long started = System.nanoTime();
        require(program != null, "naming Program is required");
        require(function != null, "selected Function is required");
        require(monitor != null, "naming TaskMonitor is required");
        require(!program.isClosed(), "naming Program is closed");
        require(program.isLocked(), "naming Program must be locked");
        require(function.getProgram() == program, "selected Function is owned by another Program");
        require(!function.isDeleted(), "selected Function is deleted");
        require(observedBody != null && observedBody.contains(function.getEntryPoint()),
            "observed function body must contain its entry");
        require(GHIDRA_VERSION.equals(Application.getApplicationVersion()),
            "configured naming requires exact Ghidra 12.0.4");
        byte[] exporterDigest = digestBytes(exporterSourceSha256, "exporter source SHA-256");
        digestBytes(generationId, "generation ID");
        require(MANIFEST_SCHEMA_ID.equals(manifestSchemaId), "manifest schema ID changed");
        require(SEAL_SCHEMA_ID.equals(sealSchemaId), "seal schema ID changed");
        requireMemberId(observationMemberId);
        digestBytes(observationMemberSha256, "observation member SHA-256");
        BigInteger entrySpace = u64(functionEntrySpaceId, "function-entry space ID");
        BigInteger entryOffset = u64(functionEntryByteOffset, "function-entry byte offset");
        Coordinate selectedEntry = coordinate(function.getEntryPoint());
        require(selectedEntry.spaceId.equals(entrySpace) && selectedEntry.byteOffset.equals(entryOffset),
            "transport function entry does not equal the selected Function");
        CaptureState state = new CaptureState(monitor, started);
        state.check();
        Map<String, Object> transport = map(
            "generation_id", generationId,
            "manifest_schema_id", manifestSchemaId,
            "seal_schema_id", sealSchemaId,
            "observation_member_id", observationMemberId,
            "observation_member_sha256", observationMemberSha256,
            "function_entry", selectedEntry.json());
        List<Map<String, Object>> calls = new ArrayList<>();
        Map<String, Object> sizingRoot = root(exporterSourceSha256, transport, calls,
            "0000000000000000000000000000000000000000000000000000000000000000");
        state.reserveRoot(sizingRoot);
        InstructionIterator instructions = program.getListing().getInstructions(observedBody, true);
        RowKey previous = null;
        while (instructions.hasNext()) {
            state.check();
            Instruction instruction = instructions.next();
            PcodeOp[] operations = instruction.getPcode();
            for (int ordinal = 0; ordinal < operations.length; ordinal++) {
                state.check();
                PcodeOp operation = operations[ordinal];
                int opcodeValue = operation.getOpcode();
                if (opcodeValue != PcodeOp.CALL && opcodeValue != PcodeOp.CALLIND) {
                    continue;
                }
                state.check();
                require(calls.size() < MAX_ROWS, "naming call rows exceed their bound");
                Coordinate instructionCoordinate = coordinate(instruction.getAddress());
                RowKey key = new RowKey(instructionCoordinate, ordinal);
                require(previous == null || previous.compareTo(key) < 0,
                    "Ghidra call occurrences are not in canonical order");
                Row row = captureRow(program, state, instructionCoordinate, ordinal,
                    opcodeValue == PcodeOp.CALL ? "CALL" : "CALLIND", operation);
                state.reserveCall(row.json, calls.isEmpty());
                calls.add(row.json);
                previous = key;
            }
        }
        DigestSink content = DigestSink.sha256(state);
        content.text(CONTENT_DOMAIN);
        content.u64(SCHEMA_VERSION);
        content.u64(EXPORTER_REVISION);
        content.bytes(exporterDigest);
        content.text(GHIDRA_VERSION);
        content.text(COMPLETE);
        content.u64(calls.size());
        for (Map<String, Object> rowJson : calls) {
            state.check();
            encodeRowBody(content, rowJson);
            content.bytes(digestBytes((String)rowJson.get("row_digest"), "row digest"));
        }
        String contentDigest = content.finishHex();
        state.check();
        return root(exporterSourceSha256, transport, calls, contentDigest);
    }
    private static Row captureRow(Program program, CaptureState state, Coordinate instruction,
            int ordinal, String opcode, PcodeOp operation) throws Exception {
        Selector selector = operation.getNumInputs() == 0
            ? Selector.missing()
            : Selector.present(operation.getInput(0));
        List<Target> targets = new ArrayList<>();
        Resolution resolution;
        if ("CALLIND".equals(opcode)) {
            resolution = Resolution.indirect();
        }
        else if (!selector.present) {
            resolution = Resolution.unresolved("MISSING_SELECTOR", null);
        }
        else if (selector.kindCode == 7) {
            resolution = Resolution.unresolved("OPAQUE_SELECTOR", null);
        }
        else if (selector.kindCode != 4) {
            resolution = Resolution.unresolved("NON_ADDRESS_SELECTOR", null);
        }
        else {
            Function current = program.getFunctionManager().getFunctionAt(selector.address);
            if (current == null) {
                resolution = Resolution.unresolved("NO_EXACT_FUNCTION", null);
            }
            else {
                Map<Coordinate, Integer> seen = new HashMap<>();
                for (;;) {
                    require(current.getProgram() == program, "thunk target is owned by another Program");
                    require(!current.isDeleted(), "thunk target Function is deleted");
                    Coordinate currentCoordinate = coordinate(current.getEntryPoint());
                    require(!seen.containsKey(currentCoordinate), "repeated target reached before edge check");
                    state.check();
                    require(targets.size() < MAX_TARGETS, "naming targets exceed their bound");
                    Target target = captureTarget(program, state, current, targets.size());
                    targets.add(target);
                    seen.put(currentCoordinate, target.ordinal);
                    if (!target.thunk) {
                        resolution = Resolution.resolved(target.named(), target.ordinal);
                        break;
                    }
                    state.check();
                    if (targets.size() == MAX_TARGETS) {
                        resolution = Resolution.unresolved("THUNK_DEPTH_EXCEEDED", null);
                        break;
                    }
                    Function next = current.getThunkedFunction(false);
                    if (next == null) {
                        resolution = Resolution.unresolved("THUNK_TARGET_MISSING", null);
                        break;
                    }
                    Coordinate nextCoordinate = coordinate(next.getEntryPoint());
                    Integer cycleOrdinal = seen.get(nextCoordinate);
                    if (cycleOrdinal != null) {
                        resolution = Resolution.unresolved("THUNK_CYCLE", cycleOrdinal);
                        break;
                    }
                    current = next;
                }
            }
        }
        Map<String, Object> json = map(
            "instruction", instruction.json(),
            "operation_ordinal", BigInteger.valueOf(ordinal),
            "opcode", opcode,
            "selector", selector.json(),
            "resolution", resolution.json(),
            "targets", targetMaps(targets),
            "row_digest", "");
        DigestSink digest = DigestSink.sha256(state);
        digest.text(ROW_DOMAIN);
        encodeRowBody(digest, json);
        json.put("row_digest", digest.finishHex());
        return new Row(json);
    }
    private static Target captureTarget(Program program, CaptureState state,
            Function function, int ordinal) throws Exception {
        boolean external = function.isExternal();
        boolean thunk = function.isThunk();
        require(!(external && thunk), "external naming target cannot be a thunk");
        Address entry = function.getEntryPoint();
        TreeSet<Alias> aliases = new TreeSet<>(Alias.ORDER);
        SymbolIterator symbols = program.getSymbolTable().getSymbolsAsIterator(entry);
        int scanned = 0;
        while (symbols.hasNext()) {
            state.check();
            require(scanned < MAX_SCANNED_SYMBOLS, "symbols scanned for target exceed their bound");
            Symbol symbol = symbols.next();
            scanned++;
            SymbolType type = symbol.getSymbolType();
            if (symbol.isDeleted() || !entry.equals(symbol.getAddress()) ||
                    (type != SymbolType.FUNCTION && type != SymbolType.LABEL) ||
                    (type == SymbolType.FUNCTION && symbol.getObject() != function)) {
                continue;
            }
            Alias alias = Alias.symbol(sourceQuality(symbol.getSource()), symbol.getName());
            retainAlias(state, aliases, alias);
        }
        if (external) {
            ExternalLocation location = function.getExternalLocation();
            if (location != null) {
                String original = location.getOriginalImportedName();
                if (original != null) {
                    retainAlias(state, aliases, Alias.originalImport(original));
                }
            }
        }
        List<Alias> ordered = new ArrayList<>(aliases);
        Target target = new Target(ordinal, coordinate(entry), external, thunk, ordered, null);
        DigestSink digest = DigestSink.sha256(state);
        digest.text(TARGET_DOMAIN);
        encodeTargetBody(digest, target);
        target.digest = digest.finishHex();
        return target;
    }
    private static void retainAlias(CaptureState state, TreeSet<Alias> aliases, Alias alias)
            throws Exception {
        state.check();
        if (aliases.contains(alias)) {
            return;
        }
        require(aliases.size() < MAX_ALIASES, "naming aliases exceed their target bound");
        state.reserveAlias(alias.valueBytes.length);
        aliases.add(alias);
    }
    private static String sourceQuality(SourceType source) {
        require(source != null, "symbol source quality is missing");
        String value = source.name();
        require(value.equals("DEFAULT") || value.equals("ANALYSIS") || value.equals("AI") ||
            value.equals("IMPORTED") || value.equals("USER_DEFINED"),
            "symbol source quality is not recognized");
        return value;
    }
    private static void encodeRowBody(DigestSink sink, Map<String, Object> row) throws Exception {
        encodeCoordinate(sink, castMap(row.get("instruction")));
        sink.u64((BigInteger)row.get("operation_ordinal"));
        sink.text((String)row.get("opcode"));
        encodeSelector(sink, castMap(row.get("selector")));
        encodeResolution(sink, castMap(row.get("resolution")));
        List<Map<String, Object>> targets = castMapList(row.get("targets"));
        sink.u64(targets.size());
        for (Map<String, Object> target : targets) {
            encodeTargetBody(sink, target);
            sink.bytes(digestBytes((String)target.get("target_digest"), "target digest"));
        }
    }
    private static void encodeSelector(DigestSink sink, Map<String, Object> selector)
            throws Exception {
        if ("MISSING".equals(selector.get("state"))) {
            sink.tag(0);
            return;
        }
        sink.tag(1);
        sink.u64((BigInteger)selector.get("kind_code"));
        sink.u64((BigInteger)selector.get("space_id"));
        sink.u64((BigInteger)selector.get("byte_offset"));
        sink.u64((BigInteger)selector.get("byte_size"));
    }
    private static void encodeResolution(DigestSink sink, Map<String, Object> resolution)
            throws Exception {
        String state = (String)resolution.get("state");
        if (state.equals("INDIRECT")) {
            sink.tag(0);
        }
        else if (state.equals("UNRESOLVED")) {
            sink.tag(1);
            sink.text((String)resolution.get("reason"));
            Object cycle = resolution.get("cycle_target_ordinal");
            sink.tag(cycle == null ? 0 : 1);
            if (cycle != null) {
                sink.u64((BigInteger)cycle);
            }
        }
        else {
            sink.tag(state.equals("RESOLVED_NAMED") ? 2 : 3);
            sink.u64((BigInteger)resolution.get("terminal_target_ordinal"));
        }
    }
    private static void encodeTargetBody(DigestSink sink, Target target) throws Exception {
        sink.u64(target.ordinal);
        encodeCoordinate(sink, target.coordinate.json());
        sink.flag(target.external);
        sink.flag(target.thunk);
        sink.u64(target.aliases.size());
        for (Alias alias : target.aliases) {
            encodeAlias(sink, alias.json());
        }
    }
    private static void encodeTargetBody(DigestSink sink, Map<String, Object> target)
            throws Exception {
        sink.u64((BigInteger)target.get("target_ordinal"));
        encodeCoordinate(sink, castMap(target.get("coordinate")));
        sink.flag((Boolean)target.get("is_external"));
        sink.flag((Boolean)target.get("is_thunk"));
        List<Map<String, Object>> aliases = castMapList(target.get("aliases"));
        sink.u64(aliases.size());
        for (Map<String, Object> alias : aliases) {
            encodeAlias(sink, alias);
        }
    }
    private static void encodeAlias(DigestSink sink, Map<String, Object> alias) throws Exception {
        if ("SYMBOL".equals(alias.get("kind"))) {
            sink.tag(0);
            sink.text((String)alias.get("source_quality"));
            sink.text((String)alias.get("value"));
        }
        else {
            sink.tag(1);
            sink.text((String)alias.get("value"));
        }
    }
    private static void encodeCoordinate(DigestSink sink, Map<String, Object> value)
            throws Exception {
        sink.u64((BigInteger)value.get("space_id"));
        sink.u64((BigInteger)value.get("byte_offset"));
    }
    private static List<Map<String, Object>> targetMaps(List<Target> targets) {
        List<Map<String, Object>> result = new ArrayList<>(targets.size());
        for (Target target : targets) {
            result.add(target.json());
        }
        return result;
    }
    private static Map<String, Object> root(String exporterDigest, Map<String, Object> transport,
            List<Map<String, Object>> calls, String contentDigest) {
        return map(
            "schema_id", SCHEMA_ID,
            "schema_version", BigInteger.valueOf(SCHEMA_VERSION),
            "exporter_revision", BigInteger.valueOf(EXPORTER_REVISION),
            "exporter_source_sha256", exporterDigest,
            "ghidra_version", GHIDRA_VERSION,
            "transport", transport,
            "inventory_completeness", COMPLETE,
            "calls", calls,
            "semantic_content_digest", contentDigest);
    }
    private static Coordinate coordinate(Address address) {
        require(address != null, "naming coordinate address is missing");
        AddressSpace space = address.getAddressSpace();
        BigInteger capacity = BigInteger.valueOf(space.getAddressableUnitSize())
            .multiply(BigInteger.ONE.shiftLeft(space.getSize()));
        require(capacity.signum() > 0 && capacity.compareTo(U64_LIMIT) <= 0,
            "address-space byte capacity exceeds unsigned 64-bit");
        long raw = address.getUnsignedOffset();
        BigInteger offset = BigInteger.valueOf(raw & Long.MAX_VALUE);
        if (raw < 0) {
            offset = offset.setBit(63);
        }
        require(offset.compareTo(capacity) < 0, "address byte offset exceeds its space capacity");
        return new Coordinate(BigInteger.valueOf(Integer.toUnsignedLong(space.getSpaceID())), offset);
    }
    private static int kindCode(Varnode value) {
        require(value != null, "present naming selector is missing");
        AddressSpace space = value.getAddress().getAddressSpace();
        boolean constant = space.isConstantSpace();
        boolean register = space.isRegisterSpace();
        boolean unique = space.isUniqueSpace();
        boolean memory = space.isMemorySpace();
        boolean loaded = space.isLoadedMemorySpace();
        boolean nonLoaded = space.isNonLoadedMemorySpace();
        boolean overlay = space.isOverlaySpace();
        boolean external = space.isExternalSpace();
        int classes = (constant ? 1 : 0) + (register ? 1 : 0) + (unique ? 1 : 0) +
            (memory ? 1 : 0);
        if (classes == 1 && !loaded && !nonLoaded && !overlay && !external) {
            if (constant) return 1;
            if (register) return 2;
            if (unique) return 3;
        }
        if (classes == 1 && memory && loaded && !nonLoaded && !overlay && !external &&
                !space.hasSignedOffset()) return 4;
        return 7;
    }
    private static byte[] digestBytes(String value, String label) {
        require(value != null && value.length() == 64 && value.chars().allMatch(
            character -> character >= '0' && character <= '9' ||
                character >= 'a' && character <= 'f'),
            label + " must be 64 lowercase hexadecimal characters");
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) {
            result[index] = (byte)Integer.parseInt(value.substring(index * 2, index * 2 + 2), 16);
        }
        return result;
    }
    private static BigInteger u64(BigInteger value, String label) {
        require(value != null && value.signum() >= 0 && value.compareTo(U64_LIMIT) < 0,
            label + " must be unsigned 64-bit");
        return value;
    }
    private static void requireText(String value, String label) {
        require(value != null && !value.isEmpty(), label + " must be nonempty");
        strictUtf8(value, label);
    }
    private static void requireMemberId(String value) {
        require(value != null && value.length() >= 1 && value.length() <= 128,
            "observation member ID must contain 1 through 128 ASCII bytes");
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            boolean alnum = item >= 'A' && item <= 'Z' || item >= 'a' && item <= 'z' ||
                item >= '0' && item <= '9';
            require(alnum || index > 0 && (item == '.' || item == '_' || item == '-'),
                "observation member ID violates its ASCII grammar");
        }
    }
    private static byte[] strictUtf8(String value, String label) {
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            if (Character.isHighSurrogate(item)) {
                require(index + 1 < value.length() && Character.isLowSurrogate(value.charAt(index + 1)),
                    label + " must contain only Unicode scalar values");
                index++;
            }
            else {
                require(!Character.isLowSurrogate(item),
                    label + " must contain only Unicode scalar values");
            }
        }
        return value.getBytes(StandardCharsets.UTF_8);
    }
    private static void require(boolean condition, String message) {
        if (!condition) throw new IllegalArgumentException(message);
    }
    private static Map<String, Object> map(Object... values) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (int index = 0; index < values.length; index += 2) {
            result.put((String)values[index], values[index + 1]);
        }
        return result;
    }
    @SuppressWarnings("unchecked")
    private static Map<String, Object> castMap(Object value) { return (Map<String, Object>)value; }
    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> castMapList(Object value) {
        return (List<Map<String, Object>>)value; }
    private static JsonStats jsonStats(Object value, int depth) {
        if (value instanceof String text) {
            byte[] decoded = strictUtf8(text, "JSON string");
            long raw = 0;
            for (int index = 0; index < text.length(); index++) {
                int codePoint = text.codePointAt(index);
                if (Character.charCount(codePoint) == 2) index++;
                if (codePoint == '"' || codePoint == '\\' || codePoint == '\b' ||
                        codePoint == '\f' || codePoint == '\n' || codePoint == '\r' ||
                        codePoint == '\t') {
                    raw += 2;
                }
                else if (codePoint < 0x20 || codePoint == 0x2028 || codePoint == 0x2029) raw += 6;
                else if (codePoint <= 0x7f) raw++;
                else if (codePoint <= 0x7ff) raw += 2;
                else if (codePoint <= 0xffff) raw += 3;
                else raw += 4;
            }
            require(raw <= MAX_JSON_RAW_STRING_BYTES, "raw JSON string token exceeds its bound");
            return JsonStats.string(raw + 2, decoded.length, raw);
        }
        if (value instanceof BigInteger integer) {
            int bytes = u64(integer, "JSON integer").toString().length();
            require(bytes <= MAX_JSON_NUMERIC_BYTES, "JSON numeric token exceeds its bound");
            return JsonStats.scalar(bytes);
        }
        if (value instanceof Boolean bool) return JsonStats.scalar(bool ? 4 : 5);
        if (value instanceof Map<?, ?> object) {
            require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds its bound");
            JsonStats result = JsonStats.container(depth);
            boolean first = true;
            for (Map.Entry<?, ?> member : object.entrySet()) {
                require(member.getKey() instanceof String, "JSON object key is not text");
                JsonStats key = jsonStats(member.getKey(), depth);
                JsonStats item = jsonStats(member.getValue(), depth + 1);
                result.add(key).add(item);
                result.bytes += (first ? 0 : 1) + 1;
                result.tokens += (first ? 0 : 1) + 1;
                result.objectMembers++;
                first = false;
            }
            return result;
        }
        if (value instanceof List<?> array) {
            require(depth <= MAX_JSON_DEPTH, "JSON nesting exceeds its bound");
            JsonStats result = JsonStats.container(depth);
            for (int index = 0; index < array.size(); index++) {
                result.add(jsonStats(array.get(index), depth + 1));
                result.bytes += index == 0 ? 0 : 1;
                result.tokens += index == 0 ? 0 : 1;
                result.arrayElements++;
            }
            return result;
        }
        throw new IllegalArgumentException("non-JSON-compatible naming value");
    }
    private static long jsonBytes(Object value) { return jsonStats(value, 1).bytes; }
    private static final class JsonStats {
        long bytes, tokens, containers, objectMembers, arrayElements, decodedStringBytes;
        long maxRawStringBytes; int maxDepth;
        static JsonStats scalar(long bytes) {
            JsonStats result = new JsonStats(); result.bytes = bytes; result.tokens = 1; return result;
        }
        static JsonStats string(long bytes, long decoded, long raw) {
            JsonStats result = scalar(bytes); result.decodedStringBytes = decoded; result.maxRawStringBytes = raw;
            return result;
        }
        static JsonStats container(int depth) {
            JsonStats result = scalar(2); result.tokens = 2; result.containers = 1; result.maxDepth = depth;
            return result;
        }
        JsonStats add(JsonStats other) {
            bytes += other.bytes; tokens += other.tokens; containers += other.containers;
            objectMembers += other.objectMembers; arrayElements += other.arrayElements;
            decodedStringBytes += other.decodedStringBytes; maxRawStringBytes = Math.max(maxRawStringBytes,
                other.maxRawStringBytes);
            maxDepth = Math.max(maxDepth, other.maxDepth); return this;
        }
    }
    private static final class CaptureState {
        private final TaskMonitor monitor; private final long started;
        private long aggregateAliasBytes;
        private long memberBytes, jsonTokens, jsonContainers, jsonObjectMembers;
        private long jsonArrayElements, jsonDecodedStringBytes;
        CaptureState(TaskMonitor monitor, long started) { this.monitor = monitor; this.started = started; }
        void check() throws Exception {
            monitor.checkCancelled();
            require(System.nanoTime() - started <= DEADLINE_NANOS,
                "configured naming capture exceeded 60 seconds");
        }
        void reserveAlias(long count) {
            require(count > 0 && count <= MAX_ALIAS_BYTES, "naming alias violates its byte bound");
            require(count <= MAX_AGGREGATE_ALIAS_BYTES - aggregateAliasBytes,
                "aggregate naming alias bytes exceed their bound");
            aggregateAliasBytes += count;
        }
        void reserveRoot(Map<String, Object> root) { reserve(jsonStats(root, 1)); }
        void reserveCall(Map<String, Object> row, boolean first) {
            JsonStats added = jsonStats(row, 3);
            added.bytes += first ? 0 : 1; added.tokens += first ? 0 : 1;
            added.arrayElements++;
            reserve(added);
        }
        private void reserve(JsonStats added) {
            require(added.maxDepth <= MAX_JSON_DEPTH, "JSON nesting exceeds its bound");
            require(added.tokens <= MAX_JSON_TOKENS - jsonTokens, "JSON tokens exceed their bound");
            require(added.containers <= MAX_JSON_CONTAINERS - jsonContainers,
                "JSON containers exceed their bound");
            require(added.objectMembers <= MAX_JSON_OBJECT_MEMBERS - jsonObjectMembers,
                "JSON object members exceed their bound");
            require(added.arrayElements <= MAX_JSON_ARRAY_ELEMENTS - jsonArrayElements,
                "JSON array elements exceed their bound");
            require(added.decodedStringBytes <= MAX_JSON_DECODED_STRING_BYTES - jsonDecodedStringBytes,
                "decoded JSON string bytes exceed their bound");
            require(added.bytes <= MAX_MEMBER_BYTES - memberBytes,
                "naming member bytes exceed their bound");
            jsonTokens += added.tokens; jsonContainers += added.containers;
            jsonObjectMembers += added.objectMembers; jsonArrayElements += added.arrayElements;
            jsonDecodedStringBytes += added.decodedStringBytes; memberBytes += added.bytes;
        }
    }
    private static final class DigestSink {
        private final MessageDigest digest; private final CaptureState state;
        private DigestSink(MessageDigest digest, CaptureState state) {
            this.digest = digest; this.state = state;
        }
        static DigestSink sha256(CaptureState state) throws Exception {
            return new DigestSink(MessageDigest.getInstance("SHA-256"), state);
        }
        void write(byte[] bytes) throws Exception {
            for (int offset = 0; offset < bytes.length;) {
                state.check();
                int count = Math.min(CANCEL_INTERVAL, bytes.length - offset);
                digest.update(bytes, offset, count);
                offset += count;
            }
        }
        void tag(int value) throws Exception { write(new byte[] {(byte)value}); }
        void flag(boolean value) throws Exception { tag(value ? 1 : 0); }
        void u64(long value) throws Exception {
            require(value >= 0, "canonical integer is negative");
            u64(BigInteger.valueOf(value));
        }
        void u64(BigInteger value) throws Exception {
            value = GhidraV2CallNaming.u64(value, "canonical integer");
            byte[] result = new byte[8];
            byte[] encoded = value.toByteArray();
            int source = encoded.length > 8 ? 1 : 0;
            int count = encoded.length - source;
            System.arraycopy(encoded, source, result, result.length - count, count);
            write(result);
        }
        void bytes(byte[] value) throws Exception { u64(value.length); write(value); }
        void text(String value) throws Exception {
            requireText(value, "canonical text");
            bytes(strictUtf8(value, "canonical text"));
        }
        String finishHex() {
            byte[] value = digest.digest();
            StringBuilder result = new StringBuilder(64);
            for (byte item : value) {
                result.append(String.format("%02x", item & 0xff));
            }
            return result.toString();
        }
    }
    private static final class Coordinate {
        final BigInteger spaceId, byteOffset;
        Coordinate(BigInteger spaceId, BigInteger byteOffset) {
            this.spaceId = u64(spaceId, "coordinate space ID"); this.byteOffset = u64(byteOffset,
                "coordinate byte offset");
        }
        Map<String, Object> json() { return map("space_id", spaceId, "byte_offset", byteOffset); }
        @Override
        public boolean equals(Object other) {
            return other instanceof Coordinate coordinate &&
                spaceId.equals(coordinate.spaceId) && byteOffset.equals(coordinate.byteOffset);
        }
        @Override
        public int hashCode() { return 31 * spaceId.hashCode() + byteOffset.hashCode(); }
    }
    private static final class RowKey implements Comparable<RowKey> {
        final Coordinate instruction; final int ordinal;
        RowKey(Coordinate instruction, int ordinal) { this.instruction = instruction; this.ordinal = ordinal; }
        @Override
        public int compareTo(RowKey other) {
            int result = instruction.spaceId.compareTo(other.instruction.spaceId);
            if (result == 0) {
                result = instruction.byteOffset.compareTo(other.instruction.byteOffset);
            }
            return result != 0 ? result : Integer.compare(ordinal, other.ordinal);
        }
    }
    private static final class Selector {
        final boolean present; final int kindCode; final Address address;
        final Coordinate coordinate; final BigInteger size;
        private Selector(boolean present, int kindCode, Address address,
                Coordinate coordinate, BigInteger size) {
            this.present = present; this.kindCode = kindCode; this.address = address;
            this.coordinate = coordinate; this.size = size;
        }
        static Selector missing() { return new Selector(false, 0, null, null, null); }
        static Selector present(Varnode value) {
            int size = value.getSize();
            require(size > 0, "present naming selector must have positive byte size");
            return new Selector(true, kindCode(value), value.getAddress(),
                coordinate(value.getAddress()), BigInteger.valueOf(size));
        }
        Map<String, Object> json() {
            return present
                ? map("state", "PRESENT", "kind_code", BigInteger.valueOf(kindCode),
                    "space_id", coordinate.spaceId, "byte_offset", coordinate.byteOffset,
                    "byte_size", size)
                : map("state", "MISSING");
        }
    }
    private static final class Alias {
        static final Comparator<Alias> ORDER = (left, right) -> {
            int result = Integer.compare(left.symbol ? 0 : 1, right.symbol ? 0 : 1);
            if (result == 0 && left.symbol) {
                result = left.quality.compareTo(right.quality);
            }
            if (result == 0) {
                result = Arrays.compareUnsigned(left.valueBytes, right.valueBytes);
            }
            return result;
        };
        final boolean symbol; final String quality, value; final byte[] valueBytes;
        private Alias(boolean symbol, String quality, String value) {
            requireText(value, "naming alias");
            this.symbol = symbol; this.quality = quality; this.value = value;
            this.valueBytes = strictUtf8(value, "naming alias");
            require(valueBytes.length <= MAX_ALIAS_BYTES, "naming alias exceeds its byte bound");
        }
        static Alias symbol(String quality, String value) { return new Alias(true, quality, value); }
        static Alias originalImport(String value) { return new Alias(false, null, value); }
        Map<String, Object> json() {
            return symbol
                ? map("kind", "SYMBOL", "source_quality", quality, "value", value)
                : map("kind", "ORIGINAL_IMPORT", "value", value);
        }
    }
    private static final class Target {
        final int ordinal; final Coordinate coordinate; final boolean external, thunk;
        final List<Alias> aliases; String digest;
        Target(int ordinal, Coordinate coordinate, boolean external, boolean thunk,
                List<Alias> aliases, String digest) {
            this.ordinal = ordinal; this.coordinate = coordinate; this.external = external;
            this.thunk = thunk; this.aliases = aliases; this.digest = digest;
        }
        boolean named() {
            for (Alias alias : aliases) {
                if (!alias.symbol || !alias.quality.equals("DEFAULT")) {
                    return true;
                }
            }
            return false;
        }
        Map<String, Object> json() {
            List<Map<String, Object>> aliasMaps = new ArrayList<>(aliases.size());
            for (Alias alias : aliases) {
                aliasMaps.add(alias.json());
            }
            return map(
                "target_ordinal", BigInteger.valueOf(ordinal),
                "coordinate", coordinate.json(),
                "is_external", external,
                "is_thunk", thunk,
                "aliases", aliasMaps,
                "target_digest", digest);
        }
    }
    private static final class Resolution {
        final String state, reason; final Integer terminal, cycle;
        private Resolution(String state, String reason, Integer terminal, Integer cycle) {
            this.state = state; this.reason = reason; this.terminal = terminal; this.cycle = cycle;
        }
        static Resolution indirect() { return new Resolution("INDIRECT", null, null, null); }
        static Resolution unresolved(String reason, Integer cycle) {
            return new Resolution("UNRESOLVED", reason, null, cycle); }
        static Resolution resolved(boolean named, int terminal) {
            return new Resolution(named ? "RESOLVED_NAMED" : "RESOLVED_UNNAMED",
                null, terminal, null);
        }
        Map<String, Object> json() {
            if (state.equals("INDIRECT")) {
                return map("state", state);
            }
            if (state.equals("UNRESOLVED")) {
                return cycle == null
                    ? map("state", state, "reason", reason)
                    : map("state", state, "reason", reason,
                        "cycle_target_ordinal", BigInteger.valueOf(cycle));
            }
            return map("state", state,
                "terminal_target_ordinal", BigInteger.valueOf(terminal));
        }
    }
    private static final class Row {
        final Map<String, Object> json;
        Row(Map<String, Object> json) { this.json = json; }
    }
}

// Stack-switch scan of a whole program, read-only (X-1, design_x1 r2 part 4 as amended by r3 / r4.1).
//
// The routine behind GhidraV2StackSwitchScan (standalone) and GhidraV2BundleExport (inside the export session,
// on the locked program, no transaction -- design_x1 r3 4.1). One scan computes two verdicts:
//
//   s3-off  today's conservative v4 rule, byte for byte (the same code path with every S3 switch off);
//   s3-on   the S3-aware transfer of design_x1 r3 4.4 / r4: every register and unique location reads UNKNOWN at
//           every seed (function entries included) and at every cross-region destination of a non-call transfer
//           (entry or mid-body); kernel transfers are classified by their bytes (r3 4.3 / r4 4.3) -- a covered
//           candidate (unprefixed 0F 05 / CD 2E) keeps only the stack pointer, a trap row (CC / CD 03 / CD 29 /
//           0F 0B) ends its path (resolved per site by the consuming run), every other kernel transfer, an
//           undecidable form, a row whose length disagrees with its form, a lift that is empty or contradicts
//           the bytes, a stack-pointer access inside a covered row and an unbounded indirect jump are UNCHECKED.
//
// A clean s3-on verdict is conditional: every listed covered row must be an admitted S3 site of the run and every
// trap row must carry the run's own decision (the consumer rule, tdo_v2.stack_evidence.authority).
//
// The listing digest (r4 4.2) has a verifiable part -- the exported rows (coordinates, lengths, bytes, override
// facts) -- that TDO recomputes from the sealed Bundle, and an attested part over everything else the scan read.

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;

public class GhidraV2StackSwitchScanner {
    // keep equal to tdo_v2.stack_evidence.DETECTORS[-1] / DETECTOR_V5
    public static final String DETECTOR = "stack-switch-coefficient-v5";
    public static final String V4_DETECTOR = "stack-switch-coefficient-v4";
    public static final String LEGACY_DETECTOR = "stack-switch-coefficient-v3";
    public static final List<String> EXCEPTIONS = List.of("loaded-and-call-result-values-hold-no-stack-pointer",
        "user-ops-change-only-their-output");
    // (r4.1, Fable r4 P2-1) the s3-off reading of entry registers, named in the v5 evidence
    public static final List<String> V5_OFF_EXCEPTIONS = List.of(
        "loaded-and-call-result-values-hold-no-stack-pointer", "user-ops-change-only-their-output",
        "entry-registers-hold-no-stack-derived-value");
    // under s3-on the user-op exception still covers every non-kernel CALLOTHER (r2 F-P3-2)
    public static final List<String> V5_ON_EXCEPTIONS = List.of(
        "loaded-and-call-result-values-hold-no-stack-pointer", "non-kernel-user-ops-change-only-their-output");
    public static final List<String> LEGACY_EXCEPTIONS = List.of(
        "loaded-and-call-result-values-hold-no-stack-pointer", "user-ops-change-only-their-output",
        "calls-preserve-the-common-nonvolatile-registers");
    private static final long MAX_STACK_ALIGNMENT = 1L << 12;
    private static final Integer UNKNOWN = null;
    private static final Set<Integer> BOOLEAN = Set.of(
        PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS,
        PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY,
        PcodeOp.INT_SBORROW, PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR,
        PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_NOTEQUAL, PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESSEQUAL,
        PcodeOp.FLOAT_NAN);
    private static final List<String> X86_64_PRESERVED = List.of("RBX", "RBP", "R12", "R13", "R14", "R15");
    private static final List<String> X86_32_PRESERVED = List.of("EBX", "EBP", "ESI", "EDI");
    private static final Set<Integer> LEGACY_PREFIXES = Set.of(
        0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65);
    private static final int MAX_INSTRUCTION_BYTES = 15;

    /** A storage location: address space, offset, size. */
    record Loc(int space, long offset, int size) {
        boolean overlaps(Loc other) {
            return space == other.space && offset < other.offset + other.size && other.offset < offset + size;
        }
    }

    // coefficient-state defaults, not storage locations: an unmentioned register
    // (and, under s3-on, an unmentioned unique location) reads UNKNOWN
    private static final Loc UNKNOWN_REGISTERS = new Loc(Integer.MIN_VALUE, 0, 0);
    private static final Loc UNKNOWN_UNIQUES = new Loc(Integer.MIN_VALUE, 1, 0);

    /** One p-code operation of a scanned region: (instruction, ordinal). */
    record Node(Address instruction, int ordinal) {}

    /** (r3 4.3) a kernel-transfer row by its bytes. */
    record Kernel(String kind, String vector, int formLength, String bytes) {}

    private final Program program;
    private final TaskMonitor monitor;
    private final boolean conservative;
    private final Loc stack;
    private final int uniqueSpace;
    private final List<Loc> preserved = new ArrayList<>();
    private final List<String> preservedNames;
    private final Register sp;

    // per pass
    private boolean s3on;
    private Map<Address, Kernel> kernels = Map.of();
    private Map<Address, String> kernelCauses = Map.of();   // kernel row -> why UNCHECKED (absent: resolved)
    private Set<Address> crossTargets = Set.of();
    private boolean everyRowSeeded;
    private Map<Node, String> causes = new HashMap<>();

    public GhidraV2StackSwitchScanner(Program program, TaskMonitor monitor, boolean conservative) {
        this.program = program;
        this.monitor = monitor;
        this.conservative = conservative;
        sp = program.getCompilerSpec().getStackPointer();
        stack = loc(new Varnode(sp.getAddress(), sp.getMinimumByteSize()));
        uniqueSpace = program.getAddressFactory().getUniqueSpace().getSpaceID();
        String language = program.getLanguageID().getIdAsString();
        preservedNames = conservative ? List.of() : language.startsWith("x86:LE:64") ? X86_64_PRESERVED
            : language.startsWith("x86:LE:32") ? X86_32_PRESERVED : List.of();
        for (String name : preservedNames) {
            Register register = program.getRegister(name);
            preserved.add(loc(new Varnode(register.getAddress(), register.getMinimumByteSize())));
        }
    }

    static Loc loc(Varnode varnode) {
        return new Loc(varnode.getSpace(), varnode.getOffset(), varnode.getSize());
    }

    /** The v1 evidence of today's standalone scan (detector v4 or legacy v3), unchanged. */
    public Map<String, Object> legacyEvidence(String expectedSha256) throws Exception {
        s3on = false;
        List<Map<String, Object>> switches = new ArrayList<>();
        long[] counts = scanProgram(switches);
        Map<String, Object> evidence = header(1, conservative ? V4_DETECTOR : LEGACY_DETECTOR, expectedSha256);
        evidence.put("functions_scanned", counts[0]);
        evidence.put("instructions_scanned", counts[1]);
        evidence.put("instructions_outside_functions", counts[2]);
        evidence.put("switches", switches);
        evidence.put("call_preserved", preservedNames);
        evidence.put("exceptions", conservative ? EXCEPTIONS : LEGACY_EXCEPTIONS);
        return evidence;
    }

    /** (X-1) the v2 evidence: both verdicts, the kernel-transfer rows and the listing digest.
     *  {@code exported}: the exported map (function entry -> its rows) when called by the exporter, else
     *  null (an unbound scan: s3-off only for its consumers). */
    public Map<String, Object> evidence(String expectedSha256, Map<Address, List<Address>> exported)
            throws Exception {
        if (!conservative) {
            throw new IllegalStateException("v2 stack evidence is conservative only");
        }
        s3on = false;
        List<Map<String, Object>> off = new ArrayList<>();
        long[] counts = scanProgram(off);
        s3on = true;
        // (Astra X-1a r1 P1-4) the byte classifier is x86-64's; another language
        // has no kernel-transfer rows here and its consumer reads s3-on as
        // inapplicable only through the sealed PE predicate (tdo_v2.stack_evidence)
        boolean x86 = program.getLanguageID().getIdAsString().startsWith("x86:LE:64");
        kernels = x86 ? classifyKernels() : Map.of();
        kernelCauses = validateKernels();   // (r1 P2-1: the whole row, before propagation)
        crossTargets = new LinkedHashSet<>();
        List<Map<String, Object>> on = new ArrayList<>();
        List<Map<String, Object>> unbounded = new ArrayList<>();
        collectCrossTargets(unbounded);
        scanProgram(on);
        on.addAll(unbounded);
        // (r4 4.8, Astra r1 P2-4 / Fable r1 P2-3) the other reading of an
        // unbounded transfer: every instruction start a destination (measured,
        // the owner chooses before S3)
        everyRowSeeded = true;
        List<Map<String, Object>> fallback = new ArrayList<>();
        scanProgram(fallback);
        everyRowSeeded = false;
        s3on = false;

        Map<String, Object> evidence = header(2, DETECTOR, expectedSha256);
        evidence.put("functions_scanned", counts[0]);
        evidence.put("instructions_scanned", counts[1]);
        evidence.put("instructions_outside_functions", counts[2]);
        Map<String, Object> stackPointer = new LinkedHashMap<>();
        stackPointer.put("space_id", sp.getAddress().getAddressSpace().getSpaceID());
        stackPointer.put("byte_offset", sp.getAddress().getOffset());
        stackPointer.put("size", sp.getMinimumByteSize());
        evidence.put("stack_pointer_coordinate", stackPointer);
        Map<String, Object> policies = new LinkedHashMap<>();
        Map<String, Object> offPolicy = new LinkedHashMap<>();
        offPolicy.put("switches", off);
        offPolicy.put("exceptions", V5_OFF_EXCEPTIONS);
        policies.put("s3-off", offPolicy);
        Map<String, Object> onPolicy = new LinkedHashMap<>();
        onPolicy.put("switches", on);
        onPolicy.put("exceptions", V5_ON_EXCEPTIONS);
        onPolicy.put("kernel_transfers", kernelRows(exported));
        onPolicy.put("language_x86_64", x86);
        onPolicy.put("fallback_switches", fallback);
        policies.put("s3-on", onPolicy);
        evidence.put("policies", policies);
        evidence.put("bound", exported != null);
        evidence.put("listing_digest", listingDigest(program, exported, null, monitor));
        return evidence;
    }

    private Map<String, Object> header(int version, String detector, String expectedSha256) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("format", "tdo-v2-stack-switch-evidence");
        evidence.put("version", version);
        evidence.put("detector", detector);
        evidence.put("executable_sha256", expectedSha256);
        evidence.put("program", program.getDomainFile().getPathname());
        evidence.put("language", program.getLanguageID().getIdAsString());
        evidence.put("stack_pointer", sp.getName());
        return evidence;
    }

    /** Every function, then every instruction outside functions: {functions, instructions, outside}. */
    private long[] scanProgram(List<Map<String, Object>> switches) throws Exception {
        Listing listing = program.getListing();
        long functions = 0, instructions = 0;
        FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
        while (iterator.hasNext()) {
            monitor.checkCancelled();
            Function function = iterator.next();
            if (function.isExternal()) {
                continue;
            }
            functions++;
            instructions += scan(function.getEntryPoint(), function.getBody(), function.getName(true), listing,
                switches);
        }
        AddressSet outside = outsideFunctions(listing);
        long outsideCount = outside.isEmpty() ? 0 : scan(null, outside, "(outside functions)", listing, switches);
        return new long[] {functions, instructions + outsideCount, outsideCount};
    }

    private AddressSet outsideFunctions(Listing listing) {
        AddressSet outside = new AddressSet();
        InstructionIterator all = listing.getInstructions(true);
        while (all.hasNext()) {
            Instruction instruction = all.next();
            if (program.getFunctionManager().getFunctionContaining(instruction.getAddress()) == null) {
                outside.add(instruction.getMinAddress(), instruction.getMaxAddress());
            }
        }
        return outside;
    }

    /** Must analysis over a region's p-code operations; returns its instruction count. */
    private long scan(Address entry, AddressSetView body, String name, Listing listing,
            List<Map<String, Object>> switches) throws Exception {
        Map<Address, PcodeOp[]> pcode = new LinkedHashMap<>();
        Map<Address, Instruction> rows = new HashMap<>();
        for (Instruction instruction : listing.getInstructions(body, true)) {
            pcode.put(instruction.getAddress(), instruction.getPcode());
            rows.put(instruction.getAddress(), instruction);
        }
        Map<Node, Map<Loc, Integer>> in = new HashMap<>();
        Set<Node> unchecked = new LinkedHashSet<>();
        causes = new HashMap<>();
        Deque<Node> pending = new ArrayDeque<>();
        List<Address> starts = new ArrayList<>();
        if (entry != null) {
            starts.add(entry);
        }
        starts.addAll(pcode.keySet());
        for (Address start : starts) {
            if (!pcode.containsKey(start) || (start != entry && reached(start, in, pcode))) {
                continue;
            }
            seed(start, entry != null && start.equals(entry), in, pending, pcode, rows);
            propagate(in, pending, pcode, rows, unchecked);
        }
        if (s3on) {
            // (r4 4.4) every cross-region destination of a non-call transfer in
            // this region merges the unknown state, entry or mid-body: the merge
            // re-enters the worklist, so a row reached from the normal entry is
            // re-decided
            for (Address start : pcode.keySet()) {
                if (everyRowSeeded || crossTargets.contains(start)) {
                    seed(start, false, in, pending, pcode, rows);
                }
                // (Astra X-1a r1 P2-3) the row after a resolved trap gets its
                // unknown seed even when another predecessor reached it
                Kernel kernel = kernels.get(start);
                if (kernel != null && "trap".equals(kernel.kind()) && !kernelCauses.containsKey(start)) {
                    Address next = rows.get(start).getFallThrough();
                    if (next == null) {
                        next = start.add(rows.get(start).getLength());
                    }
                    if (pcode.containsKey(next)) {
                        seed(next, false, in, pending, pcode, rows);
                    }
                }
            }
            propagate(in, pending, pcode, rows, unchecked);
            for (Address address : pcode.keySet()) {
                // (r1 P2-1) a kernel row decided UNCHECKED before propagation,
                // reached or not, and an empty lift too
                String cause = kernels.containsKey(address) ? kernelCauses.get(address) : null;
                if (cause != null) {
                    Node node = new Node(address, 0);
                    unchecked.add(node);
                    causes.put(node, cause);
                }
            }
        }
        Set<Node> reported = new HashSet<>();
        for (Map.Entry<Node, Map<Loc, Integer>> row : in.entrySet()) {
            Node node = row.getKey();
            PcodeOp op = pcode.get(node.instruction())[node.ordinal()];
            Varnode out = op.getOutput();
            if (out != null && (out.isRegister() || out.isUnique())) {
                Loc key = loc(out);
                Integer value = coefficient(op, new HashMap<>(row.getValue()));
                if (key.overlaps(stack) && !(key.equals(stack) && Integer.valueOf(1).equals(value))) {
                    report(switches, reported, node, op.getMnemonic(), name, rows, s3on ? "value" : null);
                }
            }
        }
        for (Node node : unchecked) {
            report(switches, reported, node, "UNCHECKED", name, rows, s3on ? causes.getOrDefault(node, "unchecked")
                : null);
        }
        return pcode.size();
    }

    private void seed(Address start, boolean functionEntry, Map<Node, Map<Loc, Integer>> in, Deque<Node> pending,
            Map<Address, PcodeOp[]> pcode, Map<Address, Instruction> rows) {
        List<Node> seeds = new ArrayList<>();
        addInstruction(seeds, start, pcode, rows);
        for (Node seed : seeds) {
            Map<Loc, Integer> state = initialState(functionEntry);
            Map<Loc, Integer> known = in.get(seed);
            if (known == null) {
                in.put(seed, state);
                pending.add(seed);
            }
            else if (s3on) {
                Map<Loc, Integer> merged = merge(known, state);
                if (!merged.equals(known)) {
                    in.put(seed, merged);
                    pending.add(seed);
                }
            }
        }
    }

    private Map<Loc, Integer> initialState(boolean functionEntry) {
        Map<Loc, Integer> state = new HashMap<>();
        state.put(stack, 1);
        if (s3on) {   // (r3 4.4 / r4.1) every seed, entries included
            state.put(UNKNOWN_REGISTERS, UNKNOWN);
            state.put(UNKNOWN_UNIQUES, UNKNOWN);
        }
        else if (conservative && !functionEntry) {
            state.put(UNKNOWN_REGISTERS, UNKNOWN);
        }
        return state;
    }

    /** (r3 4.4) the state after a covered candidate or an unchecked kernel row: only the stack pointer kept. */
    private Map<Loc, Integer> kernelState() {
        Map<Loc, Integer> state = new HashMap<>();
        state.put(stack, 1);
        state.put(UNKNOWN_REGISTERS, UNKNOWN);
        state.put(UNKNOWN_UNIQUES, UNKNOWN);
        return state;
    }

    private static void report(List<Map<String, Object>> switches, Set<Node> reported, Node node, String opcode,
            String name, Map<Address, Instruction> rows, String cause) {
        if (!reported.add(node)) {
            return;
        }
        Map<String, Object> found = new LinkedHashMap<>();
        found.put("function", name);
        found.put("instruction", node.instruction().toString());
        found.put("ordinal", node.ordinal());
        found.put("opcode", opcode);
        found.put("text", rows.get(node.instruction()).toString());
        if (cause != null) {
            found.put("cause", cause);
        }
        switches.add(found);
    }

    private static boolean reached(Address address, Map<Node, Map<Loc, Integer>> in, Map<Address, PcodeOp[]> pcode) {
        PcodeOp[] ops = pcode.get(address);
        for (int ordinal = 0; ordinal < ops.length; ordinal++) {
            if (in.containsKey(new Node(address, ordinal))) {
                return true;
            }
        }
        return false;
    }

    private Integer read(Map<Loc, Integer> state, Varnode varnode) {
        if (varnode.isConstant()) {
            return 0;
        }
        return readLocation(state, loc(varnode));
    }

    private Integer readLocation(Map<Loc, Integer> state, Loc key) {
        if (state.containsKey(key)) {
            return state.get(key);
        }
        boolean zeroCovered = false;
        for (Map.Entry<Loc, Integer> row : state.entrySet()) {
            if (row.getKey().overlaps(key) && !Integer.valueOf(0).equals(row.getValue())) {
                return UNKNOWN;
            }
            if (Integer.valueOf(0).equals(row.getValue()) && row.getKey().space() == key.space() &&
                    row.getKey().offset() <= key.offset() &&
                    key.offset() + key.size() <= row.getKey().offset() + row.getKey().size()) {
                zeroCovered = true;
            }
        }
        if (conservative && key.space() == stack.space() && state.containsKey(UNKNOWN_REGISTERS) &&
                !zeroCovered) {
            return UNKNOWN;
        }
        if (s3on && key.space() == uniqueSpace && state.containsKey(UNKNOWN_UNIQUES) && !zeroCovered) {
            return UNKNOWN;
        }
        return 0;
    }

    private void write(Map<Loc, Integer> state, Loc key, Integer value) {
        for (Loc other : new ArrayList<>(state.keySet())) {
            if (!other.overlaps(key)) {
                continue;
            }
            boolean covered = key.offset() <= other.offset() &&
                other.offset() + other.size() <= key.offset() + key.size();
            if (covered) {
                state.remove(other);
            }
            else {
                state.put(other, UNKNOWN);
            }
        }
        if (conservative || !Integer.valueOf(0).equals(value)) {
            state.put(key, value);
        }
        else {
            state.remove(key);
        }
    }

    /** The output's stack coefficient: 1, 0, or null (unknown). */
    private Integer coefficient(PcodeOp op, Map<Loc, Integer> state) {
        int opcode = op.getOpcode();
        if (conservative && (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND)) {
            return UNKNOWN;
        }
        Varnode[] inputs = op.getInputs();
        List<Integer> values = new ArrayList<>();
        for (Varnode input : inputs) {
            values.add(read(state, input));
        }
        if (opcode == PcodeOp.COPY && !values.isEmpty()) {
            return values.get(0);
        }
        if ((opcode == PcodeOp.INT_ADD || opcode == PcodeOp.INT_SUB) && values.size() == 2) {
            if (values.get(0) == null || values.get(1) == null) {
                return UNKNOWN;
            }
            int total = opcode == PcodeOp.INT_ADD ? values.get(0) + values.get(1) : values.get(0) - values.get(1);
            return total == 0 || total == 1 ? Integer.valueOf(total) : UNKNOWN;
        }
        if (opcode == PcodeOp.INT_AND && values.size() == 2) {
            for (int index = 0; index < 2; index++) {
                Varnode mask = inputs[1 - index];
                if (mask.isConstant() && values.get(index) != null) {
                    if (values.get(index) == 0) {
                        return 0;
                    }
                    int bits = 8 * mask.getSize();
                    long low = bits >= 64 ? -mask.getOffset() : (1L << bits) - mask.getOffset();
                    boolean alignment = low > 0 && low <= MAX_STACK_ALIGNMENT && (low & (low - 1)) == 0;
                    return alignment ? Integer.valueOf(1) : UNKNOWN;
                }
            }
        }
        if (opcode == PcodeOp.LOAD || BOOLEAN.contains(opcode)) {
            return 0;
        }
        for (Integer value : values) {
            if (!Integer.valueOf(0).equals(value)) {
                return UNKNOWN;
            }
        }
        return 0;
    }

    private void afterCall(Map<Loc, Integer> state) {
        state.keySet().removeIf(key -> key.space() == stack.space() && !key.equals(stack) &&
            (conservative || preserved.stream().noneMatch(kept -> key.offset() >= kept.offset() &&
                key.offset() + key.size() <= kept.offset() + kept.size())));
        if (conservative) {
            state.put(UNKNOWN_REGISTERS, UNKNOWN);
        }
    }

    private Map<Loc, Integer> merge(Map<Loc, Integer> known, Map<Loc, Integer> state) {
        Map<Loc, Integer> merged = new HashMap<>();
        if (conservative && (known.containsKey(UNKNOWN_REGISTERS) || state.containsKey(UNKNOWN_REGISTERS))) {
            merged.put(UNKNOWN_REGISTERS, UNKNOWN);
        }
        if (s3on && (known.containsKey(UNKNOWN_UNIQUES) || state.containsKey(UNKNOWN_UNIQUES))) {
            merged.put(UNKNOWN_UNIQUES, UNKNOWN);
        }
        Set<Loc> keys = new HashSet<>(known.keySet());
        keys.addAll(state.keySet());
        keys.remove(UNKNOWN_REGISTERS);
        keys.remove(UNKNOWN_UNIQUES);
        for (Loc key : keys) {
            Integer left = conservative ? readLocation(known, key) : known.getOrDefault(key, 0);
            Integer right = conservative ? readLocation(state, key) : state.getOrDefault(key, 0);
            Integer value = Objects.equals(left, right) ? left : UNKNOWN;
            if (conservative || !Integer.valueOf(0).equals(value)) {
                merged.put(key, value);
            }
        }
        return merged;
    }

    private void propagate(Map<Node, Map<Loc, Integer>> in, Deque<Node> pending, Map<Address, PcodeOp[]> pcode,
            Map<Address, Instruction> rows, Set<Node> unchecked) throws Exception {
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            Node node = pending.removeFirst();
            PcodeOp[] ops = pcode.get(node.instruction());
            PcodeOp op = ops[node.ordinal()];
            Map<Loc, Integer> state = new HashMap<>(in.get(node));
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                afterCall(state);
            }
            Varnode out = op.getOutput();
            if (out != null && (out.isRegister() || out.isUnique())) {
                Loc key = loc(out);
                write(state, key, key.overlaps(stack) ? Integer.valueOf(1) : coefficient(op, state));
                if (key.overlaps(stack)) {
                    write(state, stack, 1);
                }
            }
            // (r3 4.4; Astra X-1a r1 P2-1) a kernel row acts as a whole: every
            // edge leaving the row -- from its last operation or an early branch --
            // carries the post-kernel state (only the stack pointer kept), or
            // none at a resolved trap (the path ends there); its cause was
            // decided before propagation (validateKernels)
            Kernel kernel = s3on ? kernels.get(node.instruction()) : null;
            boolean resolvedTrap = kernel != null && "trap".equals(kernel.kind()) &&
                !kernelCauses.containsKey(node.instruction());
            for (Node next : successors(node, op, pcode, rows, unchecked)) {
                Map<Loc, Integer> edge = state;
                if (kernel != null && !next.instruction().equals(node.instruction())) {
                    if (resolvedTrap) {
                        continue;
                    }
                    edge = kernelState();
                }
                Map<Loc, Integer> known = in.get(next);
                Map<Loc, Integer> merged;
                if (known == null) {
                    merged = new HashMap<>(edge);
                }
                else {
                    merged = merge(known, edge);
                }
                if (known == null || !merged.equals(known)) {
                    in.put(next, merged);
                    pending.add(next);
                }
            }
        }
    }

    /** Why a kernel row is UNCHECKED under s3-on, or null when it is a covered candidate / a resolved trap. */
    private String kernelCause(Kernel kernel, PcodeOp[] ops, Instruction row) {
        switch (kernel.kind()) {
            case "uncovered" -> {
                return "kernel-uncovered";
            }
            case "undecidable" -> {
                return "kernel-undecidable";
            }
            default -> {
            }
        }
        if (row.getLength() != kernel.formLength()) {
            return "length-mismatch";
        }
        PcodeOp callother = null;
        for (PcodeOp op : ops) {
            if (op.getOpcode() == PcodeOp.CALLOTHER) {
                callother = op;
            }
            for (Varnode input : op.getInputs()) {
                if ("covered".equals(kernel.kind()) && loc(input).overlaps(stack)) {
                    return "sp-in-kernel-row";
                }
            }
            Varnode out = op.getOutput();
            if ("covered".equals(kernel.kind()) && out != null && loc(out).overlaps(stack)) {
                return "sp-in-kernel-row";
            }
        }
        if (callother == null) {
            return "contradictory-lift";
        }
        if ("covered".equals(kernel.kind())) {
            // (Astra X-1a r1 P2-1) the lift agrees with the bytes: 0F 05 lifts to
            // the syscall user op, CD 2E to a trap op carrying vector 0x2E
            if (kernel.vector() == null) {
                String name = program.getLanguage().getUserDefinedOpName((int) callother.getInput(0).getOffset());
                if (name == null || !name.toLowerCase(Locale.ROOT).contains("syscall")) {
                    return "contradictory-lift";
                }
            }
            else if (!kernel.vector().equals(liftVector(callother))) {
                return "contradictory-lift";
            }
        }
        if ("trap".equals(kernel.kind()) && kernel.vector() != null && !"ud".equals(kernel.vector())) {
            String lifted = liftVector(callother);
            if (!kernel.vector().equals(lifted)) {
                return "kernel-undecidable";   // (r4 4.3) the bytes' vector and the lift's disagree
            }
        }
        return null;
    }

    /** (Astra X-1a r1 P2-1) every kernel row judged once, as a whole, before propagation: row -> cause
     *  (absent: a covered candidate or a resolved trap). */
    private Map<Address, String> validateKernels() {
        Map<Address, String> result = new HashMap<>();
        Listing listing = program.getListing();
        for (Map.Entry<Address, Kernel> entry : kernels.entrySet()) {
            Instruction row = listing.getInstructionAt(entry.getKey());
            PcodeOp[] ops = row == null ? new PcodeOp[0] : row.getPcode();
            String cause = ops.length == 0 ? "empty-lift" : kernelCause(entry.getValue(), ops, row);
            if (cause != null) {
                result.put(entry.getKey(), cause);
            }
        }
        return result;
    }

    private static String liftVector(PcodeOp callother) {
        return callother.getNumInputs() >= 2 && callother.getInput(1).isConstant()
            ? Long.toString(callother.getInput(1).getOffset()) : null;
    }

    private List<Node> successors(Node node, PcodeOp op, Map<Address, PcodeOp[]> pcode,
            Map<Address, Instruction> rows, Set<Node> unchecked) {
        List<Node> result = new ArrayList<>();
        PcodeOp[] ops = pcode.get(node.instruction());
        Instruction instruction = rows.get(node.instruction());
        int opcode = op.getOpcode();
        if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
            Varnode target = op.getInput(0);
            if (target.isConstant()) {
                int bits = 8 * target.getSize();
                long displacement = bits >= 64 ? target.getOffset()
                    : (target.getOffset() << (64 - bits)) >> (64 - bits);
                long ordinal = node.ordinal() + displacement;
                if (ordinal >= 0 && ordinal < ops.length) {
                    result.add(new Node(node.instruction(), (int) ordinal));
                }
                else if (ordinal == ops.length) {
                    addInstruction(result, instruction.getFallThrough(), pcode, rows);
                }
                else {
                    unchecked.add(node);
                }
            }
            else {
                addInstruction(result, target.getAddress(), pcode, rows);
            }
            if (opcode == PcodeOp.BRANCH) {
                return result;
            }
        }
        else if (opcode == PcodeOp.BRANCHIND) {
            if (node.ordinal() != ops.length - 1) {
                unchecked.add(node);
            }
            for (Address flow : instruction.getFlows()) {
                addInstruction(result, flow, pcode, rows);
            }
            return result;
        }
        else if (opcode == PcodeOp.RETURN) {
            return result;
        }
        else if (opcode == PcodeOp.CALL && op.getInput(0).isAddress()) {
            addInstruction(result, op.getInput(0).getAddress(), pcode, rows);
        }
        if (node.ordinal() + 1 < ops.length) {
            result.add(new Node(node.instruction(), node.ordinal() + 1));
        }
        else {
            addInstruction(result, instruction.getFallThrough(), pcode, rows);
        }
        return result;
    }

    private void addInstruction(List<Node> result, Address address, Map<Address, PcodeOp[]> pcode,
            Map<Address, Instruction> rows) {
        Set<Address> seen = new HashSet<>();
        while (address != null && pcode.containsKey(address) && seen.add(address)) {
            if (pcode.get(address).length > 0) {
                result.add(new Node(address, 0));
                return;
            }
            address = rows.get(address).getFallThrough();
        }
    }

    // -- s3-on pre-passes ------------------------------------------------------------------------------

    /** (r4 4.4) every cross-region destination of a non-call transfer, program-wide; an indirect jump with no
     *  listed destination is unbounded (UNCHECKED). A destination outside program code (an import) is bounded
     *  and has no row to seed. */
    private void collectCrossTargets(List<Map<String, Object>> unbounded) throws Exception {
        Listing listing = program.getListing();
        FunctionManager functions = program.getFunctionManager();
        InstructionIterator all = listing.getInstructions(true);
        Set<Node> none = new HashSet<>();
        while (all.hasNext()) {
            monitor.checkCancelled();
            Instruction row = all.next();
            Function owner = functions.getFunctionContaining(row.getAddress());
            List<Address> destinations = new ArrayList<>();
            boolean indirect = false;
            for (PcodeOp op : row.getPcode()) {
                int opcode = op.getOpcode();
                if (opcode == PcodeOp.BRANCHIND) {
                    indirect = true;
                }
                if ((opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) && op.getInput(0).isAddress()) {
                    destinations.add(op.getInput(0).getAddress());
                }
            }
            // (Astra X-1a r1 P2-2) a validated trap row (UD2's lift ends in a
            // targetless BRANCHIND) is the trap's own business: its site decision
            // resolves it, not an unbounded-transfer verdict
            Kernel kernel = kernels.get(row.getAddress());
            boolean validatedTrap = kernel != null && "trap".equals(kernel.kind()) &&
                !kernelCauses.containsKey(row.getAddress());
            if (indirect && !validatedTrap) {
                Address[] flows = row.getFlows();
                if (flows.length == 0) {
                    report(unbounded, none, new Node(row.getAddress(), row.getPcode().length - 1), "UNCHECKED",
                        owner == null ? "(outside functions)" : owner.getName(true), Map.of(row.getAddress(), row),
                        "unbounded-transfer");
                }
                destinations.addAll(Arrays.asList(flows));
            }
            if (row.getFallThrough() != null) {
                destinations.add(row.getFallThrough());
            }
            for (Address destination : destinations) {
                if (listing.getInstructionAt(destination) == null) {
                    continue;   // no row there (an import, data): bounded, nothing to seed
                }
                Function target = functions.getFunctionContaining(destination);
                boolean sameRegion = owner == null ? target == null
                    : target != null && owner.getEntryPoint().equals(target.getEntryPoint());
                if (!sameRegion) {
                    crossTargets.add(destination);
                }
            }
        }
    }

    /** (r3 4.3 / r4 4.3) every listed instruction start classified by its bytes, read independently of the
     *  declared length (stopping at a gap or the 15-byte limit). */
    private Map<Address, Kernel> classifyKernels() throws Exception {
        Map<Address, Kernel> result = new LinkedHashMap<>();
        Memory memory = program.getMemory();
        InstructionIterator all = program.getListing().getInstructions(true);
        while (all.hasNext()) {
            monitor.checkCancelled();
            Instruction row = all.next();
            Kernel kernel = classify(memory, row.getAddress());
            if (kernel != null) {
                result.put(row.getAddress(), kernel);
            }
        }
        return result;
    }

    static Kernel classify(Memory memory, Address address) {
        byte[] buffer = new byte[MAX_INSTRUCTION_BYTES];
        int count = 0;
        for (; count < MAX_INSTRUCTION_BYTES; count++) {
            try {
                buffer[count] = memory.getByte(address.add(count));
            }
            catch (MemoryAccessException | ghidra.program.model.address.AddressOutOfBoundsException gap) {
                break;
            }
        }
        return classifyBytes(buffer, count);
    }

    /** (r3 4.3 / r4 4.3, Astra X-1a r1 P1-6) the kernel-transfer class of the bytes at an instruction start:
     *  {@code count} readable bytes (a gap or the 15-byte limit stops reading). Any prefix or REX byte before a
     *  kernel form, and bytes that still match a kernel-form prefix when the readable bytes end (bare 0F, 0F 01,
     *  CD, prefixes only), are undecidable. Only the classified bytes are recorded. null: no kernel form. */
    static Kernel classifyBytes(byte[] buffer, int count) {
        int index = 0;
        boolean prefixed = false;
        while (index < count && (LEGACY_PREFIXES.contains(buffer[index] & 0xFF) ||
                ((buffer[index] & 0xF0) == 0x40))) {
            index++;
            prefixed = true;
        }
        if (index >= count) {
            return count == 0 || prefixed ? new Kernel("undecidable", null, index, hex(buffer, count)) : null;
        }
        int opcode = buffer[index] & 0xFF;
        Integer next = index + 1 < count ? buffer[index + 1] & 0xFF : null;
        Integer third = index + 2 < count ? buffer[index + 2] & 0xFF : null;
        Kernel kernel = null;
        switch (opcode) {
            case 0xCC -> kernel = kernel("trap", "3", index + 1, buffer);
            case 0xF1, 0xCE, 0xF4 -> kernel = kernel("uncovered", null, index + 1, buffer);
            case 0xCD -> {
                if (next == null) {
                    return kernel("undecidable", null, index + 1, buffer);
                }
                kernel = switch (next) {
                    case 0x2E -> kernel("covered", "46", index + 2, buffer);
                    case 0x03 -> kernel("trap", "3", index + 2, buffer);
                    case 0x29 -> kernel("trap", "41", index + 2, buffer);
                    default -> kernel("uncovered", Integer.toString(next), index + 2, buffer);
                };
            }
            case 0x0F -> {
                if (next == null) {
                    return kernel("undecidable", null, index + 1, buffer);   // (a bare 0F at a gap)
                }
                kernel = switch (next) {
                    case 0x05 -> kernel("covered", null, index + 2, buffer);
                    case 0x0B -> kernel("trap", "ud", index + 2, buffer);
                    case 0x34, 0x07, 0x35 -> kernel("uncovered", null, index + 2, buffer);
                    case 0x01 -> third == null ? kernel("undecidable", null, index + 2, buffer)   // (0F 01 at a gap)
                        : third == 0xC1 || third == 0xD9 ? kernel("uncovered", null, index + 3, buffer) : null;
                    default -> null;
                };
            }
            default -> {
            }
        }
        if (kernel != null && prefixed) {
            return new Kernel("undecidable", kernel.vector(), kernel.formLength(), kernel.bytes());
        }
        return kernel;
    }

    private static Kernel kernel(String kind, String vector, int formLength, byte[] buffer) {
        return new Kernel(kind, vector, formLength, hex(buffer, formLength));
    }

    private List<Map<String, Object>> kernelRows(Map<Address, List<Address>> exported) {
        Set<Address> exportedRows = new HashSet<>();
        if (exported != null) {
            exported.values().forEach(exportedRows::addAll);
        }
        List<Map<String, Object>> result = new ArrayList<>();
        Listing listing = program.getListing();
        for (Map.Entry<Address, Kernel> entry : kernels.entrySet()) {
            Instruction row = listing.getInstructionAt(entry.getKey());
            Kernel kernel = entry.getValue();
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("space_id", entry.getKey().getAddressSpace().getSpaceID());
            item.put("byte_offset", entry.getKey().getOffset());
            item.put("bytes", kernel.bytes());
            item.put("class", kernel.kind());
            item.put("vector", kernel.vector());
            PcodeOp callother = null;
            PcodeOp[] ops = row == null ? new PcodeOp[0] : row.getPcode();
            for (PcodeOp op : ops) {
                if (op.getOpcode() == PcodeOp.CALLOTHER) {
                    callother = op;
                }
            }
            item.put("lift", ops.length == 0 ? "empty" : callother == null ? "contradictory"
                : "callother:" + program.getLanguage().getUserDefinedOpName((int) callother.getInput(0).getOffset()));
            item.put("lift_vector", callother == null ? null : liftVector(callother));
            item.put("exported", exportedRows.contains(entry.getKey()));
            result.add(item);
        }
        return result;
    }

    // -- the listing digest (r4 4.2) ---------------------------------------------------------------------

    /** {verifiable_sha256, attested_sha256}: the verifiable part over the exported rows (TDO recomputes it from
     *  the sealed Bundle); the attested part over EVERY listed instruction (exported ones too) with everything the
     *  scan reads of it -- its owning function, effective fallthrough, listed flows and p-code (Astra X-1a r1 P1-7).
     *  {@code collected}: the exporter's attested lines of the exported rows, taken when it collected them (the
     *  first checkpoint); null: recomputed from the listing (the scan's and the sealing checkpoints). */
    public static Map<String, Object> listingDigest(Program program, Map<Address, List<Address>> exported,
            Map<Address, String> collected, TaskMonitor monitor) throws Exception {
        MessageDigest verifiable = MessageDigest.getInstance("SHA-256");
        MessageDigest attested = MessageDigest.getInstance("SHA-256");
        Listing listing = program.getListing();
        if (exported != null) {
            List<Address> entries = new ArrayList<>(exported.keySet());
            entries.sort(GhidraV2StackSwitchScanner::compare);
            for (Address entry : entries) {
                monitor.checkCancelled();
                update(verifiable, "F " + coordinate(entry) + "\n");
                List<Address> rows = new ArrayList<>(exported.get(entry));
                rows.sort(GhidraV2StackSwitchScanner::compare);
                for (Address address : rows) {
                    update(verifiable, rowLine(listing.getInstructionAt(address), address) + "\n");
                }
            }
        }
        InstructionIterator all = listing.getInstructions(true);
        while (all.hasNext()) {
            monitor.checkCancelled();
            Instruction row = all.next();
            String line = collected != null && collected.containsKey(row.getAddress())
                ? collected.get(row.getAddress()) : attestedLine(row);
            update(attested, line + "\n");
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("verifiable_sha256", hex(verifiable.digest(), 32));
        result.put("attested_sha256", hex(attested.digest(), 32));
        return result;
    }

    /** (Astra X-1a r1 P1-7) one row of the attested digest: the verifiable fields and every other scan input --
     *  the owning function's entry, the effective fallthrough, the listed flows (sorted) and the p-code. */
    public static String attestedLine(Instruction row) {
        Program program = row.getProgram();
        Function owner = program.getFunctionManager().getFunctionContaining(row.getAddress());
        Address fallthrough = row.getFallThrough();
        List<Address> flows = new ArrayList<>(Arrays.asList(row.getFlows()));
        flows.sort(GhidraV2StackSwitchScanner::compare);
        StringBuilder line = new StringBuilder(rowLine(row, row.getAddress()));
        line.append(" owner=").append(owner == null ? "-" : coordinate(owner.getEntryPoint()));
        line.append(" ft=").append(fallthrough == null ? "-" : coordinate(fallthrough));
        line.append(" flows=");
        for (Address flow : flows) {
            line.append(coordinate(flow)).append(',');
        }
        for (PcodeOp op : row.getPcode()) {
            line.append(' ').append(op.toString());
        }
        return line.toString();
    }

    /** One row of the canonical digest text (mirrored by tdo_v2.stack_evidence.verifiable_row_line):
     *  {@code R <space>:<offset hex> <length> <bytes hex | -> <flow override> <fallthrough 0/1> <length 0/1>
     *  <references: space:offset:type:primary,... | ->}. */
    static String rowLine(Instruction row, Address address) {
        if (row == null) {
            return "R " + coordinate(address) + " - - - - - -";
        }
        // (r4 4.2) the bytes TDO can read back: only from a block the exporter
        // seals as a byte member (loaded, initialized, no overlay, not external,
        // a default block), the whole row inside it; otherwise "unavailable"
        String bytes = "-";
        MemoryBlock block = row.getProgram().getMemory().getBlock(address);
        if (block != null && block.isLoaded() && block.isInitialized() &&
                !block.getStart().getAddressSpace().isOverlaySpace() && !block.isExternalBlock() &&
                block.getType() == MemoryBlockType.DEFAULT && block.contains(row.getMaxAddress())) {
            try {
                bytes = hex(row.getBytes(), row.getLength());
            }
            catch (MemoryAccessException unavailable) {
                bytes = "-";
            }
        }
        List<String> references = new ArrayList<>();
        for (Reference reference : row.getReferencesFrom()) {
            if (reference.getReferenceType().isOverride() && reference.getToAddress() != null) {
                references.add(coordinate(reference.getToAddress()) + ":" + reference.getReferenceType().getName() +
                    ":" + (reference.isPrimary() ? 1 : 0));
            }
        }
        Collections.sort(references);
        return "R " + coordinate(address) + " " + row.getLength() + " " + bytes + " " +
            row.getFlowOverride().name() + " " + (row.isFallThroughOverridden() ? 1 : 0) + " " +
            (row.isLengthOverridden() ? 1 : 0) + " " + (references.isEmpty() ? "-" : String.join(",", references));
    }

    private static int compare(Address left, Address right) {
        int space = Integer.compare(left.getAddressSpace().getSpaceID(), right.getAddressSpace().getSpaceID());
        return space != 0 ? space : Long.compareUnsigned(left.getOffset(), right.getOffset());
    }

    private static String coordinate(Address address) {
        return address.getAddressSpace().getSpaceID() + ":" + Long.toHexString(address.getOffset());
    }

    private static void update(MessageDigest digest, String text) {
        digest.update(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String hex(byte[] data, int length) {
        StringBuilder text = new StringBuilder();
        for (int index = 0; index < Math.min(length, data.length); index++) {
            text.append(String.format("%02x", data[index] & 0xFF));
        }
        return text.toString();
    }
}

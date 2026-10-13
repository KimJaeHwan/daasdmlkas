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
// Arguments: --output PATH --expected-sha256 HEX
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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class GhidraV2StackSwitchScan extends GhidraScript {
    // keep equal to tdo_v2.stack_evidence.DETECTORS[-1]
    public static final String DETECTOR = "stack-switch-coefficient-v3";
    // what a clean scan rests on besides finding no switch (the reported
    // assumption stack-switch-check-exceptions; as tdo_v2.stack_evidence.EXCEPTIONS)
    private static final List<String> EXCEPTIONS = List.of("loaded-and-call-result-values-hold-no-stack-pointer",
        "user-ops-change-only-their-output", "calls-preserve-the-common-nonvolatile-registers");
    private static final long MAX_STACK_ALIGNMENT = 1L << 12;
    private static final Integer UNKNOWN = null;
    private static final Set<Integer> BOOLEAN = Set.of(
        PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS,
        PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL, PcodeOp.INT_CARRY, PcodeOp.INT_SCARRY,
        PcodeOp.INT_SBORROW, PcodeOp.BOOL_NEGATE, PcodeOp.BOOL_XOR, PcodeOp.BOOL_AND, PcodeOp.BOOL_OR,
        PcodeOp.FLOAT_EQUAL, PcodeOp.FLOAT_NOTEQUAL, PcodeOp.FLOAT_LESS, PcodeOp.FLOAT_LESSEQUAL,
        PcodeOp.FLOAT_NAN);
    // registers every convention of the language has a callee preserve (as may_alias.CALL_PRESERVED)
    private static final List<String> X86_64_PRESERVED = List.of("RBX", "RBP", "R12", "R13", "R14", "R15");
    private static final List<String> X86_32_PRESERVED = List.of("EBX", "EBP", "ESI", "EDI");

    /** A storage location: address space, offset, size. */
    private record Loc(int space, long offset, int size) {
        boolean overlaps(Loc other) {
            return space == other.space && offset < other.offset + other.size && other.offset < offset + size;
        }
    }

    /** One p-code operation of a scanned region: (instruction, ordinal). */
    private record Node(Address instruction, int ordinal) {}

    private Loc stack;
    private final List<Loc> preserved = new ArrayList<>();

    private static Loc loc(Varnode varnode) {
        return new Loc(varnode.getSpace(), varnode.getOffset(), varnode.getSize());
    }

    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = null;
        String expected = null;
        for (int index = 0; index + 1 < args.length; index += 2) {
            switch (args[index]) {
                case "--output" -> output = Path.of(args[index + 1]).toAbsolutePath().normalize();
                case "--expected-sha256" -> expected = args[index + 1].toLowerCase(Locale.ROOT);
                default -> throw new IllegalArgumentException("unknown argument " + args[index]);
            }
        }
        if (output == null || expected == null || args.length % 2 != 0) {
            throw new IllegalArgumentException("--output PATH --expected-sha256 HEX");
        }
        if (!currentProgram.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED_OPTION_NAME, false)) {
            throw new IllegalStateException("the program is not analyzed: analyze it in the Ghidra project first");
        }
        String claim = currentProgram.getExecutableSHA256();
        if (claim == null || !expected.equals(claim.trim().toLowerCase(Locale.ROOT))) {
            throw new IOException("the program's executable SHA-256 is not the expected one");
        }
        Register sp = currentProgram.getCompilerSpec().getStackPointer();
        stack = loc(new Varnode(sp.getAddress(), sp.getMinimumByteSize()));
        String language = currentProgram.getLanguageID().getIdAsString();
        List<String> preservedNames = language.startsWith("x86:LE:64") ? X86_64_PRESERVED
            : language.startsWith("x86:LE:32") ? X86_32_PRESERVED : List.of();
        for (String name : preservedNames) {
            Register register = currentProgram.getRegister(name);
            preserved.add(loc(new Varnode(register.getAddress(), register.getMinimumByteSize())));
        }

        Listing listing = currentProgram.getListing();
        List<Map<String, Object>> switches = new ArrayList<>();
        long functions = 0, instructions = 0;
        FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
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
        // instructions outside every function: scanned as one region (each from
        // the stack pointer being the stack pointer)
        AddressSet outside = new AddressSet();
        InstructionIterator all = listing.getInstructions(true);
        while (all.hasNext()) {
            Instruction instruction = all.next();
            if (currentProgram.getFunctionManager().getFunctionContaining(instruction.getAddress()) == null) {
                outside.add(instruction.getMinAddress(), instruction.getMaxAddress());
            }
        }
        long outsideCount = outside.isEmpty() ? 0 : scan(null, outside, "(outside functions)", listing, switches);
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("format", "tdo-v2-stack-switch-evidence");
        evidence.put("version", 1);
        evidence.put("detector", DETECTOR);
        evidence.put("executable_sha256", expected);
        evidence.put("program", currentProgram.getDomainFile().getPathname());
        evidence.put("language", language);
        evidence.put("stack_pointer", sp.getName());
        evidence.put("functions_scanned", functions);
        evidence.put("instructions_scanned", instructions + outsideCount);
        evidence.put("instructions_outside_functions", outsideCount);
        evidence.put("switches", switches);
        evidence.put("call_preserved", preservedNames);
        evidence.put("exceptions", EXCEPTIONS);
        Files.writeString(output, new GsonBuilder().setPrettyPrinting().create().toJson(evidence) + "\n",
            StandardCharsets.UTF_8);
        println("stack-switch scan: " + functions + " functions, " + (instructions + outsideCount) +
            " instructions (" + outsideCount + " outside functions), " + switches.size() + " switch(es) -> " +
            output);
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
        Deque<Node> pending = new ArrayDeque<>();
        // from the entry, then from every instruction no path reaches; the stack
        // pointer is the stack pointer everywhere
        List<Address> starts = new ArrayList<>();
        if (entry != null) {
            starts.add(entry);
        }
        starts.addAll(pcode.keySet());
        for (Address start : starts) {
            if (!pcode.containsKey(start) || (start != entry && reached(start, in, pcode))) {
                continue;
            }
            List<Node> seeds = new ArrayList<>();
            addInstruction(seeds, start, pcode, rows);
            for (Node seed : seeds) {
                if (!in.containsKey(seed)) {
                    Map<Loc, Integer> state = new HashMap<>();
                    state.put(stack, 1);
                    in.put(seed, state);
                    pending.add(seed);
                }
            }
            propagate(in, pending, pcode, rows, unchecked);
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
                    report(switches, reported, node, op.getMnemonic(), name, rows);
                }
            }
        }
        for (Node node : unchecked) {
            report(switches, reported, node, "UNCHECKED", name, rows);
        }
        return pcode.size();
    }

    private static void report(List<Map<String, Object>> switches, Set<Node> reported, Node node, String opcode,
            String name, Map<Address, Instruction> rows) {
        if (!reported.add(node)) {
            return;
        }
        Map<String, Object> found = new LinkedHashMap<>();
        found.put("function", name);
        found.put("instruction", node.instruction().toString());
        found.put("ordinal", node.ordinal());
        found.put("opcode", opcode);
        found.put("text", rows.get(node.instruction()).toString());
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

    private static Integer read(Map<Loc, Integer> state, Varnode varnode) {
        if (varnode.isConstant()) {
            return 0;
        }
        Loc key = loc(varnode);
        if (state.containsKey(key)) {
            return state.get(key);
        }
        for (Map.Entry<Loc, Integer> row : state.entrySet()) {
            if (row.getKey().overlaps(key) && !Integer.valueOf(0).equals(row.getValue())) {
                return UNKNOWN;
            }
        }
        return 0;
    }

    private static void write(Map<Loc, Integer> state, Loc key, Integer value) {
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
                // bytes of a non-zero entry survive the partial write: that
                // location no longer holds a whole coefficient (mov al, 0)
                state.put(other, UNKNOWN);
            }
        }
        if (!Integer.valueOf(0).equals(value)) {
            state.put(key, value);
        }
        else {
            state.remove(key);
        }
    }

    /** The output's stack coefficient: 1, 0, or null (unknown). */
    private static Integer coefficient(PcodeOp op, Map<Loc, Integer> state) {
        int opcode = op.getOpcode();
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
                    // an alignment mask -2**k (k <= 12) keeps "the stack pointer + a number"
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

    private void propagate(Map<Node, Map<Loc, Integer>> in, Deque<Node> pending, Map<Address, PcodeOp[]> pcode,
            Map<Address, Instruction> rows, Set<Node> unchecked) throws Exception {
        while (!pending.isEmpty()) {
            monitor.checkCancelled();
            Node node = pending.removeFirst();
            PcodeOp op = pcode.get(node.instruction())[node.ordinal()];
            Map<Loc, Integer> state = new HashMap<>(in.get(node));
            int opcode = op.getOpcode();
            if (opcode == PcodeOp.CALL || opcode == PcodeOp.CALLIND) {
                // the callee leaves what it likes, except the stack pointer (the
                // call shape) and the call-preserved registers; a user op
                // (CALLOTHER) defines just its output, if any
                state.keySet().removeIf(key -> key.space() == stack.space() && !key.equals(stack) &&
                    preserved.stream().noneMatch(kept -> key.offset() >= kept.offset() &&
                        key.offset() + key.size() <= kept.offset() + kept.size()));
            }
            Varnode out = op.getOutput();
            if (out != null && (out.isRegister() || out.isUnique())) {
                Loc key = loc(out);
                write(state, key, key.overlaps(stack) ? Integer.valueOf(1) : coefficient(op, state));
                // a write of the stack pointer, a switch or not, leaves the stack
                // pointer the stack pointer (a switch is reported where it happens)
                if (key.overlaps(stack)) {
                    write(state, stack, 1);
                }
            }
            for (Node next : successors(node, op, pcode, rows, unchecked)) {
                Map<Loc, Integer> known = in.get(next);
                Map<Loc, Integer> merged;
                if (known == null) {
                    merged = new HashMap<>(state);
                }
                else {   // MUST: the same coefficient on every path, else unknown
                    merged = new HashMap<>();
                    Set<Loc> keys = new HashSet<>(known.keySet());
                    keys.addAll(state.keySet());
                    for (Loc key : keys) {
                        Integer left = known.getOrDefault(key, 0);
                        Integer right = state.getOrDefault(key, 0);
                        Integer value = Objects.equals(left, right) ? left : UNKNOWN;
                        if (!Integer.valueOf(0).equals(value)) {
                            merged.put(key, value);
                        }
                    }
                }
                if (known == null || !merged.equals(known)) {
                    in.put(next, merged);
                    pending.add(next);
                }
            }
        }
    }

    private List<Node> successors(Node node, PcodeOp op, Map<Address, PcodeOp[]> pcode,
            Map<Address, Instruction> rows, Set<Node> unchecked) {
        List<Node> result = new ArrayList<>();
        PcodeOp[] ops = pcode.get(node.instruction());
        Instruction instruction = rows.get(node.instruction());
        int opcode = op.getOpcode();
        if (opcode == PcodeOp.BRANCH || opcode == PcodeOp.CBRANCH) {
            Varnode target = op.getInput(0);
            if (target.isConstant()) {   // p-code relative branch inside the instruction
                int bits = 8 * target.getSize();   // a signed displacement of the constant's size
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
                    unchecked.add(node);   // a relative branch out of its instruction
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
                unchecked.add(node);   // an indirect branch inside an instruction
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
            // a call into the same region (a local helper) is followed too, as
            // the engine's block graph does; the fallthrough below as well
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
        // an instruction without p-code (a nop) passes control to its fallthrough
        Set<Address> seen = new HashSet<>();
        while (address != null && pcode.containsKey(address) && seen.add(address)) {
            if (pcode.get(address).length > 0) {
                result.add(new Node(address, 0));
                return;
            }
            address = rows.get(address).getFallThrough();
        }
    }
}

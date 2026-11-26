"""X-1a (Astra X-1a r2 P1-2 / P1-3): the scanner's production Java, compiled against Ghidra 12.0.4's jars.

* ``validateRow`` -- the exact lift shape of a kernel row, fed with constructed p-code: the shapes Ghidra's x86
  lifts (``0F 05`` one ``syscall`` CALLOTHER; ``CD xx`` / ``CC`` ``swi``(vector) into a unique then a CALLIND of it,
  ``CC`` closing with ``RETURN``; ``0F 0B`` ``invalidInstructionException`` into a unique then a BRANCHIND of that
  unique) pass; a wrong vector, an unrelated user op with the right vector, a stack-pointer access anywhere in the
  row (an early branch cannot hide it), a UD2 branch on another temporary, a lift with an extra operation do not.
* ``attestedLine`` / ``listingDigest`` / ``requireSameListing`` -- successive instruction views (dynamic proxies of
  Ghidra's interfaces): changing only a listed target, only one exported p-code operand, or only byte two after a
  one-byte ``0F`` row changes the digest, and the checkpoint comparison refuses to publish.

Skipped when javac / Ghidra are unavailable (run it in WSL)."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GHIDRA_CANDIDATES = (Path("/mnt/d/01_gitproject/14_TDO_v2/ghidra_12.0.4_PUBLIC"),
                     ROOT.parent / "ghidra_12.0.4_PUBLIC", ROOT.parents[2] / "ghidra_12.0.4_PUBLIC")

HARNESS = r'''
import java.lang.reflect.*;
import java.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

public class ScannerJavaTest {
    static final AddressSpace CONST = new GenericAddressSpace("const", 64, AddressSpace.TYPE_CONSTANT, 0);
    static final AddressSpace UNIQUE = new GenericAddressSpace("unique", 64, AddressSpace.TYPE_UNIQUE, 1);
    static final AddressSpace REGISTER = new GenericAddressSpace("register", 64, AddressSpace.TYPE_REGISTER, 2);
    static final AddressSpace RAM = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 3);
    static final Map<Integer, String> OPS = Map.of(0x5, "syscall", 0x10, "swi", 0x20, "invalidInstructionException",
        0x30, "cpuid");

    static Varnode c(long value, int size) { return new Varnode(CONST.getAddress(value), size); }
    static Varnode u(long offset) { return new Varnode(UNIQUE.getAddress(offset), 8); }
    static Varnode r(long offset, int size) { return new Varnode(REGISTER.getAddress(offset), size); }
    static final GhidraV2StackSwitchScanner.Loc RSP = GhidraV2StackSwitchScanner.loc(r(0x20, 8));
    static PcodeOp op(int opcode, Varnode out, Varnode... in) {
        return new PcodeOp(new SequenceNumber(RAM.getAddress(0x1000), 0), opcode, in, out);
    }
    static GhidraV2StackSwitchScanner.Kernel kernel(String kind, String vector, int length, String bytes) {
        return new GhidraV2StackSwitchScanner.Kernel(kind, vector, length, bytes);
    }
    static void expect(String label, String expected, GhidraV2StackSwitchScanner.Kernel kernel, int rowLength,
            PcodeOp... ops) {
        String actual = GhidraV2StackSwitchScanner.validateRow(kernel, ops, rowLength, RSP, OPS::get);
        if (!Objects.equals(actual, expected)) {
            throw new AssertionError(label + ": " + actual + " != " + expected);
        }
    }

    @SuppressWarnings("unchecked")
    static <T> T stub(Class<T> type, Map<String, Object> answers) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (proxy, method, args) -> {
            if (answers.containsKey(method.getName())) {
                Object value = answers.get(method.getName());
                try {
                    return value instanceof java.util.function.Function<?, ?> f
                        ? ((java.util.function.Function<Object[], Object>) f).apply(args) : value;
                }
                catch (UndeclaredThrowableException wrapped) {   // (a declared checked exception, e.g. a gap)
                    throw wrapped.getUndeclaredThrowable();
                }
            }
            if (method.getName().equals("hashCode")) return System.identityHashCode(proxy);
            if (method.getName().equals("equals")) return proxy == args[0];
            Class<?> result = method.getReturnType();
            if (result == boolean.class) return false;
            if (result == int.class || result == long.class || result == short.class || result == byte.class) return 0;
            return null;
        });
    }

    /** One program view with one instruction at 0x1000: its bytes, listed flows and p-code. */
    static Program view(byte[] memory, int length, Address[] flows, PcodeOp[] pcode) {
        Address at = RAM.getAddress(0x1000);
        Map<String, Object> blockAnswers = new HashMap<>();
        blockAnswers.put("isLoaded", true);
        blockAnswers.put("isInitialized", true);
        blockAnswers.put("getStart", at);
        blockAnswers.put("getType", MemoryBlockType.DEFAULT);
        blockAnswers.put("contains", (java.util.function.Function<Object[], Object>) args -> true);
        MemoryBlock block = stub(MemoryBlock.class, blockAnswers);
        Map<String, Object> memoryAnswers = new HashMap<>();
        memoryAnswers.put("getBlock", (java.util.function.Function<Object[], Object>) args -> block);
        memoryAnswers.put("getByte", (java.util.function.Function<Object[], Object>) args -> {
            long index = ((Address) args[0]).getOffset() - 0x1000;
            if (index < 0 || index >= memory.length) {
                throw new UndeclaredThrowableException(new MemoryAccessException("gap"));
            }
            return memory[(int) index];
        });
        Memory mem = stub(Memory.class, memoryAnswers);
        FunctionManager functions = stub(FunctionManager.class, Map.of());
        Program[] program = new Program[1];
        Map<String, Object> rowAnswers = new HashMap<>();
        rowAnswers.put("getProgram", (java.util.function.Function<Object[], Object>) args -> program[0]);
        rowAnswers.put("getAddress", at);
        rowAnswers.put("getMaxAddress", at.add(length - 1));
        rowAnswers.put("getLength", length);
        rowAnswers.put("getBytes", Arrays.copyOf(memory, length));
        rowAnswers.put("getFlows", flows);
        rowAnswers.put("getPcode", pcode);
        rowAnswers.put("getFlowOverride", FlowOverride.NONE);
        rowAnswers.put("getReferencesFrom", new Reference[0]);
        Instruction row = stub(Instruction.class, rowAnswers);
        Map<String, Object> listingAnswers = new HashMap<>();
        listingAnswers.put("getInstructions", (java.util.function.Function<Object[], Object>) args -> {
            Iterator<Instruction> rows = List.of(row).iterator();
            Map<String, Object> iterator = new HashMap<>();
            iterator.put("hasNext", (java.util.function.Function<Object[], Object>) a -> rows.hasNext());
            iterator.put("next", (java.util.function.Function<Object[], Object>) a -> rows.next());
            return stub(InstructionIterator.class, iterator);
        });
        listingAnswers.put("getInstructionAt", (java.util.function.Function<Object[], Object>) args -> row);
        Listing listing = stub(Listing.class, listingAnswers);
        Map<String, Object> programAnswers = new HashMap<>();
        programAnswers.put("getMemory", mem);
        programAnswers.put("getFunctionManager", functions);
        programAnswers.put("getListing", listing);
        program[0] = stub(Program.class, programAnswers);
        return program[0];
    }

    static Map<String, Object> digest(Program program) throws Exception {
        Map<Address, List<Address>> exported = Map.of(RAM.getAddress(0x1000), List.of(RAM.getAddress(0x1000)));
        return GhidraV2StackSwitchScanner.listingDigest(program, exported, null, TaskMonitor.DUMMY);
    }

    static void refused(String label, Program a, Program b) throws Exception {
        Map<String, Object> first = digest(a), second = digest(b);
        if (first.equals(second)) {
            throw new AssertionError(label + ": the digests agree");
        }
        try {
            GhidraV2StackSwitchScanner.requireSameListing(first, first, second);
        }
        catch (java.io.IOException expected) {
            return;
        }
        throw new AssertionError(label + ": publication was not refused");
    }

    public static void main(String[] args) throws Exception {
        // -- validateRow ---------------------------------------------------------------------------------
        var syscall = kernel("covered", null, 2, "0f05");
        expect("syscall", null, syscall, 2, op(PcodeOp.CALLOTHER, null, c(0x5, 4)));
        expect("syscall with an output", "contradictory-lift", syscall, 2, op(PcodeOp.CALLOTHER, u(0x100), c(0x5, 4)));
        expect("syscall as another op", "contradictory-lift", syscall, 2, op(PcodeOp.CALLOTHER, null, c(0x30, 4)));
        expect("syscall with an extra op", "contradictory-lift", syscall, 2,
            op(PcodeOp.CALLOTHER, null, c(0x5, 4)), op(PcodeOp.COPY, r(0, 8), c(0, 8)));
        expect("an early branch skipping a final SP access", "sp-in-kernel-row", syscall, 2,
            op(PcodeOp.CBRANCH, null, c(2, 4), c(1, 1)), op(PcodeOp.CALLOTHER, null, c(0x5, 4)),
            op(PcodeOp.COPY, r(0x20, 8), c(0, 8)));
        expect("syscall row length", "length-mismatch", syscall, 3, op(PcodeOp.CALLOTHER, null, c(0x5, 4)));
        expect("empty lift", "empty-lift", syscall, 2);
        var int2e = kernel("covered", "46", 2, "cd2e");
        expect("int 2e", null, int2e, 2, op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(0x2e, 1)),
            op(PcodeOp.CALLIND, null, u(0x100)));
        expect("int 2e with a wrong vector", "contradictory-lift", int2e, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(0x2d, 1)), op(PcodeOp.CALLIND, null, u(0x100)));
        expect("an unrelated op with vector 46", "contradictory-lift", int2e, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x30, 4), c(0x2e, 1)), op(PcodeOp.CALLIND, null, u(0x100)));
        expect("int 2e calling another temporary", "contradictory-lift", int2e, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(0x2e, 1)), op(PcodeOp.CALLIND, null, u(0x200)));
        var int3 = kernel("trap", "3", 1, "cc");
        expect("int3 (CC, closing RETURN)", null, int3, 1, op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(3, 1)),
            op(PcodeOp.CALLIND, null, u(0x100)), op(PcodeOp.RETURN, null, c(0, 1)));
        expect("int3 (CC) without its closing RETURN", "contradictory-lift", int3, 1,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(3, 1)), op(PcodeOp.CALLIND, null, u(0x100)));
        expect("int3 (CC) closing with RETURN 1", "contradictory-lift", int3, 1,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(3, 1)), op(PcodeOp.CALLIND, null, u(0x100)),
            op(PcodeOp.RETURN, null, c(1, 1)));
        expect("int3 (CC) closing with RETURN of a temporary", "contradictory-lift", int3, 1,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(3, 1)), op(PcodeOp.CALLIND, null, u(0x100)),
            op(PcodeOp.RETURN, null, u(0x100)));
        var cd03 = kernel("trap", "3", 2, "cd03");
        expect("CD 03 with a RETURN", "contradictory-lift", cd03, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(3, 1)), op(PcodeOp.CALLIND, null, u(0x100)),
            op(PcodeOp.RETURN, null, c(0, 1)));
        var int29 = kernel("trap", "41", 2, "cd29");
        expect("int 29h", null, int29, 2, op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(0x29, 1)),
            op(PcodeOp.CALLIND, null, u(0x100)));
        expect("int 29h lifted with vector 3", "kernel-undecidable", int29, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(3, 1)), op(PcodeOp.CALLIND, null, u(0x100)));
        var ud2 = kernel("trap", "ud", 2, "0f0b");
        expect("ud2", null, ud2, 2, op(PcodeOp.CALLOTHER, u(0x100), c(0x20, 4)), op(PcodeOp.BRANCHIND, null, u(0x100)));
        expect("ud2 branching on another temporary", "contradictory-lift", ud2, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x20, 4)), op(PcodeOp.BRANCHIND, null, u(0x200)));
        expect("ud2 lifted as another op", "contradictory-lift", ud2, 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x30, 4)), op(PcodeOp.BRANCHIND, null, u(0x100)));
        expect("uncovered", "kernel-uncovered", kernel("uncovered", "128", 2, "cd80"), 2,
            op(PcodeOp.CALLOTHER, u(0x100), c(0x10, 4), c(0x80, 1)), op(PcodeOp.CALLIND, null, u(0x100)));

        // -- checkpoints -------------------------------------------------------------------------------
        byte[] bytes = {0x0F, 0x05, (byte) 0x90};
        PcodeOp[] pcode = {op(PcodeOp.COPY, r(0, 8), c(1, 8))};
        Address[] flows = {RAM.getAddress(0x2000)};
        Program base = view(bytes, 1, flows, pcode);
        if (!digest(base).equals(digest(view(bytes, 1, flows, pcode)))) {
            throw new AssertionError("the same view must give the same digest");
        }
        GhidraV2StackSwitchScanner.requireSameListing(digest(base), digest(base), digest(base));
        refused("a listed target", base, view(bytes, 1, new Address[] {RAM.getAddress(0x3000)}, pcode));
        refused("an exported p-code operand", base, view(bytes, 1, flows,
            new PcodeOp[] {op(PcodeOp.COPY, r(0, 8), c(2, 8))}));
        refused("byte two after a one-byte 0F row", base, view(new byte[] {0x0F, 0x34, (byte) 0x90}, 1, flows, pcode));
        // (Astra X-1a r3 #3) the exporter's line is built from the lift it serializes, not a second read
        Instruction row = base.getListing().getInstructionAt(RAM.getAddress(0x1000));
        PcodeOp[] serialized = {op(PcodeOp.COPY, r(0, 8), c(2, 8))};
        String fromSerialized = GhidraV2StackSwitchScanner.attestedLine(row, serialized);
        if (fromSerialized.equals(GhidraV2StackSwitchScanner.attestedLine(row))
                || !fromSerialized.equals(GhidraV2StackSwitchScanner.attestedLine(
                    view(bytes, 1, flows, serialized).getListing().getInstructionAt(RAM.getAddress(0x1000))))) {
            throw new AssertionError("the attested line must follow the passed lift");
        }
        System.out.println("ok");
    }
}
'''


def _ghidra() -> Path | None:
    return next((path for path in GHIDRA_CANDIDATES if (path / "Ghidra").is_dir()), None)


def test_the_scanner_java(tmp_path):
    ghidra = _ghidra()
    if shutil.which("javac") is None or shutil.which("java") is None or ghidra is None:
        pytest.skip("javac / java / Ghidra 12.0.4 unavailable")
    jars = ":".join(str(path) for path in sorted((ghidra / "Ghidra").rglob("*.jar")))
    classes = tmp_path / "classes"
    classes.mkdir()
    source = ROOT / "ghidra" / "GhidraV2StackSwitchScanner.java"
    shutil.copy(source, tmp_path / source.name)
    (tmp_path / "ScannerJavaTest.java").write_text(HARNESS)
    subprocess.run(["javac", "-nowarn", "-proc:none", "-cp", jars, "-d", str(classes),
                    str(tmp_path / source.name), str(tmp_path / "ScannerJavaTest.java")],
                   check=True, capture_output=True, text=True, timeout=600)
    done = subprocess.run(["java", "-cp", f"{classes}:{jars}", "ScannerJavaTest"], capture_output=True, text=True,
                          timeout=600)
    assert done.returncode == 0 and "ok" in done.stdout, done.stderr[-3000:]

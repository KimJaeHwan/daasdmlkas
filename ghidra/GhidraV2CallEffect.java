// Package-private call-effect capture for the pinned configured runner.
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.ParameterPieces;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.PrototypePieces;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeDataTypeManager;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

final class GhidraV2CallEffect {
    static final String SCHEMA_ID = "tdo-v2-call-effect-sidecar-v1";
    static final int SCHEMA_VERSION = 1;
    static final int EXPORTER_REVISION = 1;
    static final String GHIDRA_VERSION = "12.0.4";
    static final String MANIFEST_SCHEMA_ID = "tdo-v2-configured-bundle-manifest-v2";
    static final String SEAL_SCHEMA_ID = "tdo-v2-configured-bundle-seal-v2";
    private static final int MAX_CALLS = 16384;
    private static final int MAX_FIXED_FORMALS = 1024;
    private static final int MAX_RETURNED_PARAMETERS = 1026;
    private static final int MAX_OVERRIDE_FIXED_SHAPES = 1024;
    private static final int MAX_CUSTOM_PARAMETERS = 1024;
    private static final int MAX_SLOTS_PER_DIRECTION = 1024;
    private static final int MAX_PIECES_PER_ASSIGNMENT = 64;
    private static final int MAX_CAPTURED_PIECES_PER_CALL = 8192;
    private static final int MAX_OVERRIDE_SYMBOLS = 4096;
    private static final int MAX_SELECTED_OVERRIDES = 64;
    private static final int MAX_TEXT_BYTES = 4096;
    private static final long WATCHDOG_SECONDS = 60L;
    private static final long CANCEL_INTERVAL = 64L * 1024L;
    private static final BigInteger U64_LIMIT = BigInteger.ONE.shiftLeft(64);
    private static final String ROW_DOMAIN = "tdo-v2-call-effect-row-v1";
    private static final String CONTENT_DOMAIN = "tdo-v2-call-effect-content-v1";
    private static final String[] RUNTIME_CLASS_IDS = {
        "GhidraV2BundleExport", "GhidraV2CallEffect",
        "GhidraV2CallInterfaceProfile", "GhidraV2CallNaming"
    };

    private GhidraV2CallEffect() {}

    static Map<String, Object> capture(Program program, Function selectedFunction,
            GhidraV2CallInterfaceProfile.CaptureSession profileSession,
            TaskMonitor monitor, String exporterSourceSha256,
            String generationId, String manifestSchemaId, String sealSchemaId,
            String observationMemberId, String observationMemberSha256,
            String profileMemberId, String profileMemberSha256,
            List<Map<String, Object>> runtimeClasses) throws Exception {
        return capture(program, selectedFunction, profileSession, monitor,
            exporterSourceSha256, generationId, manifestSchemaId, sealSchemaId,
            observationMemberId, observationMemberSha256, profileMemberId,
            profileMemberSha256, runtimeClasses, selectedFunction.getBody());
    }

    static Map<String, Object> capture(Program program, Function selectedFunction,
            GhidraV2CallInterfaceProfile.CaptureSession profileSession,
            TaskMonitor monitor, String exporterSourceSha256,
            String generationId, String manifestSchemaId, String sealSchemaId,
            String observationMemberId, String observationMemberSha256,
            String profileMemberId, String profileMemberSha256,
            List<Map<String, Object>> runtimeClasses,
            AddressSetView observedBody) throws Exception {
        requireLiveSelection(program, selectedFunction, monitor);
        if (observedBody == null || !observedBody.contains(selectedFunction.getEntryPoint())) {
            throw new IllegalArgumentException(
                "observed function body must contain its entry");
        }
        byte[] exporterDigest = digestBytes(exporterSourceSha256,
            "effect exporter source SHA-256");
        byte[] generationDigest = digestBytes(generationId, "generation ID");
        byte[] observationDigest = digestBytes(
            observationMemberSha256, "observation member SHA-256");
        byte[] profileMemberDigest = digestBytes(
            profileMemberSha256, "profile member SHA-256");
        if (!MANIFEST_SCHEMA_ID.equals(manifestSchemaId) ||
                !SEAL_SCHEMA_ID.equals(sealSchemaId)) {
            throw new IllegalArgumentException("effect transport schema identity is unsupported");
        }
        String observationId = text(observationMemberId, "observation member ID");
        String profileId = text(profileMemberId, "profile member ID");
        List<Map<String, Object>> runtimeJson = runtimeClasses(runtimeClasses);
        if (profileSession == null) {
            throw new IllegalArgumentException("effect capture requires a profile session");
        }

        PrototypeModel[] models = null;
        GhidraV2CallInterfaceProfile.RowMetadata[] metadata = null;
        try {
            Map<String, Object> profileJson = profileSession.profileJson();
            models = profileSession.modelReferences();
            PrototypeModel defaultModel = profileSession.defaultModelReference();
            metadata = profileSession.rowMetadata();
            SessionView session = sessionView(
                profileJson, models, defaultModel, metadata);
            CaptureWatchdog watchdog = CaptureWatchdog.arm();
            Exception primaryException = null;
            Error primaryError = null;
            try {
                return captureBody(program, selectedFunction, observedBody, monitor, session,
                    exporterDigest, generationDigest, manifestSchemaId, sealSchemaId,
                    observationId, observationDigest, profileId, profileMemberDigest,
                    runtimeJson);
            }
            catch (Exception exception) {
                primaryException = exception;
                throw exception;
            }
            catch (Error error) {
                primaryError = error;
                throw error;
            }
            finally {
                try {
                    watchdog.complete();
                }
                catch (RuntimeException failure) {
                    if (primaryException != null) primaryException.addSuppressed(failure);
                    else if (primaryError != null) primaryError.addSuppressed(failure);
                    else throw failure;
                }
            }
        }
        finally {
            if (models != null) Arrays.fill(models, null);
            if (metadata != null) Arrays.fill(metadata, null);
        }
    }

    private static Map<String, Object> captureBody(Program program, Function selectedFunction,
            AddressSetView observedBody, TaskMonitor monitor, SessionView session,
            byte[] exporterDigest,
            byte[] generationDigest, String manifestSchemaId, String sealSchemaId,
            String observationMemberId, byte[] observationMemberDigest,
            String profileMemberId, byte[] profileMemberDigest,
            List<Map<String, Object>> runtimeClasses) throws Exception {
        monitor.checkCancelled();
        OverrideScan overrides = OverrideScan.capture(program, selectedFunction, monitor);
        JsonMaterializer output = new JsonMaterializer(monitor);
        output.adopt(runtimeClasses);
        List<Map<String, Object>> calls = new ArrayList<>();
        int expectedCallCount = countCallRows(program, observedBody, monitor);
        DigestEncoder contentEncoder = new DigestEncoder(monitor);
        contentEncoder.text(CONTENT_DOMAIN);
        contentEncoder.u64(SCHEMA_VERSION);
        contentEncoder.u64(EXPORTER_REVISION);
        contentEncoder.bytes(exporterDigest);
        contentEncoder.text(GHIDRA_VERSION);
        contentEncoder.bytes(session.profileContentDigest);
        contentEncoder.u64(expectedCallCount);
        InstructionIterator instructions = program.getListing().getInstructions(
            observedBody, true);
        if (instructions == null) schema("instruction iterator is null");
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (instruction == null || instruction.getProgram() != program) {
                schema("instruction is null or belongs to another Program");
            }
            PcodeOp[] operations = instruction.getPcode();
            if (operations == null) schema("instruction P-Code array is null");
            Address instructionAddress = instruction.getAddress();
            Coordinate instructionCoordinate = coordinate(instructionAddress, "instruction");
            OverrideEvidence instructionOverrides = null;
            for (int ordinal = 0; ordinal < operations.length; ordinal++) {
                PcodeOp operation = operations[ordinal];
                if (operation == null) schema("instruction P-Code contains null");
                int opcode = operation.getOpcode();
                if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND) continue;
                monitor.checkCancelled();
                if (calls.size() >= MAX_CALLS) resource("call rows exceed their bound");
                if (instructionOverrides == null) {
                    instructionOverrides = overrides.forInstruction(instructionAddress, monitor);
                }
                Selector selector = selector(operation);
                PieceBudget pieceBudget = new PieceBudget();
                InterfaceCapture interfaceCapture = captureInterface(
                    program, opcode, selector, instructionOverrides, session,
                    monitor, pieceBudget);
                EffectRow row = new EffectRow(
                    instructionCoordinate, BigInteger.valueOf(ordinal),
                    opcode == PcodeOp.CALL ? "CALL" : "CALLIND", selector,
                    instructionOverrides, interfaceCapture);
                DigestEncoder rowEncoder = new DigestEncoder(monitor);
                rowEncoder.text(ROW_DOMAIN);
                rowEncoder.mirrorTo(contentEncoder);
                try {
                    row.encodeBody(rowEncoder);
                }
                finally {
                    rowEncoder.stopMirroring(contentEncoder);
                }
                row.digest = rowEncoder.finish();
                contentEncoder.bytes(row.digest);
                calls.add(row.json(output));
                monitor.checkCancelled();
            }
            monitor.checkCancelled();
        }
        monitor.checkCancelled();
        if (calls.size() != expectedCallCount) {
            schema("call row count changed during capture");
        }
        byte[] contentDigest = contentEncoder.finish();
        Coordinate entry = coordinate(selectedFunction.getEntryPoint(), "function entry");
        Map<String, Object> transport = output.map(
            "generation_id", hex(generationDigest),
            "manifest_schema_id", manifestSchemaId,
            "seal_schema_id", sealSchemaId,
            "observation_member_id", observationMemberId,
            "observation_member_sha256", hex(observationMemberDigest),
            "call_interface_profile_member_id", profileMemberId,
            "call_interface_profile_member_sha256", hex(profileMemberDigest),
            "function_entry", entry.json(output),
            "runtime_classes", runtimeClasses);
        Map<String, Object> root = output.map(
            "schema_id", SCHEMA_ID,
            "schema_version", BigInteger.valueOf(SCHEMA_VERSION),
            "exporter_revision", BigInteger.valueOf(EXPORTER_REVISION),
            "exporter_source_sha256", hex(exporterDigest),
            "ghidra_version", GHIDRA_VERSION,
            "transport", transport,
            "call_interface_profile_semantic_content_digest",
                hex(session.profileContentDigest),
            "calls", output.list(calls),
            "semantic_content_digest", hex(contentDigest));
        monitor.checkCancelled();
        return root;
    }

    private static int countCallRows(Program program, AddressSetView observedBody,
            TaskMonitor monitor) throws CancelledException {
        int count = 0;
        InstructionIterator instructions = program.getListing().getInstructions(
            observedBody, true);
        if (instructions == null) schema("instruction iterator is null");
        while (instructions.hasNext()) {
            monitor.checkCancelled();
            Instruction instruction = instructions.next();
            if (instruction == null || instruction.getProgram() != program) {
                schema("instruction is null or belongs to another Program");
            }
            PcodeOp[] operations = instruction.getPcode();
            if (operations == null) schema("instruction P-Code array is null");
            for (PcodeOp operation : operations) {
                monitor.checkCancelled();
                if (operation == null) schema("instruction P-Code contains null");
                int opcode = operation.getOpcode();
                if (opcode != PcodeOp.CALL && opcode != PcodeOp.CALLIND) continue;
                if (count >= MAX_CALLS) resource("call rows exceed their bound");
                count++;
            }
        }
        monitor.checkCancelled();
        return count;
    }

    private static void requireLiveSelection(
            Program program, Function function, TaskMonitor monitor) {
        if (program == null || monitor == null || program.isClosed()) {
            throw new IllegalArgumentException(
                "effect capture requires a live Program and monitor");
        }
        if (!GHIDRA_VERSION.equals(Application.getApplicationVersion())) {
            throw new IllegalStateException("unsupported Ghidra version");
        }
        if (function == null || function.isDeleted() || function.getProgram() != program) {
            throw new IllegalArgumentException(
                "selected Function is not live in the exact Program");
        }
        Address entry = function.getEntryPoint();
        FunctionManager manager = program.getFunctionManager();
        if (entry == null || manager == null || manager.getProgram() != program ||
                manager.getFunctionAt(entry) != function) {
            throw new IllegalArgumentException(
                "selected Function is not the exact Program member");
        }
    }

    private static SessionView sessionView(Map<String, Object> profileJson,
            PrototypeModel[] models, PrototypeModel defaultModel,
            GhidraV2CallInterfaceProfile.RowMetadata[] metadata) {
        if (profileJson == null || models == null || metadata == null ||
                models.length != metadata.length) {
            schema("profile session inventory is inconsistent");
        }
        Object digestValue = profileJson.get("semantic_content_digest");
        if (!(digestValue instanceof String)) {
            schema("profile semantic-content digest is absent");
        }
        byte[] profileDigest = digestBytes(
            (String)digestValue, "profile semantic-content digest");
        for (int index = 0; index < models.length; index++) {
            if (models[index] == null || metadata[index] == null ||
                    !metadata[index].inventoryOrdinal().equals(BigInteger.valueOf(index))) {
                schema("profile session inventory ordinal is inconsistent");
            }
            digestBytes(metadata[index].modelDigest(), "profile model digest");
        }
        return new SessionView(models, defaultModel, metadata, profileDigest);
    }

    private static Selector selector(PcodeOp operation) {
        if (operation.getNumInputs() == 0) return null;
        Varnode varnode = operation.getInput(0);
        if (varnode == null) schema("call selector is null");
        int size = varnode.getSize();
        if (size <= 0) schema("call selector size is not positive");
        Address address = varnode.getAddress();
        Coordinate coordinate = coordinate(address, "call selector");
        requireExtent(coordinate.byteOffset, BigInteger.valueOf(size), "call selector");
        return new Selector(kind(address), coordinate, BigInteger.valueOf(size), address);
    }

    private static InterfaceCapture captureInterface(Program program, int opcode,
            Selector selector, OverrideEvidence overrides, SessionView session,
            TaskMonitor monitor, PieceBudget pieceBudget) throws Exception {
        if (opcode == PcodeOp.CALLIND) return new NoInterface("INDIRECT_CALL");
        if (selector == null) return new NoInterface("MISSING_SELECTOR");
        if (selector.kindCode == 7) return new NoInterface("OPAQUE_SELECTOR");
        if (selector.kindCode != 4) return new NoInterface("NON_ADDRESS_SELECTOR");
        Function subject = program.getFunctionManager().getFunctionAt(selector.address);
        if (subject == null || subject.getProgram() != program || subject.isDeleted()) {
            return new NoInterface("NO_EXACT_FUNCTION");
        }
        Address subjectEntry = subject.getEntryPoint();
        if (subjectEntry == null || !subjectEntry.equals(selector.address)) {
            return new NoInterface("NO_EXACT_FUNCTION");
        }
        Coordinate subjectCoordinate = selector.coordinate;
        if (!overrides.selected.isEmpty()) {
            return new Unassignable(subjectCoordinate, "OVERRIDE_PRESENT", null);
        }
        if (subject.isThunk()) {
            return new Unassignable(subjectCoordinate, "THUNK_INTERFACE_DELEGATED", null);
        }
        if (subject.hasCustomVariableStorage()) {
            CustomStorage custom = captureCustomStorage(
                subject, program, monitor, pieceBudget);
            return new Unassignable(
                subjectCoordinate, "CUSTOM_STORAGE_PRESENT", custom);
        }
        ModelResolution model = resolveModel(subject, session);
        if (!model.assignable()) {
            return new Unassignable(subjectCoordinate, model.reason, null);
        }
        try {
            return captureAssignment(subjectCoordinate, subject, program,
                model, monitor, pieceBudget);
        }
        catch (InvalidAllocation failure) {
            return new Unassignable(subjectCoordinate, "INVALID_ALLOCATION_SHAPE", null);
        }
        catch (CorrelationFailure failure) {
            return new Unassignable(subjectCoordinate, failure.reason, null);
        }
        catch (AssignmentFailure failure) {
            return new Unassignable(subjectCoordinate, "ASSIGNMENT_FAILED", null);
        }
    }

    private static ModelResolution resolveModel(Function subject, SessionView session) {
        String convention = subject.getCallingConventionName();
        if (convention == null || Function.UNKNOWN_CALLING_CONVENTION_STRING.equals(convention)) {
            return ModelResolution.failure("UNKNOWN_CONVENTION");
        }
        boolean programDefault = Function.DEFAULT_CALLING_CONVENTION_STRING.equals(convention);
        PrototypeModel candidate = programDefault
            ? session.defaultModel : subject.getCallingConvention();
        if (candidate == null) return ModelResolution.failure("MODEL_ABSENT");
        int match = -1;
        for (int index = 0; index < session.models.length; index++) {
            if (candidate == session.models[index]) {
                if (match != -1) {
                    return ModelResolution.failure("MODEL_REFERENCE_AMBIGUOUS");
                }
                match = index;
            }
        }
        if (match == -1) return ModelResolution.failure("MODEL_NOT_PERMITTED");
        GhidraV2CallInterfaceProfile.RowMetadata row = session.metadata[match];
        if (row.isErrorPlaceholder()) {
            return ModelResolution.failure("MODEL_ERROR_PLACEHOLDER");
        }
        if (row.isMerged() || programDefault && !row.allowProgramDefault() ||
                !programDefault && !row.allowExplicit()) {
            return ModelResolution.failure("MODEL_NOT_PERMITTED");
        }
        if (programDefault && candidate != session.defaultModel) {
            return ModelResolution.failure("MODEL_NOT_PERMITTED");
        }
        return ModelResolution.success(candidate, row,
            programDefault ? "PROGRAM_DEFAULT" : "EXPLICIT_REFERENCE");
    }

    private static InterfaceCapture captureAssignment(Coordinate subjectCoordinate,
            Function subject, Program program, ModelResolution model,
            TaskMonitor monitor, PieceBudget pieceBudget) throws Exception {
        Parameter[] returned = subject.getParameters();
        if (returned == null) schema("returned parameter array is null");
        if (returned.length > MAX_RETURNED_PARAMETERS) {
            resource("returned parameters exceed their bound");
        }
        Parameter resultParameter = subject.getReturn();
        if (resultParameter == null) schema("function result parameter is null");
        List<Parameter> fixedParameters = new ArrayList<>();
        Parameter thisParameter = null;
        int thisOrdinal = -1;
        int returnPointerCount = 0;
        boolean unexpectedAuto = false;
        for (int ordinal = 0; ordinal < returned.length; ordinal++) {
            Parameter parameter = returned[ordinal];
            if (parameter == null) schema("returned parameter array contains null");
            if (!parameter.isAutoParameter()) {
                if (fixedParameters.size() >= MAX_FIXED_FORMALS) {
                    resource("fixed formals exceed their bound");
                }
                fixedParameters.add(parameter);
                continue;
            }
            AutoParameterType auto = parameter.getAutoParameterType();
            if (auto == AutoParameterType.THIS) {
                if (thisParameter != null) unexpectedAuto = true;
                else {
                    thisParameter = parameter;
                    thisOrdinal = ordinal;
                }
            }
            else if (auto == AutoParameterType.RETURN_STORAGE_PTR) {
                returnPointerCount++;
                if (returnPointerCount > 1) unexpectedAuto = true;
            }
            else unexpectedAuto = true;
        }

        List<Formal> formals = new ArrayList<>(fixedParameters.size());
        List<DataType> fixedTypes = new ArrayList<>(fixedParameters.size());
        for (int ordinal = 0; ordinal < fixedParameters.size(); ordinal++) {
            Parameter parameter = fixedParameters.get(ordinal);
            DataType type = parameter.getFormalDataType();
            AllocationShape shape = allocationShape(type);
            fixedTypes.add(type);
            formals.add(new Formal(BigInteger.valueOf(ordinal),
                quality(parameter.getSource()), shape));
        }
        DataType resultType = resultParameter.getFormalDataType();
        AllocationShape resultShape = allocationShape(resultType);
        ResultShape result = new ResultShape(
            quality(resultParameter.getSource()), resultShape.metatypeCode == 14,
            resultShape);
        Signature signature = new Signature(
            quality(subject.getSignatureSource()), subject.hasVarArgs(),
            subject.hasNoReturn(), immutable(formals), result);
        boolean hasThis = model.model.hasThisPointer();
        if (hasThis != (thisParameter != null)) {
            throw new CorrelationFailure("THIS_CORRELATION_FAILED");
        }
        AllocationShape thisShape = null;
        DataType thisType = null;
        if (thisParameter != null) {
            thisType = thisParameter.getFormalDataType();
            thisShape = allocationShape(thisType);
        }
        if (unexpectedAuto) {
            throw new CorrelationFailure("UNEXPECTED_AUTO_PARAMETER");
        }

        PrototypePieces prototype = new PrototypePieces(model.model, resultType);
        if (hasThis) prototype.intypes.add(thisType);
        prototype.intypes.addAll(fixedTypes);
        prototype.firstVarArgSlot = signature.hasVarargs
            ? fixedTypes.size() + (hasThis ? 1 : 0) : -1;
        ArrayList<ParameterPieces> assignments = new ArrayList<>();
        monitor.checkCancelled();
        try {
            model.model.assignParameterStorage(
                prototype, program.getDataTypeManager(), assignments, true);
        }
        catch (RuntimeException failure) {
            throw new AssignmentFailure(failure);
        }
        monitor.checkCancelled();
        if (assignments.isEmpty()) throw new AssignmentFailure(null);
        if (assignments.size() - 1 > MAX_SLOTS_PER_DIRECTION) {
            resource("PRE_READ slots exceed their bound");
        }
        ParameterPieces output = assignments.get(0);
        if (output == null || output.isThisPointer || output.hiddenReturnPtr) {
            throw new CorrelationFailure("FORMAL_CORRELATION_FAILED");
        }
        int fixedIndex = 0;
        int assignedThisCount = 0;
        int assignedHiddenCount = 0;
        for (int index = 1; index < assignments.size(); index++) {
            ParameterPieces pieces = assignments.get(index);
            if (pieces == null) throw new AssignmentFailure(null);
            if (pieces.isThisPointer && pieces.hiddenReturnPtr) {
                throw new CorrelationFailure("UNEXPECTED_AUTO_PARAMETER");
            }
            if (pieces.isThisPointer) assignedThisCount++;
            else if (pieces.hiddenReturnPtr) assignedHiddenCount++;
            else fixedIndex++;
        }
        if (fixedIndex != fixedParameters.size() ||
                assignedHiddenCount != returnPointerCount ||
                assignments.size() != fixedParameters.size() + assignedThisCount +
                    assignedHiddenCount + 1) {
            throw new CorrelationFailure("FORMAL_CORRELATION_FAILED");
        }
        if (assignedThisCount != (hasThis ? 1 : 0)) {
            throw new CorrelationFailure("THIS_CORRELATION_FAILED");
        }
        if (unexpectedAuto || assignedHiddenCount > 1) {
            throw new CorrelationFailure("UNEXPECTED_AUTO_PARAMETER");
        }

        List<Slot> preSlots = new ArrayList<>(assignments.size() - 1);
        int correlatedFormal = 0;
        for (int assignmentOrdinal = 1;
                assignmentOrdinal < assignments.size(); assignmentOrdinal++) {
            monitor.checkCancelled();
            if (preSlots.size() >= MAX_SLOTS_PER_DIRECTION) {
                resource("PRE_READ slots exceed their bound");
            }
            ParameterPieces pieces = assignments.get(assignmentOrdinal);
            Correlation correlation;
            AllocationShape shape;
            if (pieces.isThisPointer) {
                correlation = Correlation.thisParameter(BigInteger.valueOf(thisOrdinal));
                shape = thisShape;
            }
            else if (pieces.hiddenReturnPtr) {
                correlation = Correlation.simple("HIDDEN_RETURN_POINTER");
                shape = allocationShape(pieces.type);
                if (shape.metatypeCode != 6) {
                    throw new CorrelationFailure("FORMAL_CORRELATION_FAILED");
                }
            }
            else {
                if (correlatedFormal >= formals.size()) {
                    throw new CorrelationFailure("FORMAL_CORRELATION_FAILED");
                }
                correlation = Correlation.fixed(BigInteger.valueOf(correlatedFormal));
                shape = formals.get(correlatedFormal).shape;
                correlatedFormal++;
            }
            Assignment assignment = captureParameterPieces(
                pieces, program, monitor, pieceBudget);
            preSlots.add(new Slot(BigInteger.valueOf(preSlots.size()),
                BigInteger.valueOf(assignmentOrdinal), correlation, shape,
                pieces.isIndirect, assignment));
            monitor.checkCancelled();
        }
        if (correlatedFormal != formals.size()) {
            throw new CorrelationFailure("FORMAL_CORRELATION_FAILED");
        }
        monitor.checkCancelled();
        Assignment outputAssignment = captureParameterPieces(
            output, program, monitor, pieceBudget);
        Slot outputSlot = new Slot(BigInteger.ZERO, BigInteger.ZERO,
            Correlation.simple("RESULT"), result.shape, output.isIndirect,
            outputAssignment);
        monitor.checkCancelled();
        Direction pre = new Direction("PRE_READ", signature.hasVarargs,
            immutable(preSlots));
        Direction post = new Direction("POST_WRITE", false,
            immutable(List.of(outputSlot)));
        VarargBoundary boundary = signature.hasVarargs
            ? VarargBoundary.present(BigInteger.valueOf(
                fixedTypes.size() + (hasThis ? 1 : 0)))
            : VarargBoundary.notVarargs();
        ModelSelection selection = new ModelSelection(model.state,
            model.row.inventoryOrdinal(), model.row.modelDigest(), hasThis);
        return new AssignmentCaptured(subjectCoordinate,
            BigInteger.valueOf(returned.length), selection, signature, boundary,
            immutable(List.of(pre, post)));
    }

    private static CustomStorage captureCustomStorage(Function subject, Program program,
            TaskMonitor monitor, PieceBudget pieceBudget) throws Exception {
        Parameter resultParameter = subject.getReturn();
        if (resultParameter == null) schema("custom result parameter is null");
        Parameter[] parameters = subject.getParameters();
        if (parameters == null) schema("custom parameter array is null");
        if (parameters.length > MAX_CUSTOM_PARAMETERS) {
            resource("custom parameters exceed their bound");
        }
        AllocationShape resultShape = allocationShape(resultParameter.getFormalDataType());
        CustomResult result = new CustomResult(
            quality(resultParameter.getSource()), resultShape.metatypeCode == 14,
            resultShape, captureStorage(resultParameter.getVariableStorage(), null,
                program, monitor, pieceBudget));
        List<CustomParameter> captured = new ArrayList<>(parameters.length);
        for (int ordinal = 0; ordinal < parameters.length; ordinal++) {
            monitor.checkCancelled();
            Parameter parameter = parameters[ordinal];
            if (parameter == null || parameter.getOrdinal() != ordinal) {
                schema("custom parameter database order is not gap-free");
            }
            AllocationShape shape = allocationShape(parameter.getFormalDataType());
            captured.add(new CustomParameter(BigInteger.valueOf(ordinal),
                quality(parameter.getSource()), shape,
                captureStorage(parameter.getVariableStorage(), null,
                    program, monitor, pieceBudget)));
            monitor.checkCancelled();
        }
        return new CustomStorage(result, immutable(captured));
    }

    private static Assignment captureParameterPieces(ParameterPieces pieces,
            Program program, TaskMonitor monitor, PieceBudget pieceBudget)
            throws Exception {
        monitor.checkCancelled();
        VariableStorage storage;
        try {
            storage = pieces.getVariableStorage(program);
        }
        catch (RuntimeException failure) {
            throw new AssignmentFailure(failure);
        }
        Assignment result = captureStorage(
            storage, pieces.joinPieces, program, monitor, pieceBudget);
        monitor.checkCancelled();
        return result;
    }

    private static Assignment captureStorage(VariableStorage storage,
            Varnode[] joinPieces, Program program, TaskMonitor monitor,
            PieceBudget pieceBudget) throws Exception {
        if (storage == null) schema("storage is null");
        boolean valid = storage.isValid();
        boolean bad = storage.isBadStorage();
        boolean unassigned = storage.isUnassignedStorage();
        boolean isVoid = storage.isVoidStorage();
        int signedSize = storage.size();
        if (signedSize < 0) {
            throw new IllegalStateException(
                "EFFECT_EXPORT_INVALID_STORAGE_SIZE: negative VariableStorage.size()");
        }
        int varnodeCount = storage.getVarnodeCount();
        if (varnodeCount < 0) schema("storage varnode count is negative");
        StorageFacts facts = new StorageFacts(valid, bad, unassigned, isVoid,
            BigInteger.valueOf(signedSize), BigInteger.valueOf(varnodeCount));
        String state;
        if (facts.isVoid) state = "VOID";
        else if (facts.unassigned) state = "UNASSIGNED";
        else if (facts.bad || !facts.valid) state = "BAD";
        else state = "ASSIGNED";
        if (!"ASSIGNED".equals(state)) {
            if (signedSize != 0 || varnodeCount != 0) {
                schema("non-assigned storage has nonzero size or count");
            }
            return new Assignment(state, facts, null);
        }
        if (storage.getProgramArchitecture() != program) {
            schema("assigned storage belongs to another Program");
        }
        Varnode[] varnodes;
        String ordinaryOrigin;
        if (joinPieces != null && joinPieces.length != 0) {
            if (joinPieces.length > MAX_PIECES_PER_ASSIGNMENT) {
                resource("assignment pieces exceed their bound");
            }
            varnodes = joinPieces;
            ordinaryOrigin = "JOIN_COMPONENT";
        }
        else {
            varnodes = storage.getVarnodes();
            if (varnodes == null) schema("assigned storage varnode array is null");
            if (varnodes.length > MAX_PIECES_PER_ASSIGNMENT) {
                resource("assignment pieces exceed their bound");
            }
            ordinaryOrigin = "DIRECT_STORAGE";
        }
        if (varnodes.length == 0 || varnodes.length != varnodeCount) {
            schema("assigned storage piece count disagrees with storage facts");
        }
        List<Piece> captured = new ArrayList<>(varnodes.length);
        BigInteger sum = BigInteger.ZERO;
        for (int ordinal = 0; ordinal < varnodes.length; ordinal++) {
            monitor.checkCancelled();
            pieceBudget.reserve();
            Varnode varnode = varnodes[ordinal];
            if (varnode == null || varnode.getSize() <= 0) {
                schema("assigned storage contains an invalid varnode");
            }
            Address address = varnode.getAddress();
            String storageClass = storageClass(address);
            String origin = ordinaryOrigin;
            if ("JOIN".equals(storageClass)) {
                if (joinPieces != null && joinPieces.length != 0 || varnodes.length != 1) {
                    schema("synthetic join cannot coexist with concrete pieces");
                }
                origin = "SYNTHETIC_JOIN";
            }
            Coordinate coordinate = coordinate(address, "storage piece");
            BigInteger size = BigInteger.valueOf(varnode.getSize());
            requireExtent(coordinate.byteOffset, size, "storage piece");
            sum = sum.add(size);
            if (sum.compareTo(U64_LIMIT) >= 0) {
                schema("storage piece size sum exceeds unsigned 64-bit");
            }
            captured.add(new Piece(BigInteger.valueOf(ordinal), origin,
                storageClass, storageKind(storageClass), coordinate, size));
            monitor.checkCancelled();
        }
        if (!sum.equals(facts.totalByteSize)) {
            schema("assigned storage piece sizes disagree with storage facts");
        }
        return new Assignment(state, facts, immutable(captured));
    }

    private static AllocationShape allocationShape(DataType type) {
        if (type == null) throw new InvalidAllocation();
        if (VoidDataType.isVoidDataType(type)) {
            return new AllocationShape(14, BigInteger.ZERO);
        }
        int length = type.getLength();
        if (length <= 0) throw new InvalidAllocation();
        int metatype = PcodeDataTypeManager.getMetatype(type);
        if (metatype != PcodeDataTypeManager.TYPE_UNION &&
                metatype != PcodeDataTypeManager.TYPE_STRUCT &&
                metatype != PcodeDataTypeManager.TYPE_ARRAY &&
                metatype != PcodeDataTypeManager.TYPE_PTR &&
                metatype != PcodeDataTypeManager.TYPE_FLOAT &&
                metatype != PcodeDataTypeManager.TYPE_CODE &&
                metatype != PcodeDataTypeManager.TYPE_BOOL &&
                metatype != PcodeDataTypeManager.TYPE_UINT &&
                metatype != PcodeDataTypeManager.TYPE_INT &&
                metatype != PcodeDataTypeManager.TYPE_UNKNOWN) {
            throw new InvalidAllocation();
        }
        return new AllocationShape(metatype, BigInteger.valueOf(length));
    }

    private static String quality(SourceType source) {
        if (source == SourceType.DEFAULT) return "DEFAULT";
        if (source == SourceType.ANALYSIS) return "ANALYSIS";
        if (source == SourceType.AI) return "AI";
        if (source == SourceType.IMPORTED) return "IMPORTED";
        if (source == SourceType.USER_DEFINED) return "USER_DEFINED";
        schema("unsupported Ghidra SourceType");
        return null;
    }

    private static int kind(Address address) {
        if (address == null) schema("varnode address is null");
        if (address.isConstantAddress()) return 1;
        if (address.isRegisterAddress()) return 2;
        if (address.isUniqueAddress()) return 3;
        AddressSpace space = address.getAddressSpace();
        if (address.isMemoryAddress() && address.isLoadedMemoryAddress() &&
                !address.isNonLoadedMemoryAddress() && !address.isExternalAddress() &&
                space != null && !space.isOverlaySpace()) return 4;
        return 7;
    }

    private static String storageClass(Address address) {
        if (address == null) schema("storage address is null");
        if (address.isConstantAddress()) return "CONSTANT";
        if (address.isRegisterAddress()) return "REGISTER";
        if (address.isUniqueAddress()) return "UNIQUE";
        if (address.isStackAddress()) return "STACK";
        if (address.isHashAddress()) return "HASH";
        AddressSpace space = address.getAddressSpace();
        if (space != null && space.getType() == AddressSpace.TYPE_JOIN) return "JOIN";
        if (address.isMemoryAddress() && !address.isExternalAddress() &&
                space != null && !space.isOverlaySpace()) return "ADDRESS";
        return "OTHER";
    }

    private static int storageKind(String storageClass) {
        if ("CONSTANT".equals(storageClass)) return 1;
        if ("REGISTER".equals(storageClass)) return 2;
        if ("UNIQUE".equals(storageClass)) return 3;
        if ("ADDRESS".equals(storageClass)) return 4;
        return 7;
    }

    private static Coordinate coordinate(Address address, String label) {
        if (address == null || address.getAddressSpace() == null) {
            schema(label + " address is absent");
        }
        AddressSpace space = address.getAddressSpace();
        int bits = space.getSize();
        int unit = space.getAddressableUnitSize();
        if (bits <= 0 || bits > 64 || unit <= 0) {
            schema(label + " address-space geometry is invalid");
        }
        BigInteger capacity = BigInteger.valueOf(unit).shiftLeft(bits);
        if (capacity.compareTo(U64_LIMIT) > 0) {
            schema(label + " address-space byte capacity exceeds unsigned 64-bit");
        }
        BigInteger offset = unsignedLong(address.getUnsignedOffset());
        if (offset.compareTo(capacity) >= 0) {
            schema(label + " byte offset is outside address-space capacity");
        }
        return new Coordinate(
            BigInteger.valueOf(Integer.toUnsignedLong(space.getSpaceID())), offset);
    }

    private static void requireExtent(
            BigInteger offset, BigInteger size, String label) {
        if (size.signum() <= 0 || size.bitLength() > 64 ||
                offset.add(size).compareTo(U64_LIMIT) > 0) {
            schema(label + " extent is outside unsigned 64-bit");
        }
    }

    private static BigInteger unsignedLong(long value) {
        if (value >= 0) return BigInteger.valueOf(value);
        return BigInteger.valueOf(value & Long.MAX_VALUE).setBit(63);
    }

    private static List<Map<String, Object>> runtimeClasses(
            List<Map<String, Object>> supplied) {
        if (supplied == null || supplied.size() != RUNTIME_CLASS_IDS.length) {
            throw new IllegalArgumentException("effect runtime classes must be the exact tuple");
        }
        List<Map<String, Object>> result = new ArrayList<>(RUNTIME_CLASS_IDS.length);
        for (int index = 0; index < RUNTIME_CLASS_IDS.length; index++) {
            Map<String, Object> row = supplied.get(index);
            if (row == null || row.size() != 2 ||
                    !row.containsKey("class_id") || !row.containsKey("class_sha256") ||
                    !(row.get("class_id") instanceof String classId) ||
                    !(row.get("class_sha256") instanceof String classDigest) ||
                    !RUNTIME_CLASS_IDS[index].equals(classId)) {
                throw new IllegalArgumentException(
                    "effect runtime classes must be the exact tuple");
            }
            byte[] digest = digestBytes(classDigest, "runtime class SHA-256");
            result.add(map("class_id", RUNTIME_CLASS_IDS[index],
                "class_sha256", hex(digest)));
        }
        return immutable(result);
    }

    private static byte[] digestBytes(String value, String label) {
        if (value == null || value.length() != 64 || !value.chars().allMatch(
                character -> character >= '0' && character <= '9' ||
                    character >= 'a' && character <= 'f')) {
            throw new IllegalArgumentException(
                label + " must be 64 lowercase hexadecimal characters");
        }
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            result[index] = (byte)((high << 4) | low);
        }
        return result;
    }

    private static String text(String value, String label) {
        strictUtf8(value, label);
        return value;
    }

    private static byte[] strictUtf8(String value, String label) {
        if (value == null) throw new IllegalArgumentException(label + " must be text");
        try {
            ByteBuffer encoded = Charset.forName("UTF-8").newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(CharBuffer.wrap(value));
            byte[] result = new byte[encoded.remaining()];
            encoded.get(result);
            if (result.length == 0 || result.length > MAX_TEXT_BYTES) {
                throw new IllegalArgumentException(label + " is outside its byte bound");
            }
            return result;
        }
        catch (CharacterCodingException exception) {
            throw new IllegalArgumentException(label + " is not strict UTF-8", exception);
        }
    }

    private static byte[] hash(TaskMonitor monitor, HashAction action) throws Exception {
        DigestEncoder encoder = new DigestEncoder(monitor);
        action.accept(encoder);
        return encoder.finish();
    }

    private static String hex(byte[] bytes) {
        char[] digits = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int index = 0; index < bytes.length; index++) {
            int value = bytes[index] & 0xff;
            result[index * 2] = digits[value >>> 4];
            result[index * 2 + 1] = digits[value & 0x0f];
        }
        return new String(result);
    }

    private static Map<String, Object> map(Object... entries) {
        LinkedHashMap<String, Object> value = new LinkedHashMap<>();
        for (int index = 0; index < entries.length; index += 2) {
            value.put((String)entries[index], entries[index + 1]);
        }
        return Collections.unmodifiableMap(value);
    }

    private static final class JsonMaterializer {
        private final TaskMonitor monitor;
        private long outputBytes;
        private long nextCancellation = CANCEL_INTERVAL;
        JsonMaterializer(TaskMonitor monitor) { this.monitor = monitor; }
        void check() throws CancelledException { monitor.checkCancelled(); }
        Map<String, Object> map(Object... entries) throws CancelledException {
            check();
            LinkedHashMap<String, Object> value = new LinkedHashMap<>();
            long bytes = 2L + Math.max(0, entries.length / 2 - 1);
            for (int index = 0; index < entries.length; index += 2) {
                String key = (String)entries[index];
                Object item = entries[index + 1];
                value.put(key, item);
                bytes += scalarBytes(key) + 1L + scalarBytes(item);
            }
            account(bytes);
            return Collections.unmodifiableMap(value);
        }
        <T> List<T> list(List<T> value) throws CancelledException {
            check();
            long bytes = 2L + Math.max(0, value.size() - 1);
            for (T item : value) bytes += scalarBytes(item);
            account(bytes);
            return Collections.unmodifiableList(new ArrayList<>(value));
        }
        void adopt(Object value) throws CancelledException {
            check();
            if (value instanceof Map<?, ?> object) {
                account(2L + Math.max(0, object.size() - 1));
                for (Map.Entry<?, ?> entry : object.entrySet()) {
                    account(scalarBytes(entry.getKey()) + 1L);
                    adopt(entry.getValue());
                }
            }
            else if (value instanceof List<?> list) {
                account(2L + Math.max(0, list.size() - 1));
                for (Object item : list) adopt(item);
            }
            else account(scalarBytes(value));
        }
        private long scalarBytes(Object value) {
            if (value instanceof String text) {
                return 2L + 6L * strictUtf8(text, "materialized text").length;
            }
            if (value instanceof BigInteger integer) {
                return integer.toString().length();
            }
            if (value instanceof Boolean flag) return flag ? 4L : 5L;
            if (value instanceof Map<?, ?> || value instanceof List<?>) return 0L;
            schema("materialized output contains an unsupported value");
            return 0L;
        }
        private void account(long bytes) throws CancelledException {
            if (bytes < 0 || outputBytes > Long.MAX_VALUE - bytes) {
                resource("materialized output accounting overflowed");
            }
            outputBytes += bytes;
            while (outputBytes >= nextCancellation) {
                monitor.checkCancelled();
                if (nextCancellation > Long.MAX_VALUE - CANCEL_INTERVAL) {
                    resource("materialized output cancellation cadence overflowed");
                }
                nextCancellation += CANCEL_INTERVAL;
            }
        }
    }

    private static <T> List<T> immutable(List<T> value) {
        return Collections.unmodifiableList(new ArrayList<>(value));
    }

    private static void resource(String detail) {
        throw new IllegalStateException("EFFECT_EXPORT_RESOURCE_EXCEEDED: " + detail);
    }

    private static void schema(String detail) {
        throw new IllegalStateException("EFFECT_EXPORT_SCHEMA_INVARIANT: " + detail);
    }

    @FunctionalInterface
    private interface HashAction {
        void accept(DigestEncoder encoder) throws Exception;
    }

    private interface Encodable {
        void encode(DigestEncoder encoder) throws CancelledException;
    }

    private interface InterfaceCapture extends Encodable {
        Map<String, Object> json(JsonMaterializer output) throws CancelledException;
    }

    private static final class SessionView {
        final PrototypeModel[] models;
        final PrototypeModel defaultModel;
        final GhidraV2CallInterfaceProfile.RowMetadata[] metadata;
        final byte[] profileContentDigest;
        SessionView(PrototypeModel[] models, PrototypeModel defaultModel,
                GhidraV2CallInterfaceProfile.RowMetadata[] metadata,
                byte[] profileContentDigest) {
            this.models = models;
            this.defaultModel = defaultModel;
            this.metadata = metadata;
            this.profileContentDigest = profileContentDigest;
        }
    }

    private static final class ModelResolution {
        final PrototypeModel model;
        final GhidraV2CallInterfaceProfile.RowMetadata row;
        final String state;
        final String reason;
        private ModelResolution(PrototypeModel model,
                GhidraV2CallInterfaceProfile.RowMetadata row,
                String state, String reason) {
            this.model = model; this.row = row; this.state = state; this.reason = reason;
        }
        static ModelResolution success(PrototypeModel model,
                GhidraV2CallInterfaceProfile.RowMetadata row, String state) {
            return new ModelResolution(model, row, state, null);
        }
        static ModelResolution failure(String reason) {
            return new ModelResolution(null, null, null, reason);
        }
        boolean assignable() { return reason == null; }
    }

    private static final class PieceBudget {
        int count;
        void reserve() {
            if (count >= MAX_CAPTURED_PIECES_PER_CALL) {
                resource("captured pieces exceed their per-call bound");
            }
            count++;
        }
    }

    private static final class Coordinate implements Encodable {
        final BigInteger spaceId;
        final BigInteger byteOffset;
        Coordinate(BigInteger spaceId, BigInteger byteOffset) {
            this.spaceId = spaceId; this.byteOffset = byteOffset;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(spaceId); encoder.u64(byteOffset);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("space_id", spaceId, "byte_offset", byteOffset);
        }
    }

    private static final class Selector implements Encodable {
        final int kindCode;
        final Coordinate coordinate;
        final BigInteger byteSize;
        final Address address;
        Selector(int kindCode, Coordinate coordinate, BigInteger byteSize, Address address) {
            this.kindCode = kindCode; this.coordinate = coordinate;
            this.byteSize = byteSize; this.address = address;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text("PRESENT"); encoder.u64(kindCode); coordinate.encode(encoder);
            encoder.u64(byteSize);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("state", "PRESENT", "kind_code", BigInteger.valueOf(kindCode),
                "space_id", coordinate.spaceId, "byte_offset", coordinate.byteOffset,
                "byte_size", byteSize);
        }
    }

    private static final class AllocationShape implements Encodable {
        final int metatypeCode;
        final BigInteger byteSize;
        AllocationShape(int metatypeCode, BigInteger byteSize) {
            this.metatypeCode = metatypeCode; this.byteSize = byteSize;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(metatypeCode); encoder.u64(byteSize);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("metatype_code", BigInteger.valueOf(metatypeCode),
                "byte_size", byteSize);
        }
    }

    private static final class OverrideRecord implements Encodable {
        final BigInteger symbolId;
        final String quality;
        final OverrideShape shape;
        OverrideRecord(BigInteger symbolId, String quality, OverrideShape shape) {
            this.symbolId = symbolId; this.quality = quality; this.shape = shape;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(symbolId); encoder.text(quality);
            encoder.text(shape == null ? "UNDECODABLE" : "DECODED");
            if (shape != null) shape.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            output.check();
            if (shape == null) return output.map("symbol_id", symbolId,
                "source_quality", quality, "decode_state", "UNDECODABLE");
            return output.map("symbol_id", symbolId, "source_quality", quality,
                "decode_state", "DECODED", "shape", shape.json(output));
        }
    }

    private static final class OverrideShape implements Encodable {
        final boolean hasVarargs;
        final List<AllocationShape> fixedShapes;
        final boolean resultIsVoid;
        final AllocationShape resultShape;
        OverrideShape(boolean hasVarargs, List<AllocationShape> fixedShapes,
                boolean resultIsVoid, AllocationShape resultShape) {
            this.hasVarargs = hasVarargs; this.fixedShapes = fixedShapes;
            this.resultIsVoid = resultIsVoid; this.resultShape = resultShape;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.bool(hasVarargs); encoder.u64(fixedShapes.size());
            for (AllocationShape shape : fixedShapes) shape.encode(encoder);
            encoder.bool(resultIsVoid); resultShape.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            List<Map<String, Object>> shapes = new ArrayList<>(fixedShapes.size());
            for (AllocationShape shape : fixedShapes) {
                output.check();
                shapes.add(shape.json(output));
            }
            return output.map("has_varargs", hasVarargs,
                "fixed_allocation_shapes", output.list(shapes),
                "result_is_void", resultIsVoid,
                "result_allocation_shape", resultShape.json(output));
        }
    }

    private static final class OverrideEvidence implements Encodable {
        final boolean namespacePresent;
        final BigInteger scannedCount;
        final List<OverrideRecord> selected;
        OverrideEvidence(boolean namespacePresent, BigInteger scannedCount,
                List<OverrideRecord> selected) {
            this.namespacePresent = namespacePresent;
            this.scannedCount = scannedCount;
            this.selected = selected;
        }
        static OverrideEvidence noNamespace() {
            return new OverrideEvidence(false, null, List.of());
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            if (!namespacePresent) {
                encoder.text("NO_NAMESPACE");
                return;
            }
            encoder.text("SCANNED"); encoder.u64(scannedCount);
            encoder.u64(selected.size());
            for (OverrideRecord record : selected) record.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            output.check();
            if (!namespacePresent) return output.map("state", "NO_NAMESPACE");
            List<Map<String, Object>> values = new ArrayList<>(selected.size());
            for (OverrideRecord record : selected) {
                output.check();
                values.add(record.json(output));
            }
            return output.map("state", "SCANNED", "scanned_symbol_count", scannedCount,
                "selected", output.list(values));
        }
    }

    private static final class OverrideScan {
        final boolean namespacePresent;
        final int scannedCount;
        final Map<Address, List<Symbol>> byAddress;
        final Map<Address, OverrideEvidence> cache = new HashMap<>();
        private OverrideScan(boolean namespacePresent, int scannedCount,
                Map<Address, List<Symbol>> byAddress) {
            this.namespacePresent = namespacePresent;
            this.scannedCount = scannedCount;
            this.byAddress = byAddress;
        }
        static OverrideScan capture(Program program, Function caller,
                TaskMonitor monitor) throws CancelledException {
            Namespace namespace = HighFunction.findOverrideSpace(caller);
            if (namespace == null) return new OverrideScan(false, 0, Map.of());
            SymbolIterator iterator = program.getSymbolTable().getSymbols(namespace);
            if (iterator == null) schema("override symbol iterator is null");
            Map<Address, List<Symbol>> byAddress = new HashMap<>();
            int count = 0;
            while (iterator.hasNext()) {
                monitor.checkCancelled();
                if (count >= MAX_OVERRIDE_SYMBOLS) {
                    resource("override namespace symbols exceed their bound");
                }
                Symbol symbol = iterator.next();
                if (symbol == null) {
                    schema("override namespace contains an invalid symbol");
                }
                Address symbolAddress = symbol.getAddress();
                if (symbolAddress == null) {
                    schema("override namespace contains an invalid symbol");
                }
                byAddress.computeIfAbsent(symbolAddress, ignored -> new ArrayList<>())
                    .add(symbol);
                count++;
                monitor.checkCancelled();
            }
            return new OverrideScan(true, count, byAddress);
        }
        OverrideEvidence forInstruction(Address address, TaskMonitor monitor)
                throws CancelledException {
            if (!namespacePresent) return OverrideEvidence.noNamespace();
            OverrideEvidence existing = cache.get(address);
            if (existing != null) return existing;
            List<Symbol> symbols = byAddress.getOrDefault(address, List.of());
            if (symbols.size() > MAX_SELECTED_OVERRIDES) {
                resource("selected overrides exceed their per-instruction bound");
            }
            List<OverrideRecord> selected = new ArrayList<>(symbols.size());
            for (Symbol symbol : symbols) {
                monitor.checkCancelled();
                BigInteger symbolId = unsignedLong(symbol.getID());
                String sourceQuality = quality(symbol.getSource());
                OverrideShape shape = decodeOverride(symbol);
                selected.add(new OverrideRecord(
                    symbolId, sourceQuality, shape));
                monitor.checkCancelled();
            }
            selected.sort(Comparator.comparing(record -> record.symbolId));
            for (int index = 1; index < selected.size(); index++) {
                if (selected.get(index - 1).symbolId.equals(selected.get(index).symbolId)) {
                    schema("selected override symbol IDs are not unique");
                }
            }
            OverrideEvidence result = new OverrideEvidence(true,
                BigInteger.valueOf(scannedCount), immutable(selected));
            cache.put(address, result);
            return result;
        }
        private static OverrideShape decodeOverride(Symbol symbol) {
            DataTypeSymbol decoded;
            try {
                decoded = HighFunctionDBUtil.readOverride(symbol);
            }
            catch (RuntimeException failure) {
                return null;
            }
            if (decoded == null || !(decoded.getDataType() instanceof FunctionDefinition value)) {
                return null;
            }
            ParameterDefinition[] arguments = value.getArguments();
            if (arguments == null) return null;
            if (arguments.length > MAX_OVERRIDE_FIXED_SHAPES) {
                resource("override fixed shapes exceed their bound");
            }
            try {
                List<AllocationShape> shapes = new ArrayList<>(arguments.length);
                for (ParameterDefinition argument : arguments) {
                    if (argument == null) return null;
                    shapes.add(allocationShape(argument.getDataType()));
                }
                AllocationShape result = allocationShape(value.getReturnType());
                return new OverrideShape(value.hasVarArgs(), immutable(shapes),
                    result.metatypeCode == 14, result);
            }
            catch (InvalidAllocation failure) {
                return null;
            }
        }
    }

    private static final class StorageFacts implements Encodable {
        final boolean valid;
        final boolean bad;
        final boolean unassigned;
        final boolean isVoid;
        final BigInteger totalByteSize;
        final BigInteger varnodeCount;
        StorageFacts(boolean valid, boolean bad, boolean unassigned,
                boolean isVoid, BigInteger totalByteSize, BigInteger varnodeCount) {
            this.valid = valid; this.bad = bad; this.unassigned = unassigned;
            this.isVoid = isVoid; this.totalByteSize = totalByteSize;
            this.varnodeCount = varnodeCount;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.bool(valid); encoder.bool(bad); encoder.bool(unassigned);
            encoder.bool(isVoid); encoder.u64(totalByteSize); encoder.u64(varnodeCount);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("valid", valid, "bad", bad, "unassigned", unassigned,
                "void", isVoid, "total_byte_size", totalByteSize,
                "varnode_count", varnodeCount);
        }
    }

    private static final class Piece implements Encodable {
        final BigInteger ordinal;
        final String origin;
        final String storageClass;
        final int kindCode;
        final Coordinate coordinate;
        final BigInteger byteSize;
        Piece(BigInteger ordinal, String origin, String storageClass,
                int kindCode, Coordinate coordinate, BigInteger byteSize) {
            this.ordinal = ordinal; this.origin = origin; this.storageClass = storageClass;
            this.kindCode = kindCode; this.coordinate = coordinate; this.byteSize = byteSize;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(ordinal); encoder.text(origin); encoder.text(storageClass);
            encoder.u64(kindCode); coordinate.encode(encoder); encoder.u64(byteSize);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            output.check();
            return output.map("piece_ordinal", ordinal, "origin", origin,
                "storage_class", storageClass, "kind_code", BigInteger.valueOf(kindCode),
                "space_id", coordinate.spaceId, "byte_offset", coordinate.byteOffset,
                "byte_size", byteSize);
        }
    }

    private static final class Assignment implements Encodable {
        final String state;
        final StorageFacts facts;
        final List<Piece> pieces;
        Assignment(String state, StorageFacts facts, List<Piece> pieces) {
            this.state = state; this.facts = facts; this.pieces = pieces;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(state); facts.encode(encoder);
            if ("ASSIGNED".equals(state)) {
                encoder.u64(pieces.size());
                for (Piece piece : pieces) piece.encode(encoder);
            }
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            output.check();
            if (!"ASSIGNED".equals(state)) {
                return output.map("state", state, "storage_facts", facts.json(output));
            }
            List<Map<String, Object>> values = new ArrayList<>(pieces.size());
            for (Piece piece : pieces) {
                output.check();
                values.add(piece.json(output));
            }
            return output.map("state", state, "storage_facts", facts.json(output),
                "pieces", output.list(values));
        }
    }

    private static final class Correlation implements Encodable {
        final String role;
        final BigInteger ordinal;
        private Correlation(String role, BigInteger ordinal) {
            this.role = role; this.ordinal = ordinal;
        }
        static Correlation fixed(BigInteger ordinal) {
            return new Correlation("FIXED", ordinal);
        }
        static Correlation thisParameter(BigInteger ordinal) {
            return new Correlation("THIS", ordinal);
        }
        static Correlation simple(String role) { return new Correlation(role, null); }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(role); if (ordinal != null) encoder.u64(ordinal);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            if ("FIXED".equals(role)) {
                return output.map("role", role, "formal_ordinal", ordinal);
            }
            if ("THIS".equals(role)) {
                return output.map("role", role, "returned_parameter_ordinal", ordinal);
            }
            return output.map("role", role);
        }
    }

    private static final class Slot implements Encodable {
        final BigInteger slotOrdinal;
        final BigInteger assignmentOrdinal;
        final Correlation correlation;
        final AllocationShape shape;
        final boolean indirect;
        final Assignment assignment;
        Slot(BigInteger slotOrdinal, BigInteger assignmentOrdinal,
                Correlation correlation, AllocationShape shape,
                boolean indirect, Assignment assignment) {
            this.slotOrdinal = slotOrdinal; this.assignmentOrdinal = assignmentOrdinal;
            this.correlation = correlation; this.shape = shape;
            this.indirect = indirect; this.assignment = assignment;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(slotOrdinal); encoder.u64(assignmentOrdinal);
            correlation.encode(encoder); shape.encode(encoder);
            encoder.bool(indirect); assignment.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            output.check();
            return output.map("slot_ordinal", slotOrdinal,
                "assignment_ordinal", assignmentOrdinal,
                "correlation", correlation.json(output),
                "allocation_shape", shape.json(output),
                "is_indirect", indirect, "assignment", assignment.json(output));
        }
    }

    private static final class Direction implements Encodable {
        final String direction;
        final boolean openVariableTail;
        final List<Slot> slots;
        Direction(String direction, boolean openVariableTail, List<Slot> slots) {
            this.direction = direction; this.openVariableTail = openVariableTail;
            this.slots = slots;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(direction); encoder.bool(openVariableTail);
            encoder.u64(slots.size());
            for (Slot slot : slots) slot.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            List<Map<String, Object>> values = new ArrayList<>(slots.size());
            for (Slot slot : slots) {
                output.check();
                values.add(slot.json(output));
            }
            return output.map("direction", direction,
                "open_variable_tail", openVariableTail,
                "slots", output.list(values));
        }
    }

    private static final class Formal implements Encodable {
        final BigInteger ordinal;
        final String quality;
        final AllocationShape shape;
        Formal(BigInteger ordinal, String quality, AllocationShape shape) {
            this.ordinal = ordinal; this.quality = quality; this.shape = shape;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(ordinal); encoder.text(quality); shape.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("formal_ordinal", ordinal,
                "symbol_source_quality", quality,
                "allocation_shape", shape.json(output));
        }
    }

    private static final class ResultShape implements Encodable {
        final String quality;
        final boolean isVoid;
        final AllocationShape shape;
        ResultShape(String quality, boolean isVoid, AllocationShape shape) {
            this.quality = quality; this.isVoid = isVoid; this.shape = shape;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(quality); encoder.bool(isVoid); shape.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("symbol_source_quality", quality, "is_void", isVoid,
                "allocation_shape", shape.json(output));
        }
    }

    private static final class Signature implements Encodable {
        final String quality;
        final boolean hasVarargs;
        final boolean hasNoReturn;
        final List<Formal> formals;
        final ResultShape result;
        Signature(String quality, boolean hasVarargs, boolean hasNoReturn,
                List<Formal> formals, ResultShape result) {
            this.quality = quality; this.hasVarargs = hasVarargs;
            this.hasNoReturn = hasNoReturn; this.formals = formals; this.result = result;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(quality); encoder.bool(hasVarargs); encoder.bool(hasNoReturn);
            encoder.u64(formals.size());
            for (Formal formal : formals) formal.encode(encoder);
            result.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            List<Map<String, Object>> values = new ArrayList<>(formals.size());
            for (Formal formal : formals) {
                output.check();
                values.add(formal.json(output));
            }
            return output.map("signature_source_quality", quality,
                "has_varargs", hasVarargs, "has_no_return", hasNoReturn,
                "fixed_formals", output.list(values), "result", result.json(output));
        }
    }

    private static final class ModelSelection implements Encodable {
        final String state;
        final BigInteger ordinal;
        final String digest;
        final boolean hasThis;
        ModelSelection(String state, BigInteger ordinal, String digest, boolean hasThis) {
            this.state = state; this.ordinal = ordinal; this.digest = digest;
            this.hasThis = hasThis;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(state); encoder.u64(ordinal);
            encoder.bytes(digestBytes(digest, "profile model digest"));
            encoder.bool(hasThis);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("state", state, "profile_model_ordinal", ordinal,
                "profile_model_identity_digest", digest,
                "model_has_this_pointer", hasThis);
        }
    }

    private static final class VarargBoundary implements Encodable {
        final String state;
        final BigInteger firstSlot;
        private VarargBoundary(String state, BigInteger firstSlot) {
            this.state = state; this.firstSlot = firstSlot;
        }
        static VarargBoundary notVarargs() {
            return new VarargBoundary("NOT_VARARGS", null);
        }
        static VarargBoundary present(BigInteger firstSlot) {
            return new VarargBoundary("PRESENT", firstSlot);
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(state); if (firstSlot != null) encoder.u64(firstSlot);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            if (firstSlot == null) return output.map("state", state);
            return output.map("state", state, "first_vararg_slot", firstSlot);
        }
    }

    private static final class CustomResult implements Encodable {
        final String quality;
        final boolean isVoid;
        final AllocationShape shape;
        final Assignment assignment;
        CustomResult(String quality, boolean isVoid, AllocationShape shape,
                Assignment assignment) {
            this.quality = quality; this.isVoid = isVoid;
            this.shape = shape; this.assignment = assignment;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text(quality); encoder.bool(isVoid); shape.encode(encoder);
            assignment.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("symbol_source_quality", quality, "is_void", isVoid,
                "allocation_shape", shape.json(output),
                "assignment", assignment.json(output));
        }
    }

    private static final class CustomParameter implements Encodable {
        final BigInteger ordinal;
        final String quality;
        final AllocationShape shape;
        final Assignment assignment;
        CustomParameter(BigInteger ordinal, String quality, AllocationShape shape,
                Assignment assignment) {
            this.ordinal = ordinal; this.quality = quality;
            this.shape = shape; this.assignment = assignment;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.u64(ordinal); encoder.text(quality); shape.encode(encoder);
            assignment.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            return output.map("database_ordinal", ordinal,
                "symbol_source_quality", quality,
                "allocation_shape", shape.json(output),
                "assignment", assignment.json(output));
        }
    }

    private static final class CustomStorage implements Encodable {
        final CustomResult result;
        final List<CustomParameter> parameters;
        CustomStorage(CustomResult result, List<CustomParameter> parameters) {
            this.result = result; this.parameters = parameters;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            result.encode(encoder); encoder.u64(parameters.size());
            for (CustomParameter parameter : parameters) parameter.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            List<Map<String, Object>> values = new ArrayList<>(parameters.size());
            for (CustomParameter parameter : parameters) {
                output.check();
                values.add(parameter.json(output));
            }
            return output.map("result", result.json(output),
                "parameters", output.list(values));
        }
    }

    private static final class NoInterface implements InterfaceCapture {
        final String reason;
        NoInterface(String reason) { this.reason = reason; }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text("NO_INTERFACE_SUBJECT"); encoder.text(reason);
        }
        public Map<String, Object> json(JsonMaterializer output)
                throws CancelledException {
            return output.map("state", "NO_INTERFACE_SUBJECT", "reason", reason);
        }
    }

    private static final class Unassignable implements InterfaceCapture {
        final Coordinate subject;
        final String reason;
        final CustomStorage custom;
        Unassignable(Coordinate subject, String reason, CustomStorage custom) {
            this.subject = subject; this.reason = reason; this.custom = custom;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text("UNASSIGNABLE_INTERFACE"); subject.encode(encoder);
            encoder.text(reason); if (custom != null) custom.encode(encoder);
        }
        public Map<String, Object> json(JsonMaterializer output)
                throws CancelledException {
            if (custom == null) return output.map("state", "UNASSIGNABLE_INTERFACE",
                "subject", subject.json(output), "reason", reason);
            return output.map("state", "UNASSIGNABLE_INTERFACE",
                "subject", subject.json(output), "reason", reason,
                "custom_storage", custom.json(output));
        }
    }

    private static final class AssignmentCaptured implements InterfaceCapture {
        final Coordinate subject;
        final BigInteger returnedCount;
        final ModelSelection model;
        final Signature signature;
        final VarargBoundary boundary;
        final List<Direction> directions;
        AssignmentCaptured(Coordinate subject, BigInteger returnedCount,
                ModelSelection model, Signature signature, VarargBoundary boundary,
                List<Direction> directions) {
            this.subject = subject; this.returnedCount = returnedCount;
            this.model = model; this.signature = signature;
            this.boundary = boundary; this.directions = directions;
        }
        public void encode(DigestEncoder encoder) throws CancelledException {
            encoder.text("ASSIGNMENT_CAPTURED"); subject.encode(encoder);
            encoder.u64(returnedCount); model.encode(encoder); signature.encode(encoder);
            boundary.encode(encoder); encoder.u64(directions.size());
            for (Direction direction : directions) direction.encode(encoder);
        }
        public Map<String, Object> json(JsonMaterializer output)
                throws CancelledException {
            List<Map<String, Object>> values = new ArrayList<>(directions.size());
            for (Direction direction : directions) {
                output.check();
                values.add(direction.json(output));
            }
            return output.map("state", "ASSIGNMENT_CAPTURED",
                "subject", subject.json(output),
                "returned_parameter_count", returnedCount,
                "model_selection", model.json(output),
                "signature", signature.json(output),
                "vararg_boundary", boundary.json(output),
                "directions", output.list(values));
        }
    }

    private static final class EffectRow {
        final Coordinate instruction;
        final BigInteger operationOrdinal;
        final String opcode;
        final Selector selector;
        final OverrideEvidence overrides;
        final InterfaceCapture interfaceCapture;
        byte[] digest;
        EffectRow(Coordinate instruction, BigInteger operationOrdinal, String opcode,
                Selector selector, OverrideEvidence overrides,
                InterfaceCapture interfaceCapture) {
            this.instruction = instruction; this.operationOrdinal = operationOrdinal;
            this.opcode = opcode; this.selector = selector; this.overrides = overrides;
            this.interfaceCapture = interfaceCapture;
        }
        void encodeBody(DigestEncoder encoder) throws CancelledException {
            instruction.encode(encoder); encoder.u64(operationOrdinal); encoder.text(opcode);
            if (selector == null) encoder.text("MISSING");
            else selector.encode(encoder);
            overrides.encode(encoder); interfaceCapture.encode(encoder);
        }
        Map<String, Object> json(JsonMaterializer output) throws CancelledException {
            output.check();
            Map<String, Object> selectorJson = selector == null
                ? output.map("state", "MISSING") : selector.json(output);
            return output.map("instruction", instruction.json(output),
                "operation_ordinal", operationOrdinal, "opcode", opcode,
                "selector", selectorJson,
                "override_evidence", overrides.json(output),
                "interface_capture", interfaceCapture.json(output),
                "row_digest", hex(digest));
        }
    }

    private static final class DigestEncoder {
        private final TaskMonitor monitor;
        private final MessageDigest digest;
        private DigestEncoder mirror;
        private long count;
        private long nextCancellation = CANCEL_INTERVAL;
        DigestEncoder(TaskMonitor monitor) throws NoSuchAlgorithmException {
            this.monitor = monitor;
            this.digest = MessageDigest.getInstance("SHA-256");
        }
        void u64(long value) throws CancelledException {
            if (value < 0) throw new IllegalArgumentException("digest integer is negative");
            u64(BigInteger.valueOf(value));
        }
        void u64(BigInteger value) throws CancelledException {
            if (value == null || value.signum() < 0 || value.bitLength() > 64) {
                throw new IllegalArgumentException(
                    "digest integer is outside unsigned 64-bit");
            }
            byte[] source = value.toByteArray();
            byte[] encoded = new byte[8];
            int copied = Math.min(source.length, encoded.length);
            System.arraycopy(source, source.length - copied,
                encoded, encoded.length - copied, copied);
            update(encoded);
        }
        void bool(boolean value) throws CancelledException {
            update(new byte[] {(byte)(value ? 1 : 0)});
        }
        void bytes(byte[] value) throws CancelledException {
            if (value == null) throw new IllegalArgumentException("digest bytes are null");
            u64(value.length); update(value);
        }
        void text(String value) throws CancelledException {
            bytes(strictUtf8(value, "digest text"));
        }
        void mirrorTo(DigestEncoder target) {
            if (target == null || target == this || mirror != null) {
                throw new IllegalStateException("digest mirror lifecycle is invalid");
            }
            mirror = target;
        }
        void stopMirroring(DigestEncoder target) {
            if (mirror != target) {
                throw new IllegalStateException("digest mirror lifecycle is invalid");
            }
            mirror = null;
        }
        private void update(byte[] bytes) throws CancelledException {
            monitor.checkCancelled();
            int offset = 0;
            while (offset < bytes.length) {
                int chunk = (int)Math.min(bytes.length - offset, nextCancellation - count);
                digest.update(bytes, offset, chunk);
                offset += chunk;
                count += chunk;
                if (count == nextCancellation) {
                    monitor.checkCancelled();
                    nextCancellation += CANCEL_INTERVAL;
                }
            }
            if (mirror != null) mirror.update(bytes);
        }
        byte[] finish() throws CancelledException {
            monitor.checkCancelled();
            return digest.digest();
        }
    }

    private static final class CaptureWatchdog {
        private static final int ARMED = 0;
        private static final int COMPLETED = 1;
        private static final int HALTING = 2;
        private final AtomicInteger state = new AtomicInteger(ARMED);
        private final Thread thread;
        private CaptureWatchdog() {
            thread = new Thread(() -> {
                try {
                    TimeUnit.SECONDS.sleep(WATCHDOG_SECONDS);
                }
                catch (InterruptedException ignored) {
                    // The owner interrupts only after winning completion.
                }
                if (state.compareAndSet(ARMED, HALTING)) {
                    Runtime.getRuntime().halt(124);
                }
            }, "tdo-v2-effect-watchdog");
            thread.setDaemon(true);
            thread.start();
        }
        static CaptureWatchdog arm() { return new CaptureWatchdog(); }
        void complete() {
            if (!state.compareAndSet(ARMED, COMPLETED)) {
                throw new IllegalStateException("effect watchdog completion lost ownership");
            }
            thread.interrupt();
            boolean interrupted = false;
            while (thread.isAlive()) {
                try {
                    thread.join();
                }
                catch (InterruptedException failure) {
                    interrupted = true;
                }
            }
            if (interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("effect watchdog join was interrupted");
            }
        }
    }

    private static final class InvalidAllocation extends RuntimeException {
        private static final long serialVersionUID = 1L;
    }

    private static final class CorrelationFailure extends Exception {
        private static final long serialVersionUID = 1L;
        final String reason;
        CorrelationFailure(String reason) { this.reason = reason; }
    }

    private static final class AssignmentFailure extends Exception {
        private static final long serialVersionUID = 1L;
        AssignmentFailure(Throwable cause) { super(cause); }
    }
}

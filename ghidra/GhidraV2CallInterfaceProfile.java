// Package-private call-interface profile capture for the pinned configured runner.
import java.io.IOException;
import java.io.OutputStream;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import ghidra.framework.Application;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PackedEncode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
final class GhidraV2CallInterfaceProfile {
    static final String SCHEMA_ID = "tdo-v2-call-interface-profile-v1";
    static final int SCHEMA_VERSION = 1;
    static final int EXPORTER_REVISION = 1;
    static final int PROFILE_REVISION = 1;
    static final String GHIDRA_VERSION = "12.0.4";
    static final String JVM_CHARSET = "UTF-8";
    static final String MANIFEST_SCHEMA_ID = "tdo-v2-configured-bundle-manifest-v2";
    static final String SEAL_SCHEMA_ID = "tdo-v2-configured-bundle-seal-v2";
    private static final int MAX_MODELS = 256;
    private static final int MAX_TEXT_BYTES = 4096;
    private static final int MAX_TEXT_FIELDS = 64;
    private static final long MAX_ENCODING_BYTES = 1024L * 1024L;
    private static final long MAX_AGGREGATE_BYTES = 16L * 1024L * 1024L;
    private static final long MAX_PROFILE_BYTES = 1024L * 1024L;
    private static final long MAX_HEAP_BYTES = 2L * 1024L * 1024L * 1024L;
    private static final long WATCHDOG_SECONDS = 60L;
    private static final long CANCEL_INTERVAL = 64L * 1024L;
    private static final String LOADER_DOMAIN = "tdo-v2-ghidra-loader-identity-v1";
    private static final String LANGUAGE_DOMAIN = "tdo-v2-ghidra-language-identity-v1";
    private static final String COMPILER_SPEC_DOMAIN = "tdo-v2-ghidra-compiler-spec-identity-v1";
    private static final String MODEL_DOMAIN = "tdo-v2-ghidra-prototype-model-identity-v1";
    private static final String CONTENT_DOMAIN = "tdo-v2-call-interface-profile-content-v1";
    private GhidraV2CallInterfaceProfile() {}
    static Map<String, Object> capture(Program program, TaskMonitor monitor,
            String authorityMode, String exporterSourceSha256, String originalExecutableSha256,
            String generationId, String manifestSchemaId, String sealSchemaId,
            String programMemberId, String programMemberSha256) throws Exception {
        CaptureSession session = captureSession(
            program, monitor, authorityMode, exporterSourceSha256, originalExecutableSha256,
            generationId, manifestSchemaId, sealSchemaId, programMemberId, programMemberSha256);
        return compatibilityProfile(session);
    }
    private static Map<String, Object> compatibilityProfile(CaptureSession session) {
        try {
            return session.profileJson();
        }
        finally {
            session.close();
        }
    }
    static CaptureSession captureSession(Program program, TaskMonitor monitor,
            String authorityMode, String exporterSourceSha256, String originalExecutableSha256,
            String generationId, String manifestSchemaId, String sealSchemaId,
            String programMemberId, String programMemberSha256) throws Exception {
        requireCaptureTuple(program, monitor);
        String mode = requireMode(text(authorityMode, "authority mode"));
        byte[] exporterDigest = digestBytes(exporterSourceSha256, "exporter source SHA-256");
        byte[] executableDigest = digestBytes(originalExecutableSha256, "original executable SHA-256");
        byte[] generationDigest = digestBytes(generationId, "generation ID");
        byte[] programMemberDigest = digestBytes(programMemberSha256, "program member SHA-256");
        if (!MANIFEST_SCHEMA_ID.equals(manifestSchemaId) || !SEAL_SCHEMA_ID.equals(sealSchemaId)) {
            throw new IllegalArgumentException("profile transport schema identity is unsupported");
        }
        text(manifestSchemaId, "manifest schema ID");
        text(sealSchemaId, "seal schema ID");
        String memberId = text(programMemberId, "program member ID");
        String claim = program.getExecutableSHA256();
        if (claim != null && !claim.isBlank() &&
                !originalExecutableSha256.equals(claim.trim().toLowerCase(java.util.Locale.ROOT))) {
            throw new IllegalArgumentException("Ghidra executable SHA-256 disagrees with configured original");
        }
        String executableFormat = text(program.getExecutableFormat(), "executable format");
        String compilerLabel = text(program.getCompiler(), "compiler label");
        Language language = program.getLanguage();
        String languageId = text(program.getLanguageID().getIdAsString(), "language ID");
        BigInteger languageMajor = u64(language.getVersion(), "language major version");
        BigInteger languageMinor = u64(language.getMinorVersion(), "language minor version");
        BigInteger alignment = u64(language.getInstructionAlignment(), "instruction alignment");
        if (alignment.signum() == 0 || alignment.bitLength() > 32) {
            throw new IllegalArgumentException("instruction alignment is outside its bound");
        }
        CompilerSpec compilerSpec = program.getCompilerSpec();
        String compilerSpecId = text(
            compilerSpec.getCompilerSpecID().getIdAsString(), "compiler-spec ID");
        PrototypeModel[] returnedModels = compilerSpec.getAllModels();
        if (returnedModels == null || returnedModels.length > MAX_MODELS) {
            throw new IllegalArgumentException("model inventory is null or exceeds its bound");
        }
        requireJsonBound(returnedModels.length);
        PrototypeModel[] frozenModels = returnedModels.clone();
        returnedModels = null;
        boolean referencesTransferred = false;
        try {
            for (PrototypeModel model : frozenModels) {
                if (model == null) {
                    throw new IllegalArgumentException("model inventory contains null");
                }
            }
            byte[] loaderIdentity = hash(encoder -> {
                encoder.text(LOADER_DOMAIN); encoder.bytes(executableDigest);
                encoder.text(executableFormat); encoder.text(compilerLabel);
            });
            byte[] languageIdentity = hash(encoder -> {
                encoder.text(LANGUAGE_DOMAIN); encoder.text(languageId);
                encoder.u64(languageMajor); encoder.u64(languageMinor);
                encoder.bool(language.isBigEndian()); encoder.u64(alignment);
            });
            AggregateBudget aggregate = new AggregateBudget();
            CaptureWatchdog watchdog = CaptureWatchdog.arm();
            Encoding compilerEncoding = null;
            byte[] compilerIdentity = null;
            List<ModelRow> rows = new ArrayList<>(frozenModels.length);
            DefaultModel defaultModel = null;
            PrototypeModel defaultModelReference = null;
            try {
                monitor.checkCancelled();
                compilerEncoding = encodeCompilerSpec(compilerSpec, aggregate, monitor);
                monitor.checkCancelled();
                Encoding compilerValue = compilerEncoding;
                compilerIdentity = hash(encoder -> {
                    encoder.text(COMPILER_SPEC_DOMAIN); encoder.text(GHIDRA_VERSION);
                    encoder.text(JVM_CHARSET); encoder.text(compilerSpecId);
                    encoder.u64(compilerValue.size); encoder.bytes(compilerValue.digest);
                });
                for (int ordinal = 0; ordinal < frozenModels.length; ordinal++) {
                    monitor.checkCancelled();
                    PrototypeModel model = frozenModels[ordinal];
                    Encoding packed = encodeModel(model, compilerSpec, aggregate, monitor);
                    monitor.checkCancelled();
                    boolean merged = model.isMerged();
                    boolean error = model.isErrorPlaceholder();
                    boolean extension = model.isProgramExtension();
                    BigInteger rowOrdinal = BigInteger.valueOf(ordinal);
                    byte[] compilerValueDigest = compilerIdentity;
                    byte[] modelIdentity = hash(encoder -> {
                        encoder.text(MODEL_DOMAIN); encoder.bytes(compilerValueDigest);
                        encoder.u64(rowOrdinal); encoder.u64(packed.size);
                        encoder.bytes(packed.digest); encoder.bool(merged);
                        encoder.bool(error); encoder.bool(extension);
                    });
                    rows.add(new ModelRow(
                        rowOrdinal, packed, merged, error, extension, modelIdentity));
                }
                monitor.checkCancelled();
                defaultModelReference = compilerSpec.getDefaultCallingConvention();
                defaultModel = resolveDefault(defaultModelReference, frozenModels, rows);
                monitor.checkCancelled();
                aggregate.invalidate();
                boolean permitDefault = "EXPLICIT_AND_PROGRAM_DEFAULT".equals(mode) &&
                    defaultModel.state.equals("PRESENT");
                for (ModelRow row : rows) {
                    monitor.checkCancelled();
                    row.allowProgramDefault = permitDefault &&
                        row.ordinal.equals(defaultModel.ordinal);
                    row.json = rowJson(row);
                    monitor.checkCancelled();
                }
            }
            finally {
                aggregate.invalidate();
                watchdog.complete();
            }
            byte[] finalCompilerIdentity = compilerIdentity;
            Encoding finalCompilerEncoding = compilerEncoding;
            DefaultModel finalDefault = defaultModel;
            byte[] contentDigest = hash(encoder -> {
                encoder.text(CONTENT_DOMAIN); encoder.u64(SCHEMA_VERSION);
                encoder.u64(EXPORTER_REVISION); encoder.bytes(exporterDigest);
                encoder.u64(PROFILE_REVISION); encoder.text(mode);
                encoder.text(GHIDRA_VERSION); encoder.text(JVM_CHARSET);
                encoder.bytes(loaderIdentity); encoder.bytes(languageIdentity);
                encoder.bytes(finalCompilerIdentity); encoder.u64(rows.size());
                encoder.u64(rows.size());
                for (ModelRow row : rows) row.encode(encoder);
                finalDefault.encode(encoder);
            });
            Map<String, Object> transport = map(
                "generation_id", hex(generationDigest), "manifest_schema_id", manifestSchemaId,
                "seal_schema_id", sealSchemaId, "program_member_id", memberId,
                "program_member_sha256", hex(programMemberDigest));
            Map<String, Object> loader = map(
                "executable_sha256", hex(executableDigest), "executable_format", executableFormat,
                "compiler_label", compilerLabel, "identity_digest", hex(loaderIdentity));
            Map<String, Object> languageJson = map(
                "language_id", languageId, "major_version", languageMajor,
                "minor_version", languageMinor, "is_big_endian", language.isBigEndian(),
                "instruction_alignment", alignment, "identity_digest", hex(languageIdentity));
            Map<String, Object> compilerJson = map(
                "compiler_spec_id", compilerSpecId,
                "packed_encoding_size", BigInteger.valueOf(finalCompilerEncoding.size),
                "packed_encoding_digest", hex(finalCompilerEncoding.digest),
                "identity_digest", hex(finalCompilerIdentity));
            List<Map<String, Object>> inventory = new ArrayList<>(rows.size());
            for (ModelRow row : rows) inventory.add(row.json);
            Map<String, Object> root = map(
                "schema_id", SCHEMA_ID, "schema_version", BigInteger.valueOf(SCHEMA_VERSION),
                "exporter_revision", BigInteger.valueOf(EXPORTER_REVISION),
                "exporter_source_sha256", hex(exporterDigest),
                "profile_revision", BigInteger.valueOf(PROFILE_REVISION), "transport", transport,
                "authority_mode", mode, "ghidra_version", GHIDRA_VERSION,
                "jvm_default_charset", JVM_CHARSET, "loader_identity", loader,
                "language_identity", languageJson, "compiler_spec_identity", compilerJson,
                "raw_model_count", BigInteger.valueOf(rows.size()),
                "model_inventory", Collections.unmodifiableList(inventory),
                "default_model", finalDefault.json(),
                "semantic_content_digest", hex(contentDigest));
            RowMetadata[] metadata = new RowMetadata[rows.size()];
            for (int index = 0; index < rows.size(); index++) {
                metadata[index] = new RowMetadata(rows.get(index));
            }
            monitor.checkCancelled();
            CaptureSession session = new CaptureSession(
                root, frozenModels, defaultModelReference, metadata);
            referencesTransferred = true;
            return session;
        }
        finally {
            if (!referencesTransferred) Arrays.fill(frozenModels, null);
        }
    }
    private static void requireCaptureTuple(Program program, TaskMonitor monitor) {
        if (program == null || monitor == null || program.isClosed()) {
            throw new IllegalArgumentException("profile capture requires a live Program and monitor");
        }
        if (!GHIDRA_VERSION.equals(Application.getApplicationVersion())) {
            throw new IllegalStateException("unsupported Ghidra version");
        }
        if (!JVM_CHARSET.equals(Charset.defaultCharset().name())) {
            throw new IllegalStateException("unsupported JVM default charset");
        }
        if (Runtime.getRuntime().maxMemory() > MAX_HEAP_BYTES) {
            throw new IllegalStateException("Ghidra maximum heap exceeds 2 GiB");
        }
    }
    private static Encoding encodeCompilerSpec(
            CompilerSpec compilerSpec, AggregateBudget aggregate, TaskMonitor monitor)
            throws Exception {
        DigestOutput output = new DigestOutput(aggregate, monitor);
        try {
            compilerSpec.encode(new PackedEncode(output));
        }
        catch (CancelledWrite exception) {
            throw exception.cancelled;
        }
        return output.finish();
    }
    private static Encoding encodeModel(
            PrototypeModel model, CompilerSpec compilerSpec,
            AggregateBudget aggregate, TaskMonitor monitor) throws Exception {
        DigestOutput output = new DigestOutput(aggregate, monitor);
        try {
            model.encode(new PackedEncode(output), compilerSpec.getPcodeInjectLibrary());
        }
        catch (CancelledWrite exception) {
            throw exception.cancelled;
        }
        return output.finish();
    }
    private static DefaultModel resolveDefault(
            PrototypeModel candidate, PrototypeModel[] frozen, List<ModelRow> rows) {
        if (candidate == null) return DefaultModel.absent();
        int match = -1;
        for (int index = 0; index < frozen.length; index++) {
            if (candidate == frozen[index]) {
                if (match != -1) {
                    return DefaultModel.ineligible("AMBIGUOUS_INVENTORY_IDENTITY");
                }
                match = index;
            }
        }
        if (match == -1) return DefaultModel.ineligible("NOT_IN_INVENTORY");
        ModelRow row = rows.get(match);
        if (row.merged) return DefaultModel.ineligible("MERGED_MODEL");
        if (row.error) return DefaultModel.ineligible("ERROR_PLACEHOLDER");
        return DefaultModel.present(row.ordinal, row.modelDigest);
    }
    private static Map<String, Object> rowJson(ModelRow row) {
        return map("inventory_ordinal", row.ordinal,
            "packed_encoding_size", BigInteger.valueOf(row.packed.size),
            "packed_encoding_digest", hex(row.packed.digest), "is_merged", row.merged,
            "is_error_placeholder", row.error, "is_program_extension", row.extension,
            "allow_explicit", !row.merged && !row.error,
            "allow_program_default", row.allowProgramDefault,
            "model_digest", hex(row.modelDigest));
    }
    private static String requireMode(String mode) {
        if (!"EXPLICIT_ONLY".equals(mode) && !"EXPLICIT_AND_PROGRAM_DEFAULT".equals(mode)) {
            throw new IllegalArgumentException("unsupported profile authority mode");
        }
        return mode;
    }
    private static byte[] digestBytes(String value, String label) {
        if (value == null || value.length() != 64 || !value.chars().allMatch(
                character -> character >= '0' && character <= '9' ||
                    character >= 'a' && character <= 'f')) {
            throw new IllegalArgumentException(label + " must be 64 lowercase hexadecimal characters");
        }
        byte[] result = new byte[32];
        for (int index = 0; index < result.length; index++) {
            int high = Character.digit(value.charAt(index * 2), 16);
            int low = Character.digit(value.charAt(index * 2 + 1), 16);
            result[index] = (byte)((high << 4) | low);
        }
        return result;
    }
    private static BigInteger u64(long value, String label) {
        if (value < 0) throw new IllegalArgumentException(label + " must be unsigned");
        return BigInteger.valueOf(value);
    }
    private static String text(String value, String label) {
        strictUtf8(value, label);
        return value;
    }
    private static byte[] strictUtf8(String value, String label) {
        if (value == null) {
            throw new IllegalArgumentException(label + " must be text");
        }
        try {
            ByteBuffer encoded = Charset.forName(JVM_CHARSET).newEncoder()
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
    private static byte[] hash(HashAction action) throws Exception {
        BinaryEncoder encoder = new BinaryEncoder(MessageDigest.getInstance("SHA-256"));
        action.accept(encoder); return encoder.finish();
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
    private static void requireJsonBound(int modelCount) {
        // Five unconstrained labels may each expand sixfold under JSON escaping.
        long upperBound = 5L * MAX_TEXT_BYTES * 6L + 768L * modelCount + 16384L;
        if (5 > MAX_TEXT_FIELDS || upperBound > MAX_PROFILE_BYTES) {
            throw new IllegalArgumentException("profile JSON exceeds its member bound");
        }
    }
    @FunctionalInterface
    private interface HashAction { void accept(BinaryEncoder encoder) throws Exception; }
    private static final class Encoding {
        final long size;
        final byte[] digest;
        Encoding(long size, byte[] digest) {
            if (size == 0) throw new IllegalArgumentException("packed identity encoding must be nonempty");
            this.size = size; this.digest = digest;
        }
    }
    private static final class ModelRow {
        final BigInteger ordinal;
        final Encoding packed;
        final boolean merged;
        final boolean error;
        final boolean extension;
        final byte[] modelDigest;
        boolean allowProgramDefault;
        Map<String, Object> json;
        ModelRow(BigInteger ordinal, Encoding packed, boolean merged, boolean error,
                boolean extension, byte[] modelDigest) {
            this.ordinal = ordinal; this.packed = packed; this.merged = merged;
            this.error = error; this.extension = extension; this.modelDigest = modelDigest;
        }
        void encode(BinaryEncoder encoder) {
            encoder.u64(ordinal); encoder.u64(packed.size); encoder.bytes(packed.digest);
            encoder.bool(merged); encoder.bool(error); encoder.bool(extension);
            encoder.bool(!merged && !error); encoder.bool(allowProgramDefault);
            encoder.bytes(modelDigest);
        }
    }
    static final class RowMetadata {
        private final BigInteger inventoryOrdinal;
        private final long packedEncodingSize;
        private final String packedEncodingDigest;
        private final boolean merged;
        private final boolean errorPlaceholder;
        private final boolean programExtension;
        private final boolean allowExplicit;
        private final boolean allowProgramDefault;
        private final String modelDigest;
        private RowMetadata(ModelRow row) {
            inventoryOrdinal = row.ordinal;
            packedEncodingSize = row.packed.size;
            packedEncodingDigest = hex(row.packed.digest);
            merged = row.merged;
            errorPlaceholder = row.error;
            programExtension = row.extension;
            allowExplicit = !row.merged && !row.error;
            allowProgramDefault = row.allowProgramDefault;
            modelDigest = hex(row.modelDigest);
        }
        BigInteger inventoryOrdinal() { return inventoryOrdinal; }
        long packedEncodingSize() { return packedEncodingSize; }
        String packedEncodingDigest() { return packedEncodingDigest; }
        boolean isMerged() { return merged; }
        boolean isErrorPlaceholder() { return errorPlaceholder; }
        boolean isProgramExtension() { return programExtension; }
        boolean allowExplicit() { return allowExplicit; }
        boolean allowProgramDefault() { return allowProgramDefault; }
        String modelDigest() { return modelDigest; }
    }
    static final class CaptureSession implements AutoCloseable {
        private final Thread ownerThread;
        private Map<String, Object> profileJson;
        private PrototypeModel[] modelReferences;
        private PrototypeModel defaultModelReference;
        private RowMetadata[] rowMetadata;
        private boolean active;
        private CaptureSession(Map<String, Object> profileJson,
                PrototypeModel[] modelReferences, PrototypeModel defaultModelReference,
                RowMetadata[] rowMetadata) {
            ownerThread = Thread.currentThread();
            this.profileJson = profileJson;
            this.modelReferences = modelReferences;
            this.defaultModelReference = defaultModelReference;
            this.rowMetadata = rowMetadata;
            active = true;
        }
        Map<String, Object> profileJson() {
            requireActiveOwner();
            return profileJson;
        }
        PrototypeModel[] modelReferences() {
            requireActiveOwner();
            return modelReferences.clone();
        }
        PrototypeModel defaultModelReference() {
            requireActiveOwner();
            return defaultModelReference;
        }
        RowMetadata[] rowMetadata() {
            requireActiveOwner();
            return rowMetadata.clone();
        }
        private void requireOwner() {
            if (Thread.currentThread() != ownerThread) {
                throw new IllegalStateException("profile capture session accessed by non-owner thread");
            }
        }
        private void requireActiveOwner() {
            requireOwner();
            if (!active) throw new IllegalStateException("profile capture session is closed");
        }
        @Override
        public void close() {
            requireOwner();
            if (!active) return;
            active = false;
            Arrays.fill(modelReferences, null);
            defaultModelReference = null;
            Arrays.fill(rowMetadata, null);
            profileJson = null;
            modelReferences = null;
            rowMetadata = null;
        }
    }
    private static final class DefaultModel {
        final String state;
        final BigInteger ordinal;
        final byte[] digest;
        final String reason;
        private DefaultModel(String state, BigInteger ordinal, byte[] digest, String reason) {
            this.state = state; this.ordinal = ordinal; this.digest = digest; this.reason = reason;
        }
        static DefaultModel absent() { return new DefaultModel("ABSENT", null, null, null); }
        static DefaultModel present(BigInteger ordinal, byte[] digest) {
            return new DefaultModel("PRESENT", ordinal, digest, null); }
        static DefaultModel ineligible(String reason) {
            return new DefaultModel("INELIGIBLE", null, null, reason); }
        void encode(BinaryEncoder encoder) {
            if ("ABSENT".equals(state)) encoder.raw((byte)0);
            else if ("PRESENT".equals(state)) {
                encoder.raw((byte)1); encoder.u64(ordinal); encoder.bytes(digest);
            }
            else {
                encoder.raw((byte)2); encoder.text(reason);
            }
        }
        Map<String, Object> json() {
            if ("PRESENT".equals(state)) return map(
                "state", state, "inventory_ordinal", ordinal, "model_digest", hex(digest));
            if ("INELIGIBLE".equals(state)) return map("state", state, "reason", reason);
            return map("state", state);
        }
    }
    private static final class BinaryEncoder {
        private final MessageDigest digest;
        BinaryEncoder(MessageDigest digest) { this.digest = digest; }
        void raw(byte value) { digest.update(value); }
        void u64(long value) { u64(BigInteger.valueOf(value)); }
        void u64(BigInteger value) {
            byte[] source = value.toByteArray();
            if (value.signum() < 0 || value.bitLength() > 64) {
                throw new IllegalArgumentException("digest integer is outside unsigned 64-bit");
            }
            byte[] encoded = new byte[8];
            int count = Math.min(source.length, encoded.length);
            System.arraycopy(source, source.length - count, encoded, encoded.length - count, count);
            digest.update(encoded);
        }
        void bool(boolean value) { raw((byte)(value ? 1 : 0)); }
        void bytes(byte[] value) {
            u64(value.length); digest.update(value);
        }
        void text(String value) { bytes(strictUtf8(value, "digest text")); }
        byte[] finish() { return digest.digest(); }
    }
    private static final class AggregateBudget {
        long used;
        boolean valid = true;
        void reserve(long count, long itemUsed) throws IOException {
            if (!valid) throw new IOException("packed identity aggregate budget is invalid");
            if (count > MAX_ENCODING_BYTES - itemUsed || count > MAX_AGGREGATE_BYTES - used) {
                throw new IOException("packed identity encoding exceeds its byte budget");
            }
            used += count;
        }
        void invalidate() { valid = false; }
    }
    private static final class CancelledWrite extends IOException {
        private static final long serialVersionUID = 1L;
        final CancelledException cancelled;
        CancelledWrite(CancelledException cancelled) { super(cancelled); this.cancelled = cancelled; }
    }
    private static final class DigestOutput extends OutputStream {
        private final AggregateBudget aggregate;
        private final TaskMonitor monitor;
        private final MessageDigest digest;
        private long count;
        private long nextCancellation = CANCEL_INTERVAL;
        DigestOutput(AggregateBudget aggregate, TaskMonitor monitor) throws NoSuchAlgorithmException {
            this.aggregate = aggregate; this.monitor = monitor;
            this.digest = MessageDigest.getInstance("SHA-256");
        }
        @Override
        public void write(int value) throws IOException {
            byte[] one = {(byte)value};
            write(one, 0, 1);
        }
        @Override
        public void write(byte[] bytes, int offset, int length) throws IOException {
            if (bytes == null) throw new NullPointerException("packed write bytes");
            if (offset < 0 || length < 0 || offset > bytes.length - length)
                throw new IndexOutOfBoundsException("packed write bounds");
            if (length == 0) return;
            checkCancelled();
            aggregate.reserve(length, count);
            long end = count + length;
            int position = offset;
            while (count < end) {
                int chunk = (int)Math.min(end - count, nextCancellation - count);
                digest.update(bytes, position, chunk);
                position += chunk;
                count += chunk;
                if (count == nextCancellation) {
                    checkCancelled();
                    nextCancellation += CANCEL_INTERVAL;
                }
            }
        }
        Encoding finish() { return new Encoding(count, digest.digest()); }
        private void checkCancelled() throws CancelledWrite {
            try {
                monitor.checkCancelled();
            }
            catch (CancelledException exception) { throw new CancelledWrite(exception); }
        }
    }
    private static final class CaptureWatchdog {
        private final CountDownLatch completed = new CountDownLatch(1);
        private final Thread thread;
        private CaptureWatchdog() {
            thread = new Thread(() -> {
                try {
                    if (!completed.await(WATCHDOG_SECONDS, TimeUnit.SECONDS))
                        Runtime.getRuntime().halt(124);
                }
                catch (InterruptedException ignored) {
                    // Completion deliberately interrupts the sleeping watchdog.
                }
            }, "tdo-v2-profile-watchdog");
            thread.setDaemon(true);
            thread.start();
        }
        static CaptureWatchdog arm() { return new CaptureWatchdog(); }
        void complete() {
            completed.countDown();
            thread.interrupt();
            boolean interrupted = false;
            while (thread.isAlive()) {
                try { thread.join(); }
                catch (InterruptedException exception) { interrupted = true; }
            }
            if (interrupted) Thread.currentThread().interrupt();
        }
    }
}

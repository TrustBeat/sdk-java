package eu.trustbeat.sdk;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration-style unit tests for TrustBeat HTTP client.
 *
 * Uses com.sun.net.httpserver (bundled with JDK, no extra dep)
 * to spin up a local HTTP server per test class.
 */
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TrustBeatClientTest {

    private static HttpServer server;
    private static int port;

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] sha256(byte[] data) {
        try { return MessageDigest.getInstance("SHA-256").digest(data); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    private static String anchorAcceptedJson(String id) {
        return "{\"id\":\"" + id + "\",\"hash\":\"" + "a".repeat(64) + "\"," +
               "\"hash_algorithm\":\"sha256\",\"status\":\"pending\"," +
               "\"submitted_at\":\"2026-01-01T00:00:00Z\",\"overage\":false}";
    }

    private static String proofJson(String id) {
        String leaf  = "ab".repeat(32);
        String token = Base64.getEncoder().encodeToString("DER_BYTES".getBytes());
        return "{\"id\":\"" + id + "\",\"hash\":\"" + leaf + "\"," +
               "\"hash_algorithm\":\"sha256\",\"batch_id\":\"batch-1\"," +
               "\"leaf_index\":0,\"merkle_root\":\"" + leaf + "\"," +
               "\"proof_path\":[],\"token\":\"" + token + "\"," +
               "\"token_format\":\"rfc3161\",\"tsa_serial\":\"42\"," +
               "\"provider\":\"sk-demo\",\"anchored_at\":\"2026-01-01T00:10:00Z\"," +
               "\"client_ref\":null,\"description\":null}";
    }

    private static void respond(com.sun.net.httpserver.HttpExchange ex,
                                int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    private TrustBeat client() {
        return new TrustBeat.Builder()
            .apiKey("tb_live_test")
            .baseUrl("http://localhost:" + port + "/v1")
            .build();
    }

    // ── Test lifecycle ────────────────────────────────────────────────────────

    @BeforeAll
    static void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        port = server.getAddress().getPort();
        server.start();
    }

    @AfterAll
    static void stopServer() {
        server.stop(0);
    }

    private void addHandler(String path, int status, String body) {
        server.createContext(path, ex -> {
            respond(ex, status, body);
            server.removeContext(path);
        });
    }

    // ── anchor() ─────────────────────────────────────────────────────────────

    @Test
    void anchorReturnsAnchorJob() {
        addHandler("/v1/anchor", 202, anchorAcceptedJson("track-1"));
        AnchorJob job = client().anchor("a".repeat(64));
        assertEquals("track-1", job.getId());
        assertEquals("pending",  job.getStatus());
        assertFalse(job.isOverage());
    }

    @Test
    void anchorSendsAuthorizationHeader() {
        AtomicReference<String> authHeader = new AtomicReference<>();
        server.createContext("/v1/anchors-auth", ex -> {
            authHeader.set(ex.getRequestHeaders().getFirst("Authorization"));
            respond(ex, 202, anchorAcceptedJson("t"));
            server.removeContext("/v1/anchors-auth");
        });
        new TrustBeat.Builder()
            .apiKey("tb_live_mykey")
            .baseUrl("http://localhost:" + port + "/v1-auth")
            .build();
        // Can't easily override path — verify header via a dedicated endpoint
        server.createContext("/v1-auth/anchor", ex -> {
            authHeader.set(ex.getRequestHeaders().getFirst("Authorization"));
            try { respond(ex, 202, anchorAcceptedJson("t")); }
            catch (IOException ignored) {}
            server.removeContext("/v1-auth/anchor");
        });
        new TrustBeat.Builder()
            .apiKey("tb_live_mykey")
            .baseUrl("http://localhost:" + port + "/v1-auth")
            .build().anchor("a".repeat(64));
        assertEquals("Bearer tb_live_mykey", authHeader.get());
    }

    @Test
    void anchorSendsClientRef() {
        AtomicReference<String> body = new AtomicReference<>();
        server.createContext("/v1/anchors-ref", ex -> {
            try {
                body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                respond(ex, 202, anchorAcceptedJson("t"));
            } catch (IOException ignored) {}
            server.removeContext("/v1/anchors-ref");
        });
        new TrustBeat.Builder()
            .apiKey("tb_live_test")
            .baseUrl("http://localhost:" + port + "/v1-ref")
            .build();
        server.createContext("/v1-ref/anchor", ex -> {
            try {
                body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                respond(ex, 202, anchorAcceptedJson("t"));
            } catch (IOException ignored) {}
            server.removeContext("/v1-ref/anchor");
        });
        new TrustBeat.Builder()
            .apiKey("tb_live_test")
            .baseUrl("http://localhost:" + port + "/v1-ref")
            .build().anchor("b".repeat(64), new TrustBeat.AnchorOptions().clientRef("my-ref"));
        assertTrue(body.get().contains("\"client_ref\":\"my-ref\""));
    }

    // ── anchorBatch() ─────────────────────────────────────────────────────────

    @Test
    void anchorBatchReturnsBatchSubmission() {
        String resp = "{\"submission_id\":\"sub-abc\",\"accepted\":[" + anchorAcceptedJson("t1") + "," +
                      anchorAcceptedJson("t2") + "],\"total\":2}";
        addHandler("/v1/anchor/batch", 202, resp);
        BatchSubmission result = client().anchorBatch(
            Arrays.asList("a".repeat(64), "b".repeat(64)));
        assertEquals("sub-abc", result.getSubmissionId());
        assertEquals(2, result.getItems().size());
        assertEquals("t1", result.getItems().get(0).getId());
        assertEquals("t2", result.getItems().get(1).getId());
    }

    @Test
    void anchorBatchSendsHashesAsJsonArray() {
        // Guards against the escaped-string bug: `hashes` must be a real JSON array,
        // not a quoted string. The mock captures and inspects the request body.
        AtomicReference<String> captured = new AtomicReference<>();
        server.createContext("/v1arr/anchor/batch", ex -> {
            try {
                captured.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                respond(ex, 202, "{\"submission_id\":\"s\",\"accepted\":[],\"total\":0}");
            } catch (IOException ignored) {}
            server.removeContext("/v1arr/anchor/batch");
        });
        new TrustBeat.Builder()
            .apiKey("tb_live_test")
            .baseUrl("http://localhost:" + port + "/v1arr")
            .build()
            .anchorBatch(Arrays.asList("a".repeat(64), "b".repeat(64)));
        String body = captured.get();
        assertTrue(body.contains("\"hashes\":["), "hashes must be a JSON array, got: " + body);
        assertFalse(body.contains("\"hashes\":\""), "hashes must not be a quoted string");
        assertTrue(body.contains("\"hash_algorithm\":\"SHA-256\""), "algorithm must be SHA-256");
    }

    @Test
    void anchorBatchEmptyListReturnsEmptyWithoutRequest() {
        // No handler registered — if a request is made the test hangs/fails
        BatchSubmission result = client().anchorBatch(Collections.emptyList());
        assertTrue(result.getItems().isEmpty());
    }

    @Test
    void anchorBatchOver100ThrowsIllegalArgumentException() {
        List<String> hashes = Collections.nCopies(101, "a".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> client().anchorBatch(hashes));
    }

    // ── getProof() ────────────────────────────────────────────────────────────

    @Test
    void getProofReturnsProofWhenAnchored() {
        addHandler("/v1/anchor/track-1/proof", 200, proofJson("track-1"));
        AnchorProof proof = client().getProof("track-1");
        assertNotNull(proof);
        assertArrayEquals("DER_BYTES".getBytes(), proof.getToken());
        assertEquals("42", proof.getTsaSerial());
    }

    @Test
    void getProofReturnsNullWhenPending() {
        addHandler("/v1/anchor/pending-1/proof", 200, anchorAcceptedJson("pending-1"));
        assertNull(client().getProof("pending-1"));
    }

    // ── anchorWait() ──────────────────────────────────────────────────────────

    @Test
    void anchorWaitPollsUntilProofReady() {
        AtomicInteger calls = new AtomicInteger(0);
        server.createContext("/v1/anchor/wait-1/proof", ex -> {
            try {
                int n = calls.incrementAndGet();
                respond(ex, 200, n == 1 ? anchorAcceptedJson("wait-1") : proofJson("wait-1"));
            } catch (IOException ignored) {}
            if (calls.get() >= 2) server.removeContext("/v1/anchor/wait-1/proof");
        });
        AnchorProof proof = client().anchorWait("wait-1", 30, 0);
        assertNotNull(proof);
        assertEquals(2, calls.get());
    }

    @Test
    void anchorWaitThrowsOnTimeout() {
        addHandler("/v1/anchor/timeout-1/proof", 200, anchorAcceptedJson("timeout-1"));
        // Need a handler that stays available for the first poll
        server.createContext("/v1/anchor/timeout-always/proof", ex -> {
            try { respond(ex, 200, anchorAcceptedJson("timeout-always")); }
            catch (IOException ignored) {}
        });
        TrustBeatException ex = assertThrows(TrustBeatException.class,
            () -> new TrustBeat.Builder()
                .apiKey("tb_live_test")
                .baseUrl("http://localhost:" + port + "/v1")
                .build()
                .anchorWait("timeout-always", 0, 0));
        assertTrue(ex.getMessage().contains("timed out"));
        server.removeContext("/v1/anchor/timeout-always/proof");
    }

    // ── verify() ─────────────────────────────────────────────────────────────

    @Test
    void verifyReturnsTrueForValidSingleLeafProof() {
        byte[] leaf = sha256("content".getBytes());
        AnchorProof proof = new AnchorProof(
            "x", hex(leaf), "sha256", "b", 0, hex(leaf),
            Collections.emptyList(), new byte[0], "rfc3161", "0",
            "test", "2026-01-01T00:00:00Z", null, null);
        assertTrue(client().verify(proof));
    }

    @Test
    void verifyReturnsFalseForInvalidProof() {
        byte[] leaf = sha256("content".getBytes());
        AnchorProof proof = new AnchorProof(
            "x", hex(leaf), "sha256", "b", 0, "ff".repeat(32),
            Collections.emptyList(), new byte[0], "rfc3161", "0",
            "test", "2026-01-01T00:00:00Z", null, null);
        assertFalse(client().verify(proof));
    }

    // ── Error handling ────────────────────────────────────────────────────────

    @Test
    void returns401AsAuthException() {
        addHandler("/v1/anchor", 401,
            "{\"error\":{\"message\":\"Bad key\",\"code\":\"UNAUTHORIZED\"}}");
        assertThrows(AuthException.class,
            () -> new TrustBeat.Builder().apiKey("bad_key")
                .baseUrl("http://localhost:" + port + "/v1").build()
                .anchor("a".repeat(64)));
    }

    @Test
    void returns402AsQuotaException() {
        addHandler("/v1/anchor", 402, "{\"error\":{\"message\":\"Quota exceeded\"}}");
        assertThrows(QuotaException.class, () -> client().anchor("a".repeat(64)));
    }

    @Test
    void returns404AsNotFoundException() {
        addHandler("/v1/anchor/nope/proof", 404,
            "{\"error\":{\"message\":\"Not found\",\"code\":\"NOT_FOUND\"}}");
        assertThrows(NotFoundException.class, () -> client().getProof("nope"));
    }

    @Test
    void returns429AsRateLimitException() {
        addHandler("/v1/anchor", 429, "{\"error\":{\"message\":\"Slow down\"}}");
        assertThrows(RateLimitException.class, () -> client().anchor("a".repeat(64)));
    }

    @Test
    void returns500AsTrustBeatExceptionWithStatus() {
        addHandler("/v1/anchor", 500, "{\"error\":{\"message\":\"Server error\"}}");
        TrustBeatException ex = assertThrows(TrustBeatException.class,
            () -> client().anchor("a".repeat(64)));
        assertEquals(500, ex.getStatus());
    }

    // ── Builder validation ────────────────────────────────────────────────────

    @Test
    void emptyApiKeyThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
            () -> new TrustBeat.Builder().apiKey("").build());
    }

    @Test
    void nullApiKeyThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
            () -> new TrustBeat.Builder().build());
    }

    // ── Static hash utilities ─────────────────────────────────────────────────

    @Test
    void hashBytesReturns64CharHex() {
        String h = TrustBeat.hashBytes("hello".getBytes());
        assertEquals(64, h.length());
        assertTrue(h.matches("[0-9a-f]+"));
    }

    @Test
    void hashStringMatchesHashBytes() {
        assertEquals(TrustBeat.hashBytes("world".getBytes()),
                     TrustBeat.hashString("world"));
    }

    // ── anchorFile() ──────────────────────────────────────────────────────────

    @Test
    void hashFileReturns64CharLowercaseHex() throws Exception {
        Path tmp = Files.createTempFile("tb-hash", ".bin");
        try {
            Files.write(tmp, "deterministic content".getBytes(StandardCharsets.UTF_8));
            String h = TrustBeat.hashFile(tmp);
            assertEquals(64, h.length());
            assertTrue(h.matches("[0-9a-f]+"));
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void hashFileMatchesManualSha256() throws Exception {
        byte[] content = "deterministic content 42".getBytes(StandardCharsets.UTF_8);
        String expected = hex(sha256(content));

        Path tmp = Files.createTempFile("tb-hash-match", ".bin");
        try {
            Files.write(tmp, content);
            assertEquals(expected, TrustBeat.hashFile(tmp));
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void anchorFileDescriptionDefaultsToFilename() throws Exception {
        AtomicReference<String> capturedDesc = new AtomicReference<>();
        server.createContext("/v1/anchor", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int start = body.indexOf("\"description\":\"") + 15;
            int end   = body.indexOf("\"", start);
            capturedDesc.set(body.substring(start, end));
            respond(ex, 202, anchorAcceptedJson("track-fd"));
            server.removeContext("/v1/anchor");
        });

        Path tmp = Files.createTempFile("tb-file-desc", ".txt");
        try {
            Files.write(tmp, "data".getBytes());
            client().anchorFile(tmp);
            assertEquals(tmp.getFileName().toString(), capturedDesc.get());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    @Test
    void anchorFileCustomDescriptionOverridesFilename() throws Exception {
        AtomicReference<String> capturedDesc = new AtomicReference<>();
        server.createContext("/v1/anchor", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            int start = body.indexOf("\"description\":\"") + 15;
            int end   = body.indexOf("\"", start);
            capturedDesc.set(body.substring(start, end));
            respond(ex, 202, anchorAcceptedJson("track-fd2"));
            server.removeContext("/v1/anchor");
        });

        Path tmp = Files.createTempFile("tb-file-desc2", ".txt");
        try {
            Files.write(tmp, "data".getBytes());
            client().anchorFile(tmp, new TrustBeat.AnchorOptions().description("custom-desc"));
            assertEquals("custom-desc", capturedDesc.get());
        } finally {
            Files.deleteIfExists(tmp);
        }
    }
}

package eu.trustbeat.sdk;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.*;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
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
        addHandler("/v1/anchors", 202, anchorAcceptedJson("track-1"));
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
        server.createContext("/v1-auth/anchors", ex -> {
            authHeader.set(ex.getRequestHeaders().getFirst("Authorization"));
            try { respond(ex, 202, anchorAcceptedJson("t")); }
            catch (IOException ignored) {}
            server.removeContext("/v1-auth/anchors");
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
        server.createContext("/v1-ref/anchors", ex -> {
            try {
                body.set(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                respond(ex, 202, anchorAcceptedJson("t"));
            } catch (IOException ignored) {}
            server.removeContext("/v1-ref/anchors");
        });
        new TrustBeat.Builder()
            .apiKey("tb_live_test")
            .baseUrl("http://localhost:" + port + "/v1-ref")
            .build().anchor("b".repeat(64), new TrustBeat.AnchorOptions().clientRef("my-ref"));
        assertTrue(body.get().contains("\"client_ref\":\"my-ref\""));
    }

    // ── anchorBatch() ─────────────────────────────────────────────────────────

    @Test
    void anchorBatchReturnsListOfJobs() {
        String resp = "{\"accepted\":[" + anchorAcceptedJson("t1") + "," +
                      anchorAcceptedJson("t2") + "],\"total\":2}";
        addHandler("/v1/anchors/batch", 202, resp);
        List<AnchorJob> jobs = client().anchorBatch(
            Arrays.asList("a".repeat(64), "b".repeat(64)));
        assertEquals(2, jobs.size());
        assertEquals("t1", jobs.get(0).getId());
        assertEquals("t2", jobs.get(1).getId());
    }

    @Test
    void anchorBatchEmptyListReturnsEmptyWithoutRequest() {
        // No handler registered — if a request is made the test hangs/fails
        List<AnchorJob> result = client().anchorBatch(Collections.emptyList());
        assertTrue(result.isEmpty());
    }

    @Test
    void anchorBatchOver100ThrowsIllegalArgumentException() {
        List<String> hashes = Collections.nCopies(101, "a".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> client().anchorBatch(hashes));
    }

    // ── getProof() ────────────────────────────────────────────────────────────

    @Test
    void getProofReturnsProofWhenAnchored() {
        addHandler("/v1/anchors/track-1", 200, proofJson("track-1"));
        AnchorProof proof = client().getProof("track-1");
        assertNotNull(proof);
        assertArrayEquals("DER_BYTES".getBytes(), proof.getToken());
        assertEquals("42", proof.getTsaSerial());
    }

    @Test
    void getProofReturnsNullWhenPending() {
        addHandler("/v1/anchors/pending-1", 200, anchorAcceptedJson("pending-1"));
        assertNull(client().getProof("pending-1"));
    }

    // ── anchorWait() ──────────────────────────────────────────────────────────

    @Test
    void anchorWaitPollsUntilProofReady() {
        AtomicInteger calls = new AtomicInteger(0);
        server.createContext("/v1/anchors/wait-1", ex -> {
            try {
                int n = calls.incrementAndGet();
                respond(ex, 200, n == 1 ? anchorAcceptedJson("wait-1") : proofJson("wait-1"));
            } catch (IOException ignored) {}
            if (calls.get() >= 2) server.removeContext("/v1/anchors/wait-1");
        });
        AnchorProof proof = client().anchorWait("wait-1", 30, 0);
        assertNotNull(proof);
        assertEquals(2, calls.get());
    }

    @Test
    void anchorWaitThrowsOnTimeout() {
        addHandler("/v1/anchors/timeout-1", 200, anchorAcceptedJson("timeout-1"));
        // Need a handler that stays available for the first poll
        server.createContext("/v1/anchors/timeout-always", ex -> {
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
        server.removeContext("/v1/anchors/timeout-always");
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
        addHandler("/v1/anchors", 401,
            "{\"error\":{\"message\":\"Bad key\",\"code\":\"UNAUTHORIZED\"}}");
        assertThrows(AuthException.class,
            () -> new TrustBeat.Builder().apiKey("bad_key")
                .baseUrl("http://localhost:" + port + "/v1").build()
                .anchor("a".repeat(64)));
    }

    @Test
    void returns402AsQuotaException() {
        addHandler("/v1/anchors", 402, "{\"error\":{\"message\":\"Quota exceeded\"}}");
        assertThrows(QuotaException.class, () -> client().anchor("a".repeat(64)));
    }

    @Test
    void returns404AsNotFoundException() {
        addHandler("/v1/anchors/nope", 404,
            "{\"error\":{\"message\":\"Not found\",\"code\":\"NOT_FOUND\"}}");
        assertThrows(NotFoundException.class, () -> client().getProof("nope"));
    }

    @Test
    void returns429AsRateLimitException() {
        addHandler("/v1/anchors", 429, "{\"error\":{\"message\":\"Slow down\"}}");
        assertThrows(RateLimitException.class, () -> client().anchor("a".repeat(64)));
    }

    @Test
    void returns500AsTrustBeatExceptionWithStatus() {
        addHandler("/v1/anchors", 500, "{\"error\":{\"message\":\"Server error\"}}");
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
}

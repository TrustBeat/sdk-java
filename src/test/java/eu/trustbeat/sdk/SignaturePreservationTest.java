package eu.trustbeat.sdk;

import com.sun.net.httpserver.HttpServer;
import eu.trustbeat.sdk.internal.Json;
import org.junit.jupiter.api.*;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/** Signature Preservation: the SDK passes the extractor's submission through and maps the responses. */
class SignaturePreservationTest {

    static final String SUBMISSION = "{\"submission_version\":1,\"extractor\":{\"name\":\"trustbeat-signature\",\"version\":\"1.0.0\"},"
        + "\"container\":{\"format\":\"PAdES\",\"name\":\"contract.pdf\",\"size_bytes\":10,\"digests\":{\"sha256\":\"aa\",\"sha512\":\"bb\",\"sha3-512\":\"cc\"}},"
        + "\"data_objects\":[],\"signatures\":[{\"format\":\"CAdES\",\"source\":\"pdf\",\"signature_b64\":\"MA==\",\"binding\":[]}],\"timestamps\":[]}";

    static final String RECORD = "{\"id\":\"01REC\",\"status\":\"pending\",\"created_at\":\"2026-10-13T10:00:00Z\",\"client_ref\":\"contract-17\","
        + "\"container\":{\"format\":\"PAdES\",\"name\":\"contract.pdf\",\"sha256\":\"aa\"},\"signature_count\":1,"
        + "\"peo\":{\"sha256\":\"dd\",\"sha512\":\"ee\"},"
        + "\"preservation\":{\"profile\":\"https://trustbeat.eu/preservation/profile/pds-wst-v1\",\"profile_status\":\"draft\",\"preserve_until\":\"2056-10-13T10:00:00Z\"},"
        + "\"evidence_record\":{\"status\":\"pending\"},\"signatures\":[{\"index\":0,\"format\":\"CAdES\",\"indication\":\"TOTAL_PASSED\"}]}";

    static final String REPORT = "{\"report_version\":1,\"record_id\":\"01REC\",\"result\":\"failed\",\"claim\":\"At least one step failed.\","
        + "\"steps\":[{\"step\":1,\"name\":\"file\",\"title\":\"The presented file is the preserved file\",\"result\":\"failed\","
        + "\"checked_by\":[\"extractor\"],\"details\":[\"The digests differ.\"]}],\"signatures\":[],\"evidence_record\":[]}";

    static final class Call {
        final String method, uri, contentType, body;
        Call(String method, String uri, String contentType, String body) {
            this.method = method; this.uri = uri; this.contentType = contentType; this.body = body;
        }
        String method()      { return method; }
        String uri()         { return uri; }
        String contentType() { return contentType; }
        String body()        { return body; }
    }

    HttpServer server;
    final List<Call> calls = new ArrayList<>();
    volatile int status = 200;
    volatile String contentType = "application/json";
    volatile byte[] response = new byte[0];

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            calls.add(new Call(ex.getRequestMethod(), ex.getRequestURI().toString(), ex.getRequestHeaders().getFirst("Content-Type"), body));
            ex.getResponseHeaders().set("Content-Type", contentType);
            ex.sendResponseHeaders(status, response.length);
            try (OutputStream os = ex.getResponseBody()) { os.write(response); }
        });
        server.start();
    }

    @AfterEach
    void stop() { server.stop(0); }

    void answer(int s, String ct, String body) { status = s; contentType = ct; response = body.getBytes(StandardCharsets.UTF_8); }

    TrustBeat client() {
        return new TrustBeat.Builder().apiKey("tb_live_test").baseUrl("http://localhost:" + server.getAddress().getPort() + "/v1").build();
    }

    @Test
    void preserveSendsTheSubmissionUnchanged() {
        answer(202, "application/json", RECORD);
        SignaturePreservationRecord rec = client().preserveSignatures(SUBMISSION, "contract 17/a");
        Call c = calls.get(0);
        assertEquals("POST", c.method());
        assertEquals("/v1/signature-preservation?client_ref=contract+17%2Fa", c.uri());
        assertEquals("application/json", c.contentType());
        assertEquals(SUBMISSION, c.body());
        assertEquals("01REC", rec.getId());
        assertEquals("pending", rec.getStatus());
        assertEquals("PAdES", rec.getContainerFormat());
        assertEquals("dd", rec.getPeoSha256());
        assertEquals("contract-17", rec.getClientRef());
        assertEquals("2056-10-13T10:00:00Z", rec.getPreserveUntil());
        assertNull(rec.getEvidenceRecordUrl());
        assertEquals("TOTAL_PASSED", rec.getSignatures().get(0).get("indication"));
    }

    @Test
    void aSubmissionMustBeAJsonObject() {
        answer(202, "application/json", RECORD);
        assertThrows(IllegalArgumentException.class, () -> client().preserveSignatures("not json"));
        assertTrue(calls.isEmpty());
    }

    @Test
    void anInvalidSubmissionCarriesTheCode() {
        answer(400, "application/json", "{\"error\":{\"code\":\"INVALID_SUBMISSION\",\"message\":\"binding\"}}");
        TrustBeatException e = assertThrows(TrustBeatException.class, () -> client().preserveSignatures(SUBMISSION));
        assertEquals(400, e.getStatus());
        assertEquals("INVALID_SUBMISSION", e.getCode());
    }

    @Test
    void getAndList() {
        answer(200, "application/json", RECORD.replace("\"evidence_record\":{\"status\":\"pending\"}",
            "\"evidence_record\":{\"status\":\"ready\",\"download_url\":\"https://x/evidence-record.ers\"}"));
        SignaturePreservationRecord rec = client().getSignaturePreservation("01REC");
        assertEquals("/v1/signature-preservation/01REC", calls.get(0).uri());
        assertEquals("ready", rec.getEvidenceRecordStatus());
        assertEquals("https://x/evidence-record.ers", rec.getEvidenceRecordUrl());

        answer(200, "application/json", "{\"records\":[" + RECORD.replace(",\"signatures\":[{\"index\":0,\"format\":\"CAdES\",\"indication\":\"TOTAL_PASSED\"}]", "") + "]}");
        List<SignaturePreservationRecord> recs = client().listSignaturePreservations(10);
        assertEquals("/v1/signature-preservation?limit=10", calls.get(1).uri());
        assertEquals(1, recs.size());
        assertNull(recs.get(0).getSignatures());
    }

    @Test
    void notFoundAlsoForTheBinaryDownloads() {
        answer(404, "application/json", "{\"error\":{\"code\":\"NOT_FOUND\",\"message\":\"Record not found.\"}}");
        TrustBeat c = client();
        assertThrows(NotFoundException.class, () -> c.getSignaturePreservation("nope"));
        assertThrows(NotFoundException.class, () -> c.downloadSignaturePreservationPackage("nope"));
        assertThrows(NotFoundException.class, () -> c.verifySignaturePreservationPdf("nope", SUBMISSION));
    }

    @Test
    void thePackageIsTheZipBytes() {
        answer(200, "application/zip", "PK\u0003\u0004zip");
        byte[] zip = client().downloadSignaturePreservationPackage("01REC");
        assertEquals("/v1/signature-preservation/01REC/package", calls.get(0).uri());
        assertEquals("PK\u0003\u0004zip", new String(zip, StandardCharsets.UTF_8));
    }

    @Test
    void verifyReturnsTheReport() {
        answer(200, "application/json", REPORT);
        SignaturePreservationReport rep = client().verifySignaturePreservation("01REC", SUBMISSION);
        assertEquals("/v1/signature-preservation/01REC/verify", calls.get(0).uri());
        assertEquals(SUBMISSION, calls.get(0).body());
        assertEquals("failed", rep.getResult());
        assertEquals("file", rep.getSteps().get(0).getName());
        assertEquals(List.of("extractor"), rep.getSteps().get(0).getCheckedBy());
        assertEquals(1, Json.intVal(rep.getRaw(), "report_version"));
    }

    @Test
    void verifyAsPdfPostsTheSubmissionAndReturnsThePdf() {
        answer(200, "application/pdf", "%PDF-1.7");
        byte[] pdf = client().verifySignaturePreservationPdf("01REC", SUBMISSION);
        Call c = calls.get(0);
        assertEquals("POST", c.method());
        assertEquals("/v1/signature-preservation/01REC/verify?format=pdf", c.uri());
        assertEquals("application/json", c.contentType());
        assertEquals(SUBMISSION, c.body());
        assertEquals("%PDF-1.7", new String(pdf, StandardCharsets.UTF_8));
    }
}

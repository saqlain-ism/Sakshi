package dev.sakshi;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Sends signed Beckn requests from a Java participant, using only the JDK's HTTP client.
 *
 * <p>The body is turned into bytes exactly once; those same bytes are hashed, signed and sent.
 *
 * <pre>{@code
 * SignedClient client = new SignedClient("mybuyer.app", "k1", privateKeyBase64);
 * HttpResponse<String> r = client.post("https://gateway.example/search", searchJson);
 * }</pre>
 */
public final class SignedClient {
    private final String subscriberId;
    private final String uniqueKeyId;
    private final String privateKey;
    private final HttpClient http;

    public SignedClient(String subscriberId, String uniqueKeyId, String privateKeyBase64) {
        this(subscriberId, uniqueKeyId, privateKeyBase64,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
    }

    public SignedClient(String subscriberId, String uniqueKeyId, String privateKeyBase64, HttpClient http) {
        this.subscriberId = subscriberId;
        this.uniqueKeyId = uniqueKeyId;
        this.privateKey = privateKeyBase64;
        this.http = http;
    }

    public HttpRequest signedRequest(String url, String jsonBody) {
        byte[] body = jsonBody.getBytes(StandardCharsets.UTF_8);
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(20))
                .header("Content-Type", "application/json")
                .header("Authorization", AuthHeader.create(body, subscriberId, uniqueKeyId, privateKey))
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
    }

    public HttpResponse<String> post(String url, String jsonBody) throws IOException, InterruptedException {
        return http.send(signedRequest(url, jsonBody), HttpResponse.BodyHandlers.ofString());
    }
}

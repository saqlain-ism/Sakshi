package dev.sakshi;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Creates and verifies ONDC/Beckn {@code Authorization: Signature ...} headers.
 *
 * <p>Wire-compatible with the Python implementation ({@code sakshi.auth}). Ed25519 signatures are
 * deterministic, so for the same key, body and timestamps both produce the exact same header,
 * and the cross-language tests check that byte for byte.
 */
public final class AuthHeader {
    public static final String ALGORITHM = "ed25519";
    public static final String SIGNED_HEADERS = "(created) (expires) digest";
    public static final int DEFAULT_TTL_S = 30;
    public static final int MAX_WINDOW_S = 300;
    public static final int CLOCK_SKEW_S = 5;
    private static final Pattern PARAM = Pattern.compile("(\\w+)=\"([^\"]*)\"");

    private AuthHeader() {}

    /** Looks up a participant's key, e.g. in the network registry. */
    @FunctionalInterface
    public interface KeyResolver {
        KeyRecord resolve(String subscriberId, String uniqueKeyId);
    }

    /** What the registry says about one signing key. */
    public record KeyRecord(String subscriberId, String uniqueKeyId, String signingPublicKey,
                            double validFrom, double validUntil, String status) {
        boolean usableAt(double ts) {
            return "SUBSCRIBED".equals(status) && validFrom <= ts && ts <= validUntil;
        }
    }

    /** Parsed header parameters. */
    public record Params(String subscriberId, String uniqueKeyId, String algorithm, long created, long expires,
                         String headers, String signature) {}

    /** The verified sender of a request. */
    public record Sender(String subscriberId, String uniqueKeyId, long created, long expires) {}

    public static String bodyDigest(byte[] body) {
        return Base64.getEncoder().encodeToString(Blake2b.digest512(body));
    }

    public static String signingString(long created, long expires, String digestBase64) {
        return "(created): " + created + "\n(expires): " + expires + "\ndigest: BLAKE-512=" + digestBase64;
    }

    public static String create(byte[] body, String subscriberId, String uniqueKeyId, String privateKeyBase64,
                                long created, int ttlSeconds) {
        long expires = created + ttlSeconds;
        String sig = Ed25519.sign(privateKeyBase64,
                signingString(created, expires, bodyDigest(body)).getBytes(StandardCharsets.UTF_8));
        return "Signature keyId=\"" + subscriberId + "|" + uniqueKeyId + "|" + ALGORITHM + "\",algorithm=\"" + ALGORITHM
                + "\",created=\"" + created + "\",expires=\"" + expires + "\",headers=\"" + SIGNED_HEADERS
                + "\",signature=\"" + sig + "\"";
    }

    public static String create(byte[] body, String subscriberId, String uniqueKeyId, String privateKeyBase64) {
        return create(body, subscriberId, uniqueKeyId, privateKeyBase64, System.currentTimeMillis() / 1000, DEFAULT_TTL_S);
    }

    public static Params parse(String header) {
        if (header == null || header.isEmpty()) {
            throw new SakshiException("AUTH_MISSING", "no Authorization header");
        }
        if (!header.startsWith("Signature ")) {
            throw new SakshiException("AUTH_MALFORMED", "expected 'Signature' scheme");
        }
        Map<String, String> p = new HashMap<>();
        Matcher m = PARAM.matcher(header);
        while (m.find()) {
            p.put(m.group(1), m.group(2));
        }
        for (String k : new String[] {"keyId", "algorithm", "created", "expires", "headers", "signature"}) {
            if (!p.containsKey(k)) {
                throw new SakshiException("AUTH_MALFORMED", "missing parameter " + k);
            }
        }
        String[] key = p.get("keyId").split("\\|", -1);
        if (key.length != 3 || key[0].isEmpty() || key[1].isEmpty() || key[2].isEmpty()) {
            throw new SakshiException("AUTH_MALFORMED", "keyId must be subscriber_id|unique_key_id|algorithm");
        }
        try {
            return new Params(key[0], key[1], p.get("algorithm"), Long.parseLong(p.get("created")),
                    Long.parseLong(p.get("expires")), p.get("headers"), p.get("signature"));
        } catch (NumberFormatException e) {
            throw new SakshiException("AUTH_MALFORMED", "created/expires must be unix timestamps");
        }
    }

    /** Verifies a signed request with the same rules (and error codes) as the Python services. */
    public static Sender verify(String header, byte[] body, KeyResolver resolver, double now) {
        Params p = parse(header);
        if (!ALGORITHM.equals(p.algorithm()) || !SIGNED_HEADERS.equals(p.headers())) {
            throw new SakshiException("AUTH_UNSUPPORTED", "unsupported algorithm or signed headers");
        }
        if (p.expires() <= p.created()) {
            throw new SakshiException("AUTH_MALFORMED", "expires must be after created");
        }
        if (p.expires() - p.created() > MAX_WINDOW_S) {
            throw new SakshiException("AUTH_WINDOW_TOO_LONG", "validity window over " + MAX_WINDOW_S + "s");
        }
        if (p.created() > now + CLOCK_SKEW_S) {
            throw new SakshiException("AUTH_NOT_YET_VALID", "created is in the future");
        }
        if (p.expires() < now - CLOCK_SKEW_S) {
            throw new SakshiException("AUTH_EXPIRED", "signature expired");
        }
        KeyRecord key = resolver.resolve(p.subscriberId(), p.uniqueKeyId());
        if (key == null) {
            throw new SakshiException("AUTH_UNKNOWN_KEY", "no such key");
        }
        if ("REVOKED".equals(key.status())) {
            throw new SakshiException("AUTH_KEY_REVOKED", "key is revoked");
        }
        if (!key.usableAt(p.created())) {
            throw new SakshiException("AUTH_KEY_INACTIVE", "key not valid at signing time");
        }
        byte[] message = signingString(p.created(), p.expires(), bodyDigest(body)).getBytes(StandardCharsets.UTF_8);
        if (!Ed25519.verify(key.signingPublicKey(), message, p.signature())) {
            throw new SakshiException("AUTH_BAD_SIGNATURE", "signature does not match body or key");
        }
        return new Sender(p.subscriberId(), p.uniqueKeyId(), p.created(), p.expires());
    }

    public static Sender verify(String header, byte[] body, KeyResolver resolver) {
        return verify(header, body, resolver, System.currentTimeMillis() / 1000.0);
    }
}

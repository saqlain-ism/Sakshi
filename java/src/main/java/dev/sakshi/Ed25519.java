package dev.sakshi;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 using the JDK's built-in provider (Java 15+), with keys in the raw 32-byte form that
 * ONDC registries publish.
 *
 * <p>The JDK only accepts encoded keys, so the raw bytes are wrapped in the fixed DER prefix
 * for the Ed25519 algorithm identifier (OID 1.3.101.112).
 */
public final class Ed25519 {
    private static final byte[] X509_PREFIX = hex("302a300506032b6570032100");
    private static final byte[] PKCS8_PREFIX = hex("302e020100300506032b657004220420");

    private Ed25519() {}

    public static PublicKey publicKey(String base64Raw) {
        byte[] raw = Base64.getDecoder().decode(base64Raw);
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
        }
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(X509_PREFIX, raw)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 public key", e);
        }
    }

    /** Accepts a 32-byte seed, or a 64-byte libsodium secret key (seed || public). */
    public static PrivateKey privateKey(String base64Raw) {
        byte[] raw = Base64.getDecoder().decode(base64Raw);
        if (raw.length == 64) {
            raw = java.util.Arrays.copyOf(raw, 32);
        }
        if (raw.length != 32) {
            throw new IllegalArgumentException("Ed25519 private key must be 32 or 64 bytes");
        }
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, raw)));
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("invalid Ed25519 private key", e);
        }
    }

    public static String sign(String privateKeyBase64, byte[] message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(privateKey(privateKeyBase64));
            s.update(message);
            return Base64.getEncoder().encodeToString(s.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("signing failed", e);
        }
    }

    /** True only for a valid signature; never throws on malformed input. */
    public static boolean verify(String publicKeyBase64, byte[] message, String signatureBase64) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(publicKey(publicKeyBase64));
            s.update(message);
            return s.verify(Base64.getDecoder().decode(signatureBase64));
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            return false;
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}

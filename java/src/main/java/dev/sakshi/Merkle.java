package dev.sakshi;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Client-side verification of the Sakshi transparency log (RFC 6962 / RFC 9162 hashing).
 *
 * <p>A Java buyer or seller app never has to trust the witness. With these functions it can check
 * that its receipt is in the log ({@link #verifyInclusion}) and that the log only ever grew
 * ({@link #verifyConsistency}).
 */
public final class Merkle {
    private Merkle() {}

    static byte[] sha256(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (byte[] p : parts) {
                md.update(p);
            }
            return md.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] leafHash(byte[] entry) {
        return sha256(new byte[] {0}, entry);
    }

    public static byte[] nodeHash(byte[] left, byte[] right) {
        return sha256(new byte[] {1}, left, right);
    }

    /** RFC 9162 2.1.3.2: is {@code leaf} (a leaf hash) at {@code index} in the tree with {@code root}? */
    public static boolean verifyInclusion(byte[] leaf, long index, long size, List<byte[]> proof, byte[] root) {
        if (index < 0 || index >= size) {
            return false;
        }
        long fn = index;
        long sn = size - 1;
        byte[] r = leaf;
        for (byte[] p : proof) {
            if (sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                r = nodeHash(p, r);
                if ((fn & 1) == 0) {
                    while (fn != 0 && (fn & 1) == 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                r = nodeHash(r, p);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return sn == 0 && Arrays.equals(r, root);
    }

    /** RFC 9162 2.1.4.2: is the tree of {@code oldSize} a prefix of the tree of {@code newSize}? */
    public static boolean verifyConsistency(long oldSize, long newSize, byte[] oldRoot, byte[] newRoot,
                                            List<byte[]> proof) {
        if (oldSize == newSize) {
            return Arrays.equals(oldRoot, newRoot) && proof.isEmpty();
        }
        if (oldSize <= 0 || oldSize > newSize || proof.isEmpty()) {
            return false;
        }
        List<byte[]> path = new java.util.ArrayList<>(proof);
        if ((oldSize & (oldSize - 1)) == 0) {
            path.add(0, oldRoot);
        }
        long fn = oldSize - 1;
        long sn = newSize - 1;
        while ((fn & 1) == 1) {
            fn >>= 1;
            sn >>= 1;
        }
        byte[] fr = path.get(0);
        byte[] sr = path.get(0);
        for (byte[] c : path.subList(1, path.size())) {
            if (sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                fr = nodeHash(c, fr);
                sr = nodeHash(c, sr);
                if ((fn & 1) == 0) {
                    while (fn != 0 && (fn & 1) == 0) {
                        fn >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                sr = nodeHash(sr, c);
            }
            fn >>= 1;
            sn >>= 1;
        }
        return Arrays.equals(fr, oldRoot) && Arrays.equals(sr, newRoot) && sn == 0;
    }

    /** A Signed Tree Head as served by the witness at {@code GET /ledger/sth}. */
    public record TreeHead(String logId, long treeSize, String rootHash, long timestamp, String keyId,
                           String signature) {
        /** The exact bytes the witness signed: a fixed prefix plus canonical JSON (sorted keys). */
        public byte[] signedBytes() {
            String json = "{\"log_id\":" + quote(logId) + ",\"root_hash\":" + quote(rootHash)
                    + ",\"timestamp\":" + timestamp + ",\"tree_size\":" + treeSize + "}";
            return ("sakshi/tree-head/v1\n" + json).getBytes(StandardCharsets.UTF_8);
        }

        public boolean verify(String witnessPublicKeyBase64) {
            return Ed25519.verify(witnessPublicKeyBase64, signedBytes(), signature);
        }

        public byte[] root() {
            return Base64.getDecoder().decode(rootHash);
        }
    }

    /** JSON string quoting matching Python's json.dumps(ensure_ascii=False). */
    static String quote(String s) {
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"' -> b.append("\\\"");
                case '\\' -> b.append("\\\\");
                case '\n' -> b.append("\\n");
                case '\r' -> b.append("\\r");
                case '\t' -> b.append("\\t");
                case '\b' -> b.append("\\b");
                case '\f' -> b.append("\\f");
                default -> {
                    if (c < 0x20) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
                }
            }
        }
        return b.append('"').toString();
    }
}

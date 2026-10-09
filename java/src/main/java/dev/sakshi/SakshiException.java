package dev.sakshi;

/** A verification failure with a stable, machine-readable code (same codes as the Python services). */
public class SakshiException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    public SakshiException(String code, String message) {
        super(code + ": " + message);
        this.code = code;
    }

    public String code() {
        return code;
    }
}

package exercise.proxy1;

public class TrustSourceException extends RuntimeException {
  public TrustSourceException() {
  }

  public TrustSourceException(String message) {
    super(message);
  }

  public TrustSourceException(String message, Throwable cause) {
    super(message, cause);
  }

  public TrustSourceException(Throwable cause) {
    super(cause);
  }

  public TrustSourceException(String message, Throwable cause, boolean enableSuppression,
                              boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}

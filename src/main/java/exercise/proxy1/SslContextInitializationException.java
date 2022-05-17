package exercise.proxy1;

public class SslContextInitializationException extends RuntimeException {
  public SslContextInitializationException() {
  }

  public SslContextInitializationException(String message) {
    super(message);
  }

  public SslContextInitializationException(String message, Throwable cause) {
    super(message, cause);
  }

  public SslContextInitializationException(Throwable cause) {
    super(cause);
  }

  public SslContextInitializationException(String message, Throwable cause,
                                           boolean enableSuppression,
                                           boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}

package exercise.proxy1;

public class MitmException extends RuntimeException {

  public MitmException() {
  }

  public MitmException(String message) {
    super(message);
  }

  public MitmException(String message, Throwable cause) {
    super(message, cause);
  }

  public MitmException(Throwable cause) {
    super(cause);
  }

  public MitmException(String message, Throwable cause, boolean enableSuppression,
                       boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}

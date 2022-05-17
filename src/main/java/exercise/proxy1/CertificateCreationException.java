package exercise.proxy1;

public class CertificateCreationException extends RuntimeException{

  public CertificateCreationException() {
  }

  public CertificateCreationException(String message) {
    super(message);
  }

  public CertificateCreationException(String message, Throwable cause) {
    super(message, cause);
  }

  public CertificateCreationException(Throwable cause) {
    super(cause);
  }

  public CertificateCreationException(String message, Throwable cause, boolean enableSuppression,
                                      boolean writableStackTrace) {
    super(message, cause, enableSuppression, writableStackTrace);
  }
}

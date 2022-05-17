package exercise.proxy1;

public class KeyGeneratorException extends RuntimeException {
  public KeyGeneratorException() {
  }

  public KeyGeneratorException(String message) {
    super(message);
  }

  public KeyGeneratorException(String message, Throwable cause) {
    super(message, cause);
  }

  public KeyGeneratorException(Throwable cause) {
    super(cause);
  }
}

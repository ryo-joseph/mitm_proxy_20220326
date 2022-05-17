package exercise.proxy1;

public class MitmConstans {

  public static final String DEFAULT_MESSAGE_DIGEST = is32BitJvm() ? "SHA256" : "SHA384";

  public static final String DEFAULT_KEYSTORE_TYPE = "PKCS12";

  private static boolean is32BitJvm() {
    Integer bits = Integer.getInteger("sun.arc.data.model");

    return bits != null && bits == 32;
  }
}

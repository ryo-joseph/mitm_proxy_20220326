package exercise.proxy1;

import java.math.BigInteger;
import java.security.Key;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.util.Random;

public class EncriptionUtil {

  public static BigInteger getRandomBigInteger(int bits) {
    return new BigInteger(bits, new Random());
  }

  public static String getSignatureAlgorithm(String messageDigest, Key signingKey) {
    return messageDigest + "with" + getDigitalSignatureType(signingKey);
  }

  public static String getDigitalSignatureType(Key signingKey) {
    if (signingKey instanceof ECKey) {
      return "ECDSA";
    } else if (signingKey instanceof RSAKey) {
      return "RSA";
    } else if (signingKey instanceof DSAKey) {
      return "DSA";
    } else {
      throw new IllegalArgumentException("");
    }
  }

  public static boolean isRsaKey(Key key) {
    return "RSA".equals(key.getAlgorithm());
  }

  public static boolean isEcKey(Key key) {
    return "EC".equals(key.getAlgorithm());
  }
}

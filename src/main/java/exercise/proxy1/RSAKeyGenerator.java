package exercise.proxy1;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAKeyGenerator implements KeyGenerator {
  private static final String RSA_kEY_GEN_ALGORITHM = "RSA";
  private static final int DEFAULT_KEY_SIZE = 2048;

  private final int keySize;

  public RSAKeyGenerator() {
    this.keySize = DEFAULT_KEY_SIZE;
  }

  @Override
  public KeyPair generate() {
    KeyPairGenerator generator;
    try {
      generator = KeyPairGenerator.getInstance(RSA_kEY_GEN_ALGORITHM);
      generator.initialize(keySize);
    } catch (NoSuchAlgorithmException e) {
      throw new KeyGeneratorException("Unable to generate " + keySize + "-bit RSA public/private key pair");
    }

    return generator.generateKeyPair();
  }
}

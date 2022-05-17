package exercise.proxy1;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.Key;
import java.security.KeyPair;
import java.security.Security;
import java.text.SimpleDateFormat;
import java.util.Date;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import lombok.extern.log4j.Log4j;
import lombok.extern.log4j.Log4j2;
import lombok.extern.slf4j.XSlf4j;

@RequiredArgsConstructor
@Log
public class RootCertificateGenerator implements CertificateAndKeySource {
  private final CertificateInfo rootCertificateInfo;
  private final String messageDigest;
  private final KeyGenerator keyGenerator;
  private final SecurityProviderTool securityProviderTool;

  private final Supplier<CertificateAndKey> generateCertificateAndKey = Suppliers.memoize(
      () -> generateRootCertificate());

  @Override
  public CertificateAndKey load() {
    return generateCertificateAndKey.get();
  }

  private CertificateAndKey generateRootCertificate() {
    long generationStart = System.currentTimeMillis();

    final KeyPair caKeyPair = keyGenerator.generate();

    final CertificateAndKey certificateAndKey = securityProviderTool.createCARootCertificate(
        rootCertificateInfo,
        caKeyPair,
        messageDigest);

    long generationFinished = System.currentTimeMillis();

    return certificateAndKey;
  }

  public static Builder builder() {
    return new Builder();
  }

  public static class Builder {

    private CertificateInfo certificateInfo = CertificateInfo.builder()
        .commonName(getDefaultCommonName())
        .organization("CA dynamically generated")
        .notBefore(new Date(System.currentTimeMillis() - 365L * 24L * 60L * 60L * 1000L))
        .notAfter(new Date(System.currentTimeMillis() + 365L * 24L * 60L * 60L * 1000L))
        .build();

    private KeyGenerator keyGenerator = new RSAKeyGenerator();

    private String messageDigest = MitmConstans.DEFAULT_MESSAGE_DIGEST;

    private SecurityProviderTool securityProviderTool = new DefaultSecurityProviderTool();

    public Builder certificateInfo(CertificateInfo certificateInfo) {
      this.certificateInfo = certificateInfo;
      return this;
    }

    public Builder keyGenerator(KeyGenerator keyGenerator) {
      this.keyGenerator = keyGenerator;
      return this;
    }

    public Builder messageDigest(KeyGenerator keyGenerator) {
      this.messageDigest = messageDigest;
      return this;
    }

    public RootCertificateGenerator build() {
      return new RootCertificateGenerator(
          certificateInfo,
          messageDigest,
          keyGenerator,
          securityProviderTool);
    }
  }

  private static String getDefaultCommonName() {
    String hostName;
    try {
      hostName = InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      hostName = "localhost";
    }

    SimpleDateFormat dateFormat = new SimpleDateFormat("yy" +
        "yy-MM-dd HH:mm:ss zzz");

    final String currentDateTime = dateFormat.format(new Date());

    String defaultCN = "Generated CA (" + hostName + ")" + currentDateTime;

    return defaultCN.length() <= 64 ? defaultCN : defaultCN.substring(0, 63);
  }
}

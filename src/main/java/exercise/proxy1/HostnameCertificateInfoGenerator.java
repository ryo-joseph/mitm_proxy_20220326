package exercise.proxy1;

import com.sun.jdi.event.StepEvent;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

public class HostnameCertificateInfoGenerator implements CertificateInfoGenerator {
  private static final String DEFAULT_IMPERSONATED_CERT_ORG = "Impersonated Certificate";
  private static final String DEFAULT_IMPERSONATED_CERT_ORG_UNIT = "LittleProxy MITM";

  @Override
  public CertificateInfo generate(List<String> hostNames, X509Certificate originalCertificate) {
    // TOOD hostNamesのチェック
    final String commonName = hostNames.get(0);

    return CertificateInfo.builder()
        .commonName(commonName)
        .organization(DEFAULT_IMPERSONATED_CERT_ORG)
        .organizationUnit(DEFAULT_IMPERSONATED_CERT_ORG_UNIT)
        .notBefore(getNotBefore())
        .notAfter(getNotAfter())
        .subjectAlternativeNames(hostNames)
        .build();
  }

  protected Date getNotBefore() {
    return new Date(System.currentTimeMillis() - 365L * 24L * 60L * 60L * 1000L);
  }

  protected Date getNotAfter() {
    return new Date(System.currentTimeMillis() + 365L * 24L * 60L * 60L * 1000L);
  }
}

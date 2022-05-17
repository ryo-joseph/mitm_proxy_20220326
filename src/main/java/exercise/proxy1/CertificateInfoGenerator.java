package exercise.proxy1;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateInfoGenerator {
  CertificateInfo generate(List<String> hostNames, X509Certificate originalCertificate);
}

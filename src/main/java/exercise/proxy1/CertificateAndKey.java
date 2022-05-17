package exercise.proxy1;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public class CertificateAndKey {
  private final X509Certificate certificate;
  private final PrivateKey privateKey;
}

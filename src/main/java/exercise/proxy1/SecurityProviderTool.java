package exercise.proxy1;

import java.io.Reader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public interface SecurityProviderTool {

  CertificateAndKey createCARootCertificate(
      CertificateInfo certificateInfo,
      KeyPair keyPair,
      String messageDigest);

  CertificateAndKey createServerCertificate(
      CertificateInfo certificateInfo,
      X509Certificate caRootCertificate,
      PrivateKey caPrivateKey,
      KeyPair serverKeyPair,
      String messageDigest
  );

  X509Certificate decodePemEncodedCertificate(Reader certificateReader);
}

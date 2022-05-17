package exercise.proxy1;

import com.google.common.io.CharStreams;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class DefaultSecurityProviderTool implements SecurityProviderTool {
  private final SecurityProviderTool bouncyCastle = new BouncyCastleSecurityProviderTool();


  @Override
  public CertificateAndKey createCARootCertificate(CertificateInfo certificateInfo, KeyPair keyPair,
                                                 String messageDigest) {
    return bouncyCastle.createCARootCertificate(certificateInfo, keyPair, messageDigest);
  }

  @Override
  public CertificateAndKey createServerCertificate(CertificateInfo certificateInfo,
                                                   X509Certificate caRootCertificate,
                                                   PrivateKey caPrivateKey, KeyPair serverKeyPair,
                                                   String messageDigest) {

    return bouncyCastle.createServerCertificate(certificateInfo, caRootCertificate, caPrivateKey, serverKeyPair, messageDigest);
  }

  @Override
  public X509Certificate decodePemEncodedCertificate(Reader certificateReader) {
    Certificate certificate;

   try(InputStream certificateAsStream = new ByteArrayInputStream(CharStreams.toString(certificateReader).getBytes(StandardCharsets.US_ASCII))) {
     final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
     certificate = certificateFactory.generateCertificate(certificateAsStream);
   } catch (CertificateException | IOException e) {
     throw new ImportException("Attempted to import non-X.509 certificate as X.509 certificate");
   }

   if (!(certificate instanceof X509Certificate)) {
     throw new ImportException("Attempted to import non-X.509 certificate as X.509 certificate");
   }

    return (X509Certificate) certificate;
  }
}

package exercise.proxy1;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.reflect.ClassPath;
import com.sun.jdi.event.StepEvent;
import io.netty.handler.ipfilter.AbstractRemoteAddressFilter;
import java.io.StringReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class TrustUtil {

  public static final X509Certificate[] EMPTY_CERTIFICATE_ARRAY = new X509Certificate[0];

  private static final SecurityProviderTool securityProviderTool = new DefaultSecurityProviderTool();

  private static final Pattern CA_PEM_PATTERN = Pattern.compile(
      "-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", Pattern.DOTALL);

  private static final String DEFAULT_TRUSTED_CA_RESOURCE = "/keystore.jks";

  private static final Supplier<X509Certificate[]> javaTrustedCAs =
      Suppliers.memoize(new Supplier<X509Certificate[]>() {
        @Override
        public X509Certificate[] get() {
          X509TrustManager defaultTrustManager = getDefaultTrustManager();

          X509Certificate[] defaultJavaTrustedCerts = defaultTrustManager.getAcceptedIssuers();

          if (defaultJavaTrustedCerts != null) {
            return defaultJavaTrustedCerts;
          } else {
            return EMPTY_CERTIFICATE_ARRAY;
          }
        }
      });

  private static final Supplier<X509Certificate[]> builtinTrustedCAs = Suppliers.memoize(
      new Supplier<X509Certificate[]>() {
        @Override
        public X509Certificate[] get() {
          try {
            String allCAs = ClasspathResourceUtil.classpathResourceToString(
                DEFAULT_TRUSTED_CA_RESOURCE,
                StandardCharsets.UTF_8);
            return readX509CertificatesFromPem(allCAs);
          } catch (UncheckedIOException e) {
            return new X509Certificate[0];
          }
        }
      }
  );

  public static X509Certificate[] getBuiltinTrustedCAs() {
    return builtinTrustedCAs.get();
  }

  public static X509Certificate[] getJavaTrustedCAs() {
    return javaTrustedCAs.get();
  }

  public static X509Certificate[] readX509CertificatesFromPem(String pemEncodedCAs) {
    List<X509Certificate> certificates = new ArrayList<>(500);

    final Matcher pemMatcher = CA_PEM_PATTERN.matcher(pemEncodedCAs);

    while (pemMatcher.find()) {
      final String singleCAPem = pemMatcher.group();

      X509Certificate certificate = readSingleX509Certificate(singleCAPem);
      certificates.add(certificate);
    }

    return  certificates.toArray(new X509Certificate[0]);
  }

  public static X509Certificate readSingleX509Certificate(String x509CertificatePem) {
    return securityProviderTool.decodePemEncodedCertificate(new StringReader(x509CertificatePem));
  }

  public static X509TrustManager getDefaultTrustManager() {
    TrustManagerFactory tmf;
    try {
      tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init((KeyStore) null);
    } catch (NoSuchAlgorithmException | KeyStoreException e) {
      throw new TrustSourceException("Unable to retrieve default TrustManagerFactory", e);
    }

    for (TrustManager tm : tmf.getTrustManagers()) {
      if (tm instanceof X509TrustManager) {
        return (X509TrustManager) tm;
      }
    }

    throw new TrustSourceException("No X509TrustManager found");
  }
}

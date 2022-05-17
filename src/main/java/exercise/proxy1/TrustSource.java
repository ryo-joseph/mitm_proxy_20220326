package exercise.proxy1;

import com.google.common.base.Objects;
import com.google.common.collect.ObjectArrays;
import io.netty.util.internal.ObjectUtil;
import java.security.cert.X509Certificate;
import javax.swing.TransferHandler;

public class TrustSource {

  private final X509Certificate[] trustedCAs;

  public TrustSource(X509Certificate... trustedCAs) {
    if (trustedCAs == null) {
      this.trustedCAs = TrustUtil.EMPTY_CERTIFICATE_ARRAY;
    } else {
      this.trustedCAs = trustedCAs;
    }
  }

  private static final TrustSource DEFAULT_TRUST_SOURCE = TrustSource.javaTrustSource().add(TrustSource.builtinTrustSource());

  public static TrustSource javaTrustSource() {
    return new TrustSource(TrustUtil.getJavaTrustedCAs());
  }

  public static TrustSource builtinTrustSource() {
    return new TrustSource(TrustUtil.getBuiltinTrustedCAs());
  }

  public static TrustSource defaultTrustSource() {
    return DEFAULT_TRUST_SOURCE;
  }

  public X509Certificate[] getTrustedCAs() {
    return trustedCAs;
  }

  public TrustSource add(String trustedPemEncodedCAs) {
    if (trustedPemEncodedCAs == null) {
      throw new IllegalArgumentException("PEM-encoded trusted CA String cannot be null");
    }

    final X509Certificate[] trustedCertificates =
        TrustUtil.readX509CertificatesFromPem(trustedPemEncodedCAs);

    return add(trustedCertificates);
  }

  public TrustSource add(X509Certificate... trustedCertificates) {
    if(trustedCertificates == null || trustedCertificates.length == 0) {
      return this;
    }

    X509Certificate[] newTrustedCAs = ObjectArrays.concat(trustedCAs, trustedCertificates, X509Certificate.class);

    return new TrustSource(newTrustedCAs);
  }

  public TrustSource add(TrustSource trustSource) {
    if(trustSource == null) {
      throw new IllegalArgumentException("TrustSource cannot be null");
    }

    return add(trustSource.getTrustedCAs());
  }
}

package exercise.proxy1;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableList;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SupportedCipherSuiteFilter;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import lombok.extern.java.Log;

@Log
public class ImpersonatingMitmManager {
  private Cache<String, SslContext> sslContextCache;
  private final CertificateInfoGenerator certificateInfoGenerator;
  private final KeyGenerator serverKeyGenerator;

  private final TrustSource trustSource;

  private final CertificateAndKeySource rootCertificateSource;
  private final SecurityProviderTool securityProviderTool;

  private final String serverCertificateMessageDigest;

  private final List<String> clientCipherSuites;
  private final List<String> serverCipherSuites;

  private Supplier<CertificateAndKey> rootCertificate = Suppliers.memoize(
      new Supplier<CertificateAndKey>() {
        @Override
        public CertificateAndKey get() {
          return rootCertificateSource.load();
        }
      });

  public ImpersonatingMitmManager(
      CertificateAndKeySource rootCertificateSource,
      KeyGenerator serverKeyGenerator,
      String serverMessageDigest,
      TrustSource trustSource,
      int sslContextCacheConcurrencyLevel,
      long cacheExpirationIntervalMs,
      SecurityProviderTool securityProviderTool,
      CertificateInfoGenerator certificateInfoGenerator,
      List<String> serverCipherSuites,
      List<String> clientCipherSuites) {
    this.rootCertificateSource = rootCertificateSource;
    this.trustSource = trustSource;
    this.serverCertificateMessageDigest = serverMessageDigest;
    this.certificateInfoGenerator = certificateInfoGenerator;
    this.securityProviderTool = securityProviderTool;
    this.serverCipherSuites = ImmutableList.copyOf(serverCipherSuites);
    this.clientCipherSuites = ImmutableList.copyOf(clientCipherSuites);
    this.serverKeyGenerator = serverKeyGenerator;
    this.sslContextCache = CacheBuilder.newBuilder()
        .concurrencyLevel(sslContextCacheConcurrencyLevel)
        .expireAfterAccess(
            cacheExpirationIntervalMs, TimeUnit.MILLISECONDS)
        .build();
  }

  private SslContext createImpersonatingSslContext(CertificateInfo certificateInfo) {
    long impersonationStart = System.currentTimeMillis();

    final KeyPair serverKeyPair = serverKeyGenerator.generate();

    log.info("rootCertificate: " + rootCertificate);
    log.info("rootCertificate.get(): " + rootCertificate.get());
    X509Certificate caRootCertificate = rootCertificate.get().getCertificate();
    PrivateKey caPrivateKey = rootCertificate.get().getPrivateKey();
    if (caRootCertificate == null || caPrivateKey == null) {
      throw new IllegalArgumentException();
    }

    if (EncriptionUtil.isEcKey(serverKeyPair.getPrivate()) &&
    EncriptionUtil.isRsaKey(caPrivateKey)) {
      log.warning("CA private key is an RSA key and impersonated server private key is an Elliptic Curve key. JDK bug 8136442 may prevent the proxy server from creating connections to clients due to 'no cipher suites in common'");
    }

    CertificateAndKey impersonatedCertificateAndKey = securityProviderTool.createServerCertificate(
        certificateInfo,
        caRootCertificate,
        caPrivateKey,
        serverKeyPair,
        serverCertificateMessageDigest);

    X509Certificate[] certChain = {impersonatedCertificateAndKey.getCertificate(), caRootCertificate};
    SslContext sslContext;
    try {
      sslContext = SslContextBuilder.forServer(impersonatedCertificateAndKey.getPrivateKey(), certChain)
          .ciphers(clientCipherSuites, SupportedCipherSuiteFilter.INSTANCE)
          .build();
    } catch (SSLException sslException) {
      throw new MitmException();
    }

    long impersonationFinish = System.currentTimeMillis();

    return sslContext;
  }

  private SslContext createImpersonatingSslContext(SSLSession sslSession, String hostNameToImpersonate) {
    X509Certificate originalCertificate = SslUtil.getServerCertificate(sslSession);

    final CertificateInfo certificateInfo = certificateInfoGenerator
        .generate(Collections.singletonList(hostNameToImpersonate), originalCertificate);

    final SslContext sslContext = createImpersonatingSslContext(certificateInfo);

    return  sslContext;
  }

  public SslContext getHostNameImpersonatingSslContext(
      String hostNameToImpersonate, SSLSession sslSession) {

    try {
      return sslContextCache.get(
          hostNameToImpersonate,
          () -> createImpersonatingSslContext(sslSession, hostNameToImpersonate));
    } catch (ExecutionException e) {
      throw new SslContextInitializationException(e);
    } catch (Exception e) {
      e.printStackTrace();
      throw e;
    }
  }

}

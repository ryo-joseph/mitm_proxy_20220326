package exercise.proxy1;

import com.google.common.base.Supplier;
import com.google.common.base.Suppliers;
import com.google.common.io.CharStreams;
import io.netty.handler.ssl.OpenSsl;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.swing.plaf.SplitPaneUI;
import lombok.extern.java.Log;

@Log
public class SslUtil {

  private static final String DEFAULT_CIPHERS_LIST_RESOUCE = "/default-ciphers.txt";

  private static final Supplier<List<String>> defaultCipherList =
      Suppliers.memoize(new Supplier<List<String>>() {
        @Override
        public List<String> get() {
         List<String> ciphers;
         if (OpenSsl.isAvailable()) {
           ciphers = getBuiltinCipherList();
         } else {
           ciphers = getEnabledJdkCipherSuites();

           if (ciphers.isEmpty()) {
             ciphers = getBuiltinCipherList();
           }
         }

          return ciphers;
        }
      });

  public static List<String> getDefaultCipherList() {
    return defaultCipherList.get();
  }

  public static X509Certificate getServerCertificate(SSLSession sslSession) {
    Certificate[] peerCertificates;

    try {
      peerCertificates = sslSession.getPeerCertificates();
      System.out.println("peerCertificates: " + peerCertificates);
    } catch (SSLPeerUnverifiedException e) {
      e.printStackTrace();
      peerCertificates = null;
    }

    if (peerCertificates != null && peerCertificates.length > 0) {
      Certificate peerCertificate = peerCertificates[0];
      if (peerCertificate != null && peerCertificate instanceof X509Certificate) {
        return (X509Certificate) peerCertificate;
      }
    }

    return null;
  }

  public static List<String> getEnabledJdkCipherSuites() {
    try {
      final SSLContext sslContext = SSLContext.getInstance("TLS");
      sslContext.init(null, null, null);

      String[] defaultCiphers = sslContext.getServerSocketFactory().getDefaultCipherSuites();

      return Arrays.asList(defaultCiphers);
    } catch (Throwable e) {
      log.info("Unable to load default JDK server cipher list from SSLContext");

      return Collections.emptyList();
    }
  }

  public static List<String> getBuiltinCipherList() {
    try (final InputStream cipherListStream =
             SslUtil.class.getResourceAsStream(DEFAULT_CIPHERS_LIST_RESOUCE);) {
      if (cipherListStream == null) {
        return Collections.emptyList();
      }

      final Reader reader =
          new InputStreamReader(cipherListStream, StandardCharsets.UTF_8);

      return CharStreams.readLines(reader);
    } catch (IOException e) {
      return Collections.emptyList();
    }
  }
}

package exercise.proxy1;

import com.sun.source.doctree.SeeTree;
import io.netty.handler.ssl.SslContext;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import java.util.spi.AbstractResourceBundleProvider;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import lombok.val;
import org.apache.http.HttpServerConnection;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpService;

public class ProxyWorker extends Thread {
  public static String targetHost;
  public static int targetPort;

  private static final Logger logger = Logger.getLogger(ProxyWorker.class.getName());

  private final HttpService httpService;
  private final HttpServerConnection inconn;
  private final Socket insocket;

  protected SSLContext sslContext;
  protected SSLSocketFactory sslSocketFactory;

  private ImpersonatingMitmManager impersonatingMitmManager;

  final DefaultSecurityProviderTool defaultSecurityProviderTool = new DefaultSecurityProviderTool();

  public ProxyWorker(final HttpService httpService,
                     final HttpServerConnection inconn,
                     final Socket insocket)
      throws IOException, KeyStoreException, NoSuchAlgorithmException,
      KeyManagementException, CertificateException, UnrecoverableKeyException {
    super();
    this.httpService = httpService;
    this.inconn = inconn;
    this.insocket = insocket;

    // TODO
    System.setProperty("javax.net.debug", "all");
    char[] commonPassword = "changeit".toCharArray();
    final KeyStore ks1 = KeyStore.getInstance("JKS");
//    ks1.load(new FileInputStream("src/main/resources/keystore.jks"), commonPassword);
    ks1.load(new FileInputStream("C:\\Program Files\\Amazon Corretto\\jdk11.0.11_9\\lib\\security\\cacerts"), commonPassword);
    System.out.println("KeyStore's size = " + ks1.size());
    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks1, commonPassword);

    final KeyStore emptyTrustStore = KeyStore.getInstance("JKS");
    emptyTrustStore.load(new FileInputStream("C:\\Program Files\\Amazon Corretto\\jdk11.0.11_9\\lib\\security\\cacerts"), "changeit".toCharArray());
//    emptyTrustStore.load(new FileInputStream("src/main/resources/keystore_20220521.jks"), "changeit".toCharArray());
    final TrustManagerFactory emptyTMF = TrustManagerFactory.getInstance("PKIX");
    emptyTMF.init(emptyTrustStore);

    final SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(kmf.getKeyManagers(), emptyTMF.getTrustManagers(), null);
    this.sslSocketFactory = sslContext.getSocketFactory();

    impersonatingMitmManager = new ImpersonatingMitmManager(
        RootCertificateGenerator.builder().build(),
        new RSAKeyGenerator(),
        MitmConstans.DEFAULT_MESSAGE_DIGEST,
        TrustSource.defaultTrustSource(),
        8,
        TimeUnit.MILLISECONDS.convert(5, TimeUnit.MINUTES),
        new DefaultSecurityProviderTool(),
        new HostnameCertificateInfoGenerator(),
        SslUtil.getDefaultCipherList(),
        SslUtil.getDefaultCipherList()
    );

    // TODO

  }

  private static String readLine(InputStream inputStream) throws IOException {
    String line = null;
    int ch = -1;
    try {
      while ((ch = inputStream.read()) > 0) {
        if (ch == '\r') {
          continue;
        } else if (ch == '\n') {
          break;
        } else {
          line = (line != null ? line + (char) ch : "" + (char) ch);
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      if (line == null && ch == '\n') {
        return "";
      }
      return line;
    }
  }

  @Override
  public void run() {
    logger.info("New connection thread");
    final HttpContext context = new BasicHttpContext(null);
    boolean switchToHttps = false;
    context.setAttribute("switch_to_https", switchToHttps);
    context.setAttribute("https.host", "");
    context.setAttribute("https.port", -1);
    try {
      while (!Thread.interrupted() && inconn.isOpen()) {
        switchToHttps = (Boolean) context.getAttribute("switch_to_https");
        if (switchToHttps) {
          logger.info("Switching HTTPS Tunneling mode...");
          break;
        } else {
          logger.info("handleRequest start");
          this.httpService.handleRequest(this.inconn, context);
          switchToHttps = (Boolean)context.getAttribute("switch_to_https");
//          switchToHttps = Boolean.valueOf((String) context.getAttribute("switch_to_https"));
          logger.info("switchToHttps: " + switchToHttps);
          if(!switchToHttps) {
            this.inconn.close();
          }
          System.out.println("handleRequest end");
        }
      }
      if(switchToHttps) {
        logger.info("Https mode.");
        String targetHost = (String)context.getAttribute("https.host");
        int targetPort = (Integer)context.getAttribute("https.port");
        logger.info("HTTPS : host=[" + targetHost + "], port=[" + targetPort + "]");
        Socket targetSocket = null;
        if ("localhost".equals(targetHost) && 8081 == targetPort) {
          logger.info("to localhost");
          targetSocket = new Socket("localhost", 8889);
        } else {
          logger.info("to " + targetHost);
//          targetSocket = new Socket(targetHost, targetPort);
          targetHost = (String)context.getAttribute("https.host");
          targetPort = (Integer)context.getAttribute("https.port");

          SSLSocket clientSslSocket = (SSLSocket) sslSocketFactory.createSocket(
              targetHost, targetPort);
          clientSslSocket.setUseClientMode(true);

          X509Certificate originalCertificate = SslUtil.getServerCertificate(clientSslSocket.getSession());

          final val hostnameCertificateInfoGenerator = new HostnameCertificateInfoGenerator();

          TrustManagerFactory tmf = TrustManagerFactory
              .getInstance(TrustManagerFactory.getDefaultAlgorithm());
          KeyStore ks = KeyStore.getInstance("JKS");
          ks.load(new FileInputStream("src/main/resources/keystore.jks"), "changeit".toCharArray()); // You don't need the KeyStore instance to come from a file.

          tmf.init(ks);
          X509Certificate caCertificate = null;
          final val trustManagers = tmf.getTrustManagers();
          for (TrustManager trustManager : trustManagers) {
            for(X509Certificate c: ((X509TrustManager)trustManager).getAcceptedIssuers()) {
              System.out.println(c.getIssuerX500Principal());
              if (c.getIssuerX500Principal().getName().contains("interca")) {
                caCertificate = c;
                break;
              }
            }
          }

          // keystore内に、認証認可の秘密鍵のインポートが必要
          KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(
              "inter_key",
              new KeyStore.PasswordProtection("changeit".toCharArray())
          );

          String cn = originalCertificate.getSubjectX500Principal()
              .getName().split(",")[0].split("=")[1];
          System.out.println(cn);

          CertificateAndKey certificateAndKey = defaultSecurityProviderTool.createServerCertificate(
              hostnameCertificateInfoGenerator.generate(List.of(cn), originalCertificate),
//              RootCertificateGenerator.builder().build().load().getCertificate(),
              caCertificate,
//              new RSAKeyGenerator().generate().getPrivate(),
              privateKeyEntry.getPrivateKey(),
              new RSAKeyGenerator().generate(),
              MitmConstans.DEFAULT_MESSAGE_DIGEST
          );

          X509Certificate[] chain = new X509Certificate[1];
          chain[0] = certificateAndKey.getCertificate();
          ks.setKeyEntry("new_keystore_alias", certificateAndKey.getPrivateKey(), "changeit".toCharArray(), chain);

          tmf.init(ks);

          final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
          kmf.init(ks, "changeit".toCharArray());

          SSLContext sslContext = SSLContext.getInstance("TLS");
          sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

          SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(
              insocket, insocket.getInetAddress().getHostAddress(), insocket.getPort(), false);
          sslSocket.setUseClientMode(false);

          try (
              final InputStream inputStream = sslSocket.getInputStream();
              final OutputStream outputStream = sslSocket.getOutputStream();
              final InputStream clientInputStream = clientSslSocket.getInputStream();
              final OutputStream clientOutputStream = clientSslSocket.getOutputStream();
          ) {

            String line = "";
            BufferedReader in = new BufferedReader(new InputStreamReader(inputStream));
            while((line = in.readLine()) != null) {
              System.out.println(">>> " + line);
              if (line.length() == 0) break;
            }
            clientOutputStream.write("GET / HTTP/1.1\r\n".getBytes());
            clientOutputStream.write("Host: www.google.com\r\n".getBytes());
            clientOutputStream.write("User-Agent: curl/7.81.0\r\n".getBytes());
            clientOutputStream.write("Accept: */*\r\n".getBytes());
            clientOutputStream.write("\r\n".getBytes());

            String realTargetLine;
            while ((realTargetLine = readLine(clientInputStream)) != null) {
                System.out.println(realTargetLine);
              outputStream.write((realTargetLine + "\r\n").getBytes());
            }
            outputStream.write("\r\n".getBytes());

          } catch (Exception e) {
            e.printStackTrace();
          }
          return;
        }

        Thread in2target = new TcpRelayWorker("in2target", insocket, targetSocket);
        in2target.setDaemon(true);
        in2target.start();
        Thread target2in = new TcpRelayWorker("target2in", targetSocket, insocket);
        target2in.setDaemon(true);
        target2in.start();
      }
      logger.info("connection closed or thread interrputed.");
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      if (!switchToHttps) {
        try {
          this.inconn.shutdown();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    }
  }
}

package exercise.proxy1;

import io.netty.handler.ssl.SslContext;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
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
    ks1.load(new FileInputStream("src/main/resources/keystore.jks"), commonPassword);
    System.out.println("KeyStore's size = " + ks1.size());
    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks1, commonPassword);

    final KeyStore emptyTrustStore = KeyStore.getInstance("JKS");
    emptyTrustStore.load(new FileInputStream("C:\\Program Files\\Amazon Corretto\\jdk11.0.11_9\\lib\\security\\cacerts"), "changeit".toCharArray());
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
          targetSocket = new Socket("localhost", 8889);


          SSLSocket clientSslSocket = (SSLSocket) sslSocketFactory.createSocket(
               targetHost, targetPort);
          clientSslSocket.setUseClientMode(true);

          X509Certificate originalCertificate = SslUtil.getServerCertificate(clientSslSocket.getSession());

          logger.info("originalCertificate: " + originalCertificate);

          TrustManagerFactory tmf = TrustManagerFactory
              .getInstance(TrustManagerFactory.getDefaultAlgorithm());
          KeyStore ks = KeyStore.getInstance("JKS");
//          ks.load(new FileInputStream("src/main/resources/keystore.jks"), "changeit".toCharArray()); // You don't need the KeyStore instance to come from a file.
          ks.load(new FileInputStream("src/main/resources/cacerts"), "changeit".toCharArray()); // You don't need the KeyStore instance to come from a file.
//          ks.load("src/main/resources/cacerts", "changeit".toCharArray()); // You don't need the KeyStore instance to come from a file.
          ks.setCertificateEntry("accvraiz1", originalCertificate);

          tmf.init(ks);

          final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
          kmf.init(ks, "changeit".toCharArray());

          SSLContext sslContext = SSLContext.getInstance("TLS");
          sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

          SSLSocket sslSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(
              insocket, insocket.getInetAddress().getHostAddress(), insocket.getPort(), false);
          sslSocket.setUseClientMode(false);

//          for(String s: sslSocket.getEnabledCipherSuites()) {
//            System.out.println(s);
//          }
//          for(String s: sslSocket.getEnabledProtocols()) {
//            System.out.println(s);
//          }
//
          final InputStream inputStream = sslSocket.getInputStream();
          int ch;
          while ((ch = inputStream.read()) != -1) {
            System.out.print((char) ch);
          }
          System.out.println();
//
          final OutputStream outputStream = sslSocket.getOutputStream();
//
          outputStream.write("<html><body>Hello</body></html>".getBytes());
          outputStream.close();

          sslSocket.close();
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

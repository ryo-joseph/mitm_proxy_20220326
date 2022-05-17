package exercise.proxy1;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.impl.DefaultBHttpServerConnection;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.DefaultHttpServerConnection;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestHandlerRegistry;
import org.apache.http.protocol.HttpService;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;

public class TlsRequestListener extends Thread {
  private final ServerSocket serverSocket;
  private final HttpParams params;
//  private final HttpService httpService;
  private HttpService httpService;

  TlsRequestListener(int port, String targetost, int targetPort) throws Exception {
    this.params = new SyncBasicHttpParams();
    this.params
        .setIntParameter(CoreConnectionPNames.SO_TIMEOUT, 5000)
        .setIntParameter(CoreConnectionPNames.SOCKET_BUFFER_SIZE, 8 * 1024)
        .setBooleanParameter(CoreConnectionPNames.STALE_CONNECTION_CHECK, false)
        .setBooleanParameter(CoreConnectionPNames.TCP_NODELAY, true)
        .setParameter(CoreProtocolPNames.ORIGIN_SERVER, "HttpComponents/1.1");

    HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpResponseInterceptor[]{
        new ResponseDate(),
        new ResponseServer(),
        new ResponseContent(),
        new ResponseConnControl()
    });

    final HttpRequestHandlerRegistry registry = new HttpRequestHandlerRegistry();
    registry.register("*", new TlsHandler(targetost, targetPort));

    this.httpService = new HttpService(
        httpproc,
        new DefaultConnectionReuseStrategy(),
        new DefaultHttpResponseFactory(),
        registry,
        this.params
    );

    System.setProperty("javax.net.debug", "all");
    char[] commonPassword = "changeit".toCharArray();
    final KeyStore ks1 = KeyStore.getInstance("JKS");
    ks1.load(new FileInputStream("src/main/resources/keystore.jks"), commonPassword);
    System.out.println("KeyStore's size = " + ks1.size());
    final KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks1, commonPassword);

    final KeyStore emptyTrustStore = KeyStore.getInstance("JKS");
    emptyTrustStore.load(null, "".toCharArray());
    final TrustManagerFactory emptyTMF = TrustManagerFactory.getInstance("PKIX");
    emptyTMF.init(emptyTrustStore);

    final SSLContext sslContext = SSLContext.getInstance("TLSv1");
    sslContext.init(kmf.getKeyManagers(), emptyTMF.getTrustManagers(), null);

    this.serverSocket = sslContext.getServerSocketFactory().createServerSocket(port);
  }

  @Override
  public void run() {
    System.out.println("Listening on port " + this.serverSocket.getLocalPort());
    while (!Thread.interrupted()) {
      try {
        final Socket socket = this.serverSocket.accept();
        final DefaultHttpServerConnection conn =
            new DefaultHttpServerConnection();
        System.out.println("Incoming connection from " + socket.getInetAddress());
        conn.bind(socket, this.params);

        // TODO
        HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpResponseInterceptor[]{
            new ResponseDate(),
            new ResponseServer(),
            new ResponseContent(),
            new ResponseConnControl()
        });

        final HttpRequestHandlerRegistry registry = new HttpRequestHandlerRegistry();
        registry.register("*", new TlsHandler(ProxyWorker.targetHost, ProxyWorker.targetPort));

        this.httpService = new HttpService(
            httpproc,
            new DefaultConnectionReuseStrategy(),
            new DefaultHttpResponseFactory(),
            registry,
            this.params
        );
        // TODO

        Thread t = new TlsWorker(this.httpService, conn);
        t.setDaemon(true);
        t.start();
      } catch (InterruptedIOException ex) {
        break;
      } catch (IOException e) {
        System.err.println("I/O error initialising connection thread: "
            + e.getMessage());
        break;
      }
    }
  }
}

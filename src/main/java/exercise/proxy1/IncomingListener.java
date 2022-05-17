package exercise.proxy1;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import org.apache.http.ConnectionReuseStrategy;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.impl.DefaultBHttpServerConnection;
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
import org.apache.http.protocol.RequestConnControl;
import org.apache.http.protocol.RequestContent;
import org.apache.http.protocol.RequestExpectContinue;
import org.apache.http.protocol.RequestTargetHost;
import org.apache.http.protocol.RequestUserAgent;
import org.apache.http.protocol.ResponseConnControl;

public class IncomingListener extends Thread {
  private final ServerSocket serversocket;
  private final HttpParams params;
  private final HttpService httpService;

  public IncomingListener(int port) throws IOException {
    this.serversocket = new ServerSocket(port);
    this.params = new SyncBasicHttpParams();
    this.params
        .setIntParameter(CoreConnectionPNames.SO_TIMEOUT, 60 * 1000)
        .setIntParameter(CoreConnectionPNames.SOCKET_BUFFER_SIZE, 8 *1024)
        .setBooleanParameter(CoreConnectionPNames.STALE_CONNECTION_CHECK, false)
        .setBooleanParameter(CoreConnectionPNames.TCP_NODELAY, true)
        .setParameter(CoreProtocolPNames.ORIGIN_SERVER, "HttpComponents/1.1");

    final HttpProcessor inhttpproc = new ImmutableHttpProcessor(
        new HttpRequestInterceptor[]{
            new RequestContent(),
            new RequestTargetHost(),
            new RequestConnControl(),
            new RequestUserAgent(),
            new RequestExpectContinue()
        }
    );

    final HttpRequestHandlerRegistry registry = new HttpRequestHandlerRegistry();
    registry.register("*", new ProxyHandler());

    this.httpService = new HttpService(
        inhttpproc,
        new AlwaysConnectionReuseStrategy(),
        new DefaultHttpResponseFactory(),
        registry,
        this.params
    );
  }

  @Override
  public void run() {
    System.out.println("Listening on port " + this.serversocket.getLocalPort());
    while (!Thread.interrupted()) {
      try {
        final Socket insocket = this.serversocket.accept();
        final DefaultHttpServerConnection inconn =
            new DefaultHttpServerConnection();
        System.out.println("Incoming connection from " + insocket.getInetAddress());
        inconn.bind(insocket, this.params);

        Thread t = new ProxyWorker(this.httpService, inconn, insocket);
        t.setDaemon(true);
        t.start();
      } catch (InterruptedIOException ex) {
        ex.printStackTrace();
        break;
      } catch (IOException e) {
        System.err.println("I/O error initialising connection thread: " + e.getMessage());
        break;
      } catch (UnrecoverableKeyException e) {
        e.printStackTrace();
      } catch (CertificateException e) {
        e.printStackTrace();
      } catch (KeyStoreException e) {
        e.printStackTrace();
      } catch (NoSuchAlgorithmException e) {
        e.printStackTrace();
      } catch (KeyManagementException e) {
        e.printStackTrace();
      }
    }
  }
}

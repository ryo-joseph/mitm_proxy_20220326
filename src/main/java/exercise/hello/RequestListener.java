package exercise.hello;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.impl.DefaultConnectionReuseStrategy;
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

public class RequestListener extends Thread {
  private final ServerSocket serverSocket;
  private final HttpParams params;
  private final HttpService httpService;

  public RequestListener(int port) throws IOException {
    this.serverSocket = new ServerSocket(port);
    this.params = new SyncBasicHttpParams();
    this.params
        .setIntParameter(CoreConnectionPNames.SO_TIMEOUT, 60 * 1000)
        .setIntParameter(CoreConnectionPNames.SOCKET_BUFFER_SIZE, 8 * 1024)
        .setBooleanParameter(CoreConnectionPNames.STALE_CONNECTION_CHECK, false)
        .setBooleanParameter(CoreConnectionPNames.TCP_NODELAY, true)
        .setParameter(CoreProtocolPNames.ORIGIN_SERVER, "HttpComponents/1.1");

    HttpProcessor httpproc = new ImmutableHttpProcessor(new HttpResponseInterceptor[] {
       new ResponseDate(),
       new ResponseServer(),
       new ResponseContent(),
        new ResponseConnControl()
    });

    final HttpRequestHandlerRegistry registry = new HttpRequestHandlerRegistry();
    registry.register("*", new HelloHandler());

    this.httpService = new HttpService(
        httpproc,
        new DefaultConnectionReuseStrategy(),
        new DefaultHttpResponseFactory(),
        registry,
        this.params
    );
  }

  @Override
  public void run() {
    System.out.println("Listening on port " + this.serverSocket.getLocalPort());
    while (!Thread.interrupted()) {
      try {
        Socket socket = this.serverSocket.accept();
        final DefaultHttpServerConnection conn =
            new DefaultHttpServerConnection();
        System.out.println("Incoming connection from " + socket.getInetAddress());
        conn.bind(socket, this.params);

        final Thread t = new WorkerThread(this.httpService, conn);
        t.setDaemon(true);
        t.start();
      } catch (InterruptedIOException ex) {
        break;
      } catch (IOException e) {
        System.err.println("I/O error initialising connection thread: " + e.getMessage());
        e.printStackTrace();
        break;
      }
    }
  }
}

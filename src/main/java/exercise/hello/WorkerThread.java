package exercise.hello;

import java.io.IOException;
import org.apache.http.ConnectionClosedException;
import org.apache.http.HttpException;
import org.apache.http.HttpServerConnection;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpService;

public class WorkerThread extends Thread {
  private final HttpService httpservice;
  private final HttpServerConnection conn;

  public WorkerThread(
      final HttpService httpService,
      final HttpServerConnection conn) {
    super();
    this.httpservice = httpService;
    this.conn = conn;
  }

  @Override
  public void run() {
    System.out.println("New connection thread");
    final HttpContext context = new BasicHttpContext(null);
    while (!Thread.interrupted() && this.conn.isOpen()) {
      try {
        this.httpservice.handleRequest(this.conn, context);
      } catch (ConnectionClosedException ex) {
        System.err.println("Client closed connection");
      } catch (IOException ex) {
        System.err.println("I/O error: " + ex.getMessage());
      } catch (HttpException ex) {
        System.err.println("Unrecoverable HTTP protocol violation: " + ex.getMessage());
      } finally {
        try {
          this.conn.shutdown();
        } catch (IOException e) {
          e.printStackTrace();
        }
      }
    }
  }
}

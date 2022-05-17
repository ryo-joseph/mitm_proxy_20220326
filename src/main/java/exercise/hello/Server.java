package exercise.hello;

import java.io.IOException;

public class Server {

  public static void main(String[] args) throws Exception {
    Thread t = new RequestListener(8080);
    t.setDaemon(false);
    t.start();

    Thread tls_t = new TlsRequestListener(8081);
    tls_t.setDaemon(false);
    tls_t.start();
  }
}

package exercise.proxy1;

public class Server {

  public static void main(String[] args) throws Exception {
    Thread t = new IncomingListener(8888);
    t.setDaemon(false);
    t.start();

    Thread t2 = new TlsRequestListener(8889, "localhost", 8081);
    t2.setDaemon(true);
    t2.start();
  }
}

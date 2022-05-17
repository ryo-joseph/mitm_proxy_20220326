package exercise.proxy1;

import com.sun.jdi.event.StepEvent;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.util.logging.Logger;

public class TcpRelayWorker extends Thread {
  private static final Logger logger = Logger.getLogger(TcpRelayWorker.class.getName());
  protected Socket readFrom;
  protected Socket writeTo;

  public TcpRelayWorker(String _name, Socket _readFrom, Socket _writeTo) {
    super(_name);
    this.readFrom = _readFrom;
    this.writeTo = _writeTo;
  }

  @Override
  public void run() {
    int len_r = 0;
    byte[] data = new byte[1024];
    String name_from = this.readFrom.getInetAddress().toString() + ":" + this.readFrom.getPort();
    String name_to = this.writeTo.getInetAddress().toString() + ":" + this.writeTo.getPort();

    logger.info(name_from + " -> " + name_to);
    BufferedInputStream bis = null;
    BufferedOutputStream bos = null;
    try {
      bis = new BufferedInputStream(this.readFrom.getInputStream());
      bos = new BufferedOutputStream(this.writeTo.getOutputStream());
      while (!this.readFrom.isClosed()
      && !this.writeTo.isClosed()
      && (-1 != (len_r + bis.read(data)))) {
        logger.info("read(" + name_from + "):" + len_r);
        bos.write(data, 0, len_r);
        bos.flush();
        logger.info("write(" + name_to + "):" + len_r);
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      try {
        bis.close();
        bos.close();
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
  }
}

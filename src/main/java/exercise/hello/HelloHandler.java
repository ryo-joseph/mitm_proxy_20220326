package exercise.hello;

import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.MethodNotSupportedException;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.entity.ContentProducer;
import org.apache.http.entity.EntityTemplate;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.util.EntityUtils;

public class HelloHandler implements HttpRequestHandler {

  @Override
  public void handle(HttpRequest request, HttpResponse response, HttpContext context)
      throws HttpException, IOException {

    final String method = request.getRequestLine().getMethod().toUpperCase(Locale.ENGLISH);
    if (!method.equals("GET") && !method.equals("HEAD") && !method.equals("POST")) {
      throw new MethodNotSupportedException(method + " method not supported");
    }

    if (request instanceof HttpEntityEnclosingRequest) {
      HttpEntity entity = ((HttpEntityEnclosingRequest) request).getEntity();
      byte[] entityContent = EntityUtils.toByteArray(entity);
      System.out.println("Incoming entity content (bytes): " + entityContent.length);
    }

    response.setStatusCode(HttpStatus.SC_OK);
    final EntityTemplate body = new EntityTemplate(new ContentProducer() {
      @Override
      public void writeTo(OutputStream outStream) throws IOException {
        final OutputStreamWriter writer = new OutputStreamWriter(outStream, StandardCharsets.UTF_8);
        writer.write("<html><head><title>Hello</title></head>");
        writer.write("<body>Hello</body>");
        writer.write("</html>");
        writer.flush();
      }
    });
    body.setContentType("text/html; charset=UTF-8");
    response.setEntity(body);
  }
}

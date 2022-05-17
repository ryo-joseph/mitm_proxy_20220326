package exercise.proxy1;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.util.logging.Logger;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
import org.apache.http.HttpStatus;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.DefaultHttpClientConnection;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.params.CoreConnectionPNames;
import org.apache.http.params.CoreProtocolPNames;
import org.apache.http.params.HttpParams;
import org.apache.http.params.SyncBasicHttpParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.protocol.HttpProcessor;
import org.apache.http.protocol.HttpRequestExecutor;
import org.apache.http.protocol.HttpRequestHandler;
import org.apache.http.protocol.ImmutableHttpProcessor;
import org.apache.http.protocol.ResponseConnControl;
import org.apache.http.protocol.ResponseContent;
import org.apache.http.protocol.ResponseDate;
import org.apache.http.protocol.ResponseServer;
import org.apache.http.util.EntityUtils;

public class ProxyHandler implements HttpRequestHandler {
  private static final Logger logger = Logger.getLogger(ProxyHandler.class.getName());
  private final HttpProcessor httpproc;
  private final HttpRequestExecutor httpexecutor;
  private final HttpParams params;

  public ProxyHandler() {
    this.httpproc = new ImmutableHttpProcessor(
        new HttpResponseInterceptor[]{
            new ResponseDate(),
            new ResponseServer(),
            new ResponseContent(),
            new ResponseConnControl()
        });
    this.httpexecutor = new HttpRequestExecutor();
    this.params = new SyncBasicHttpParams();
    this.params
        .setIntParameter(CoreConnectionPNames.SO_TIMEOUT, 5000)
        .setIntParameter(CoreConnectionPNames.SOCKET_BUFFER_SIZE, 8 * 1024)
        .setBooleanParameter(CoreConnectionPNames.STALE_CONNECTION_CHECK, false)
        .setBooleanParameter(CoreConnectionPNames.TCP_NODELAY, true)
        .setParameter(CoreProtocolPNames.ORIGIN_SERVER, "HttpComponents/1.1");
  }

  @Override
  public void handle(HttpRequest request, HttpResponse response, HttpContext context)
      throws HttpException, IOException {
    
    System.out.println(">> Request URI: " + request.getRequestLine().getUri());
    final String requestMethod = request.getRequestLine().getMethod();
    if("CONNECT".equals(requestMethod)) {
      System.out.println("CONNECT method detected, switing to HTTPS...");
      response.setStatusCode(HttpStatus.SC_OK);
      response.setReasonPhrase("Connection established");
      context.setAttribute("switch_to_https", true);
      final Header[] headers = request.getHeaders("Host");
      final Header hostHeader = headers[0];
      final String hostValue = hostHeader.getValue();
      System.out.println("HTTPS host: " + hostValue);
      int colon = hostValue.indexOf(":");
      if (-1 == colon) {
        context.setAttribute("https.host", hostValue);
        context.setAttribute("https.port", 443);
      } else {
//        context.setAttribute("switch_to_https", hostValue.substring(0, colon));
        context.setAttribute("https.host", hostValue.substring(0, colon));
        int port = 443;
        try {
          final String port_s = hostValue.substring(colon + 1);
          port = Integer.parseInt(port_s);
        } catch (Exception ignore) {
          port = 443;
        }
        context.setAttribute("https.port", port);
      }
      return;
    }

    logger.info("Not connect method.");
    String incommingUrlStr = request.getRequestLine().getUri();
    URL incomingUrl = null;
    try {
      incomingUrl = new URL(incommingUrlStr);
    } catch (MalformedURLException e) {
      e.printStackTrace();
      System.err.println("ignore illegal url : " + incommingUrlStr + "]");
      return;
    }
    final String realHost = incomingUrl.getHost();
    int realPort = incomingUrl.getPort();
    if (-1 == realPort) {
      realPort = 80;
    }
    final String actualRequestPath = incomingUrl.getFile();

    Socket outsocket = new Socket(realHost, realPort);
    DefaultHttpClientConnection outconn = new DefaultHttpClientConnection();
    outconn.bind(outsocket, this.params);
    System.out.println("Outgoing connection to " + outsocket.getInetAddress());

    request.removeHeaders(HTTP.CONTENT_LEN);
    request.removeHeaders(HTTP.TRANSFER_ENCODING);
    request.removeHeaders(HTTP.CONN_DIRECTIVE);
    request.removeHeaders("Keep-Alive");
    request.removeHeaders("Proxy-Authenticate");
    request.removeHeaders("TE");
    request.removeHeaders("Trailers");
    request.removeHeaders("Upgrade");

    HttpRequest targetRequest = new BasicHttpRequest(
        request.getRequestLine().getMethod(),
        actualRequestPath,
        request.getRequestLine().getProtocolVersion()
    );
    targetRequest.setHeaders(request.getAllHeaders());

    HttpResponse targetResponse = this.httpexecutor.execute(targetRequest, outconn, context);

    HttpEntity entity = targetResponse.getEntity();
    System.out.println(EntityUtils.getContentMimeType(entity));
    byte[] responseBody = EntityUtils.toByteArray(entity);
    EntityUtils.consume(entity);

    this.httpexecutor.postProcess(response, this.httpproc, context);

    targetResponse.removeHeaders(HTTP.CONTENT_LEN);
    targetResponse.removeHeaders(HTTP.TRANSFER_ENCODING);
    targetResponse.removeHeaders(HTTP.CONN_DIRECTIVE);
    targetResponse.removeHeaders("Keep-Alive");
    targetResponse.removeHeaders("TE");
    targetResponse.removeHeaders("Trailers");
    targetResponse.removeHeaders("Upgrade");

    response.setStatusLine(targetResponse.getStatusLine());
    response.setHeaders(targetResponse.getAllHeaders());
    response.setEntity(new ByteArrayEntity(responseBody));

    System.out.println("<< Response: " + response.getStatusLine());
    try {
      outsocket.close();
    } catch (Exception e) {}
  }
}

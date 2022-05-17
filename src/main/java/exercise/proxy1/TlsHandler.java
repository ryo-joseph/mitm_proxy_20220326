package exercise.proxy1;

import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.HttpResponseInterceptor;
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

public class TlsHandler implements HttpRequestHandler {

  private final HttpProcessor httpproc;
  private final HttpRequestExecutor httpexecutor;
  private final HttpParams params;

  protected final String targetHost;
  protected final int targetPort;

  protected SSLContext sslContext;
  protected SSLSocketFactory sslSocketFactory;

  public TlsHandler(String _targetHost, int _targetPort) {
    this.httpproc = new ImmutableHttpProcessor(
        new HttpResponseInterceptor[] {
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

//    this.targetHost = _targetHost;
    this.targetHost = _targetHost;
//    this.targetPort = _targetPort;
    this.targetPort = _targetPort;
    try {
      this.sslContext = SSLContext.getInstance("TLSv1");
      TrustManager tm = new X509TrustManager() {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {

        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
          return null;
        }
      };
      this.sslContext.init(null, new TrustManager[] { tm }, null);
      this.sslSocketFactory = sslContext.getSocketFactory();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  @Override
  public void handle(HttpRequest request, HttpResponse response, HttpContext context)
      throws HttpException, IOException {

    System.out.println(">> Request URI: " + request.getRequestLine().getUri());

    Socket outsocket = this.sslSocketFactory.createSocket(this.targetHost, this.targetPort);
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
        request.getRequestLine().getUri(),
        request.getRequestLine().getProtocolVersion());
    targetRequest.setHeaders(request.getAllHeaders());

    HttpResponse targetResponse = this.httpexecutor.execute(targetRequest, outconn, context);

    final HttpEntity entity = targetResponse.getEntity();
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

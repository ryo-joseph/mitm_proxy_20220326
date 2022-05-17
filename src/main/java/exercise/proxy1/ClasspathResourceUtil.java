package exercise.proxy1;

import com.google.common.io.CharStreams;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.nio.charset.Charset;

public class ClasspathResourceUtil {

  public static String classpathResourceToString(String resource, Charset charset) throws
      UncheckedIOException {
    if (resource == null) {
      throw new IllegalArgumentException("Classpath resource to load cannot be null");
    }

    if (charset == null) {
      throw new IllegalArgumentException("Character set cannot be null");
    }

    try(final InputStream resourceAsStream = ClasspathResourceUtil.class.getResourceAsStream(resource);) {
      if (resourceAsStream == null) {
        throw new UncheckedIOException(new FileNotFoundException(
            "Unable to locate classpath resource: " + resource));
      }

      Reader resourceReader = new InputStreamReader(resourceAsStream, charset);
      return CharStreams.toString(resourceReader);
    } catch (IOException e) {
      throw new UncheckedIOException("Error occured while reading classpath resource", e);
    }
  }
}

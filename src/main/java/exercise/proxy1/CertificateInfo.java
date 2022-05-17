package exercise.proxy1;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class CertificateInfo {
  private String commonName;
  private String organization;
  private String organizationUnit;

  private String email;
  private String locality;
  private String state;
  private String countryCode;

  private Date notBefore;
  private Date notAfter;

//  private List<String> subjectAlternativeNames = Collections.emptyList();
  private List<String> subjectAlternativeNames;
}

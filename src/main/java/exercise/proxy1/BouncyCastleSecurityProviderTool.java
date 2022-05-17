package exercise.proxy1;

import com.google.common.net.InetAddresses;
import java.io.Reader;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class BouncyCastleSecurityProviderTool implements SecurityProviderTool {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private static final int CERTIFICATE_SPECIAL_NUMBER_SIZE = 160;

  @Override
  public CertificateAndKey createCARootCertificate(CertificateInfo certificateInfo, KeyPair keyPair,
                                                   String messageDigest) {

    if (certificateInfo.getNotBefore() == null) {
      throw new IllegalArgumentException("Must specify Not Before for server certificate");
    }

    if (certificateInfo.getNotAfter() == null) {
      throw new IllegalArgumentException("Must specify Not After for server certificate");
    }

    X500Name issuer = createX500NameForCertificate(certificateInfo);

    BigInteger serial = EncriptionUtil.getRandomBigInteger(CERTIFICATE_SPECIAL_NUMBER_SIZE);

    PublicKey rootCertificatePublicKey = keyPair.getPublic();

    String signatureAlgorithm = EncriptionUtil.getSignatureAlgorithm(messageDigest, keyPair.getPrivate());

    ContentSigner selfSigner = getCertificateSigner(keyPair.getPrivate(), signatureAlgorithm);

    ASN1EncodableVector extendedKeyUsages = new ASN1EncodableVector();
    extendedKeyUsages.add(KeyPurposeId.id_kp_serverAuth);
    extendedKeyUsages.add(KeyPurposeId.id_kp_clientAuth);
    extendedKeyUsages.add(KeyPurposeId.anyExtendedKeyUsage);

    X509CertificateHolder certificateHolder;

    try {
      certificateHolder = new JcaX509v3CertificateBuilder(
          issuer,
          serial,
          certificateInfo.getNotBefore(),
          certificateInfo.getNotAfter(),
          issuer,
          rootCertificatePublicKey)
          .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(rootCertificatePublicKey))
          .addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
          .addExtension(Extension.keyUsage, false, new KeyUsage(
              KeyUsage.keyCertSign
              | KeyUsage.digitalSignature
              | KeyUsage.keyEncipherment
              | KeyUsage.dataEncipherment
              | KeyUsage.cRLSign))
          .addExtension(Extension.extendedKeyUsage, false, new DERSequence(extendedKeyUsages))
          .build(selfSigner);
    } catch (CertIOException e) {
      throw new CertificateCreationException();
    }

    final X509Certificate cert = convertToJcaCertificate(certificateHolder);

    return new  CertificateAndKey(cert, keyPair.getPrivate());
  }

  private static X509Certificate convertToJcaCertificate(X509CertificateHolder bouncyCastleCertificate) {
    try {
      return new JcaX509CertificateConverter().getCertificate(bouncyCastleCertificate);
    } catch (CertificateException e) {
      throw new CertificateCreationException();
    }
  }

  private static SubjectKeyIdentifier createSubjectKeyIdentifier(Key key) {
    SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.getInstance(key.getEncoded());

    return new BcX509ExtensionUtils().createSubjectKeyIdentifier(publicKeyInfo);
  }

  private static ContentSigner getCertificateSigner(PrivateKey certAuthorityPrivateKey, String signatureAlgorithm) {
    try {
      return new JcaContentSignerBuilder(signatureAlgorithm)
          .build(certAuthorityPrivateKey);
    } catch (OperatorCreationException e) {
      throw new CertificateCreationException();
    }
  }

  @Override
  public CertificateAndKey createServerCertificate(CertificateInfo certificateInfo,
                                                   X509Certificate caRootCertificate,
                                                   PrivateKey caPrivateKey, KeyPair serverKeyPair,
                                                   String messageDigest) {
    // TODO
    if (certificateInfo.getCommonName() == null) {
      throw new IllegalArgumentException();
    }

    if (certificateInfo.getNotBefore() == null) {
      throw new IllegalArgumentException();
    }

    if (certificateInfo.getNotAfter() == null) {
      throw new IllegalArgumentException();
    }

    final X500Name serverCertificateSubject = createX500NameForCertificate(certificateInfo);

    final String signatureAlgorithm =
        EncriptionUtil.getSignatureAlgorithm(messageDigest, caPrivateKey);

    final ContentSigner signer = getCertificateSigner(caPrivateKey, signatureAlgorithm);

    final BigInteger serialNumber =
        EncriptionUtil.getRandomBigInteger(CERTIFICATE_SPECIAL_NUMBER_SIZE);

    X509CertificateHolder certificateHolder;
    try {
      certificateHolder = new JcaX509v3CertificateBuilder(caRootCertificate,
          serialNumber,
          certificateInfo.getNotBefore(),
          certificateInfo.getNotAfter(),
          serverCertificateSubject,
          serverKeyPair.getPublic())
          .addExtension(Extension.subjectAlternativeName, false, getDomainNameSANsAsSN1Encodable(certificateInfo.getSubjectAlternativeNames()))
          .addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(serverKeyPair.getPublic()))
          .addExtension(Extension.basicConstraints, false, new BasicConstraints(false))
          .build(signer);
    } catch (CertIOException e) {
      throw new CertificateCreationException();
    }

    X509Certificate serverCertificate = convertToJcaCertificate(certificateHolder);

    return new CertificateAndKey(serverCertificate, serverKeyPair.getPrivate());
  }

  private static GeneralNames getDomainNameSANsAsSN1Encodable(List<String> subjectAlternativeNames) {
    List<GeneralName> encodedSANs = new ArrayList<>(subjectAlternativeNames.size());
    for (String subjectAlternativeName : subjectAlternativeNames) {
      final boolean isIpAddress = InetAddresses.isInetAddress(subjectAlternativeName);
      GeneralName generalName = new GeneralName(isIpAddress ? GeneralName.iPAddress : GeneralName.dNSName, subjectAlternativeName);
      encodedSANs.add(generalName);
    }

    return new GeneralNames(encodedSANs.toArray(new GeneralName[encodedSANs.size()]));
  }

  @Override
  public X509Certificate decodePemEncodedCertificate(Reader certificateReader) {
    return null;
  }

  private static X500Name createX500NameForCertificate(CertificateInfo certificateInfo) {
    final X500NameBuilder x500NameBuilder = new X500NameBuilder(BCStyle.INSTANCE);

    if (certificateInfo.getCommonName() != null) {
      x500NameBuilder.addRDN(BCStyle.CN, certificateInfo.getCommonName());
    }

    if (certificateInfo.getOrganization() != null) {
      x500NameBuilder.addRDN(BCStyle.O, certificateInfo.getOrganization());
    }

    if (certificateInfo.getOrganizationUnit() != null) {
      x500NameBuilder.addRDN(BCStyle.OU, certificateInfo.getOrganizationUnit());
    }

    if (certificateInfo.getEmail() != null) {
      x500NameBuilder.addRDN(BCStyle.E, certificateInfo.getEmail());
    }

    if (certificateInfo.getLocality() != null) {
      x500NameBuilder.addRDN(BCStyle.L, certificateInfo.getLocality());
    }

    if (certificateInfo.getState() != null) {
      x500NameBuilder.addRDN(BCStyle.ST, certificateInfo.getState());
    }

    if (certificateInfo.getCountryCode() != null) {
      x500NameBuilder.addRDN(BCStyle.C, certificateInfo.getCountryCode());
    }

    return x500NameBuilder.build();
  }
}

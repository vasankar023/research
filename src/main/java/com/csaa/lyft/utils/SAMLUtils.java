package com.csaa.lyft.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.Key;
import java.security.PublicKey;
import java.util.List;
import java.util.Properties;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLException;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml1.core.AttributeValue;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMarshaller;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.csaa.lyft.domain.IDPMetaData;
import com.csaa.lyft.domain.SPMetaData;
import com.csaa.lyft.domain.UserData;

public class SAMLUtils {
	
	private static IDPMetaData idpMetaData = null;
	private static SPMetaData spMetaData = null;
	private static SecureRandomIdentifierGenerator generator;
	private static Logger log = Logger.getLogger(SAMLUtils.class);

	static {
		try {
			DefaultBootstrap.bootstrap();
			generator = new SecureRandomIdentifierGenerator();
		} catch (Exception e) {
			log.error("Exception in static block of SAMLUtils", e);
		}
	}

	public static void readIDPMetaData(InputStream is) {
		try {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
			Document document = docBuilder.parse(is);
			Element element = document.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
			EntityDescriptor ed = (EntityDescriptor) unmarshaller.unmarshall(element);
			IDPSSODescriptor idpssoDesc = ed.getIDPSSODescriptor(SAMLConstants.SAML20P_NS);
			Signature signature = ed.getSignature();

			X509Certificate certificate = idpssoDesc.getKeyDescriptors().get(0).getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0);
			String certValue = certificate.getValue();

			byte[] z = Base64.decodeBase64(certValue);
			javax.security.cert.X509Certificate cert = javax.security.cert.X509Certificate.getInstance(z);
			PublicKey publicKey = cert.getPublicKey();

			BasicCredential credential = new BasicCredential();
			credential.setPublicKey(publicKey);
			SignatureValidator validator = new SignatureValidator(credential);
			validator.validate(signature);
			
			/*BigInteger modulus = new BigInteger(Base64.decodeBase64(element.getElementsByTagName("ds:Modulus").item(0).getTextContent()));
			BigInteger exponent = new BigInteger(Base64.decodeBase64(element.getElementsByTagName("ds:Exponent").item(0).getTextContent()));
			credential.setPrivateKey(KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, exponent)));
			signature.setSigningCredential(credential);
			System.out.println(modulus);*/
			/*KeyInfo keyInfo = idpssoDesc.getKeyDescriptors().get(0).getKeyInfo();
			keyInfo.setParent(null);
			signature.setKeyInfo(keyInfo);*/
			
			idpMetaData = new IDPMetaData();

			idpMetaData.setEntityID(ed.getEntityID());
			idpMetaData.setPublicKey(publicKey);
			idpMetaData.setSigned(idpssoDesc.isSigned());
			idpMetaData.setWantAuthRequestSigned(idpssoDesc.getWantAuthnRequestsSigned());
			idpMetaData.setSsoServiceUrl(idpssoDesc.getSingleSignOnServices().get(0).getLocation());
			//idpMetaData.setLogOutServiceUrl(idpssoDesc.getSingleLogoutServices().get(0).getLocation());
		} catch (Exception e) {
			log.error("Exception in readIDPMetaData method of SAMLUtils", e);
		}
	}

	public static void readSPMetaData(InputStream is) throws IOException {
		Properties properties = new Properties();
		properties.load(is);

		spMetaData = new SPMetaData();
		spMetaData.setAcsURL(properties.getProperty("serviceprovider.acs.url"));
		spMetaData.setIssueURL(properties.getProperty("serviceprovider.issuer.url"));
		spMetaData.setProviderName(properties.getProperty("serviceprovider.providername"));
		spMetaData.setRelayState(properties.getProperty("serviceprovider.relaystate"));
		spMetaData.setEntityID(properties.getProperty("serviceprovider.entityid"));
	}

	public static String getSAMLRequest(HttpServletRequest request) {
		String requestStr = null;
		String encodedRequestMessage = null;
		String redirectionUrl = idpMetaData.getSsoServiceUrl();

		AuthnRequest authnRequest = null;
		try {
			authnRequest = prepareSAMLAuthNReqObject();
			encodedRequestMessage = encodeAuthnRequest(authnRequest);
		} catch (MarshallingException e) {
			log.error("Exception in getSAMLRequest method of SAMLUtils", e);
		} catch (Exception e) {
			log.error("Exception in getSAMLRequest method of SAMLUtils", e);
		}
		requestStr = (new StringBuilder(redirectionUrl))//.append("?redirectUrl=").append(redirectionUrl)
				.append("?SAMLRequest=").append(encodedRequestMessage).append(
						"&RelayState=").append(spMetaData.getRelayState())
				.toString();
		HttpSession session = request.getSession();
		session.setAttribute("authnRequest", authnRequest);

		return requestStr;
	}
	
	public static String getLogOutRequest(String email, String sessionIndex) {
		String requestStr = null;
		String encodedRequestMessage = null;
		String logOutServiceURL = idpMetaData.getLogOutServiceUrl();
		String redirectionUrl = logOutServiceURL+"?SAMLRequest=";
		
		LogoutRequest logOutRequest = prepareLogOutRequestObject(email , sessionIndex);
		try {
			encodedRequestMessage = encodeLogOutRequest(logOutRequest);
		} catch (MarshallingException e) {
			log.error("Exception in getLogOutRequest method of SAMLUtils", e);
		} catch (IOException e) {
			log.error("Exception in getLogOutRequest method of SAMLUtils", e);
		}
		requestStr = (new StringBuilder(redirectionUrl)).
				append(encodedRequestMessage).toString();
		
		return requestStr;
	}
	
	
	
	private static LogoutRequest prepareLogOutRequestObject(String email, String sessionIndex) {
		String issuerNamespaceURI = "urn:oasis:names:tc:SAML:2.0:assertion";
		String sessIndexNameSpaceURI = "urn:oasis:names:tc:SAML:2.0:protocol";
		String nameIDNameSpaceURI = "urn:oasis:names:tc:SAML:2.0:assertion";
		
		LogoutRequestBuilder logOutReqBuilder = new LogoutRequestBuilder();
				
		DateTime issueInstant = new DateTime();
		LogoutRequest logOutRequest = logOutReqBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",LogoutRequest.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject(issuerNamespaceURI, Issuer.DEFAULT_ELEMENT_LOCAL_NAME,"saml");
		issuer.setValue(spMetaData.getIssueURL());
		
		SessionIndexBuilder sessIndexBuilder = new SessionIndexBuilder();
		SessionIndex sessIndex = sessIndexBuilder.buildObject(sessIndexNameSpaceURI, SessionIndex.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		sessIndex.setSessionIndex(sessionIndex);
		
		NameIDBuilder nameIDBuilder = new NameIDBuilder();
		NameID nameID = nameIDBuilder.buildObject(nameIDNameSpaceURI, NameID.DEFAULT_ELEMENT_LOCAL_NAME, "saml");
		nameID.setNameQualifier(idpMetaData.getEntityID());
		nameID.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
		nameID.setSPNameQualifier(spMetaData.getEntityID());
		nameID.setValue(email);
		
		logOutRequest.setID(generator.generateIdentifier());
		logOutRequest.setVersion(SAMLVersion.VERSION_20);
		logOutRequest.setIssueInstant(issueInstant);
		logOutRequest.setIssuer(issuer);
		logOutRequest.setNameID(nameID);
		logOutRequest.getSessionIndexes().add(sessIndex);
		
		return logOutRequest;
	}
	
	private static AuthnRequest prepareSAMLAuthNReqObject() throws Exception {
		String issuerNamespaceURI = "urn:oasis:names:tc:SAML:2.0:assertion";
		String authContextNameSpaceURI = "urn:oasis:names:tc:SAML:2.0:assertion";
		String authContextClassRefURI = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
		String nameIDPolicyFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject(issuerNamespaceURI, "Issuer", "samlp");
		issuer.setValue(spMetaData.getEntityID());

		NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
		NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
		nameIdPolicy.setFormat(nameIDPolicyFormat);
		nameIdPolicy.setSPNameQualifier("LRT");
		nameIdPolicy.setAllowCreate(new Boolean(false));
		nameIdPolicy.setAllowCreate(new Boolean(true));

		AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
		AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject(authContextNameSpaceURI, "AuthnContextClassRef", "saml");
		authnContextClassRef.setAuthnContextClassRef(authContextClassRefURI);
		RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
		RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
		requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
		DateTime issueInstant = new DateTime();
		AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
		AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol","AuthnRequest", "samlp");
		authRequest.setForceAuthn(new Boolean(false));
		authRequest.setIsPassive(new Boolean(false));
		authRequest.setIssueInstant(issueInstant);
		authRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
		authRequest.setAssertionConsumerServiceURL(spMetaData.getAcsURL());
		authRequest.setIssuer(issuer);
		
		/*
		//Custom code to Sign a certificate
		Signature signature = (Signature) Configuration.getBuilderFactory().getBuilder(Signature.DEFAULT_ELEMENT_NAME).buildObject(Signature.DEFAULT_ELEMENT_NAME);
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		
		File certFile = new File(System.getProperty("catalina.home")+"/conf/sso/certificates/ecs_rsa_key.cer");
		File pubKeyFile = new File(System.getProperty("catalina.home")+"/conf/sso/certificates/ecs_rsa_public.key");
		File privKeyFile = new File(System.getProperty("catalina.home")+"/conf/sso/certificates/ecs_rsa_private.key");

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		
        DataInputStream dis = new DataInputStream(new FileInputStream(pubKeyFile));
        byte[] pubKeyBytes = new byte[(int)pubKeyFile.length()];
        dis.readFully(pubKeyBytes);
        dis.close();
        
     // decode public key
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubKeyBytes);
        RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(pubSpec);
        
        dis = new DataInputStream(new FileInputStream(privKeyFile));
        byte[] privKeyBytes = new byte[(int)privKeyFile.length()];
        dis.read(privKeyBytes);
        dis.close();
        
        // decode private key
        PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);
		            
        BasicCredential credential = new BasicCredential();
        credential.setPublicKey(pubKey);
        credential.setPrivateKey(privKey);
        signature.setSigningCredential(credential);
        
		KeyInfo keyInfo = (KeyInfo) Configuration.getBuilderFactory().getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME).buildObject(KeyInfo.DEFAULT_ELEMENT_NAME);

        KeyInfoHelper.addPublicKey(keyInfo, pubKey);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
		Document document = docBuilder.parse(new FileInputStream(certFile));
		Element element = document.getDocumentElement();
        
        java.security.cert.X509Certificate cert = (java.security.cert.X509Certificate)cf.generateCertificate(new FileInputStream(certFile));	
        log.debug("---Certificate---");
        log.debug("type = " + cert.getType());
        log.debug("version = " + cert.getVersion());
        log.debug("subject = " + cert.getSubjectDN().getName());
        log.debug("valid from = " + cert.getNotBefore());
        log.debug("valid to = " + cert.getNotAfter());
        log.debug("serial number = " + cert.getSerialNumber().toString(16));
        log.debug("issuer = " + cert.getIssuerDN().getName());
        log.debug("signing algorithm = " + cert.getSigAlgName());
        log.debug("public key algorithm = " + cert.getPublicKey().getAlgorithm());
        dis.close();
        
        KeyInfoHelper.addCertificate(keyInfo, cert);
		signature.setKeyInfo(keyInfo);
		            
		authRequest.setSignature(signature);*/
		//authRequest.setNameIDPolicy(nameIdPolicy);
		authRequest.setRequestedAuthnContext(requestedAuthnContext);
		authRequest.setID(generator.generateIdentifier());
		authRequest.setProviderName(spMetaData.getProviderName());
		authRequest.setVersion(SAMLVersion.VERSION_20);
		return authRequest;
	}
	
	public static String getLogOutResponse(String sessionIndex) {
		String requestStr = null;
		String encodedRequestMessage = null;
		String logOutServiceURL = idpMetaData.getLogOutServiceUrl();
		String redirectionUrl = logOutServiceURL+"?SAMLResponse=";
		LogoutResponse logOutResponse = prepareLogOutResponseObject(sessionIndex);
		try {
			encodedRequestMessage = encodeLogOutResponse(logOutResponse);
		} catch (MarshallingException e) {
			log.error("Exception in getLogOutResponse method of SAMLUtils", e);
		} catch (IOException e) {
			log.error("Exception in getLogOutResponse method of SAMLUtils", e);
		}
		requestStr = (new StringBuilder(redirectionUrl))
				.append(encodedRequestMessage).toString();
		
		return requestStr;
	}
	
	private static LogoutResponse prepareLogOutResponseObject(String sessionIndex) {
		String issuerNamespaceURI = "urn:oasis:names:tc:SAML:2.0:assertion";
		
		LogoutResponseBuilder logOutRespBuilder = new LogoutResponseBuilder();
		DateTime issueInstant = new DateTime();
		LogoutResponse logOutResponse = logOutRespBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol", LogoutResponse.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		
		IssuerBuilder issuerBuilder = new IssuerBuilder();
		Issuer issuer = issuerBuilder.buildObject(issuerNamespaceURI, Issuer.DEFAULT_ELEMENT_LOCAL_NAME,"saml");
		issuer.setValue(spMetaData.getEntityID());
		
		StatusBuilder statusBuilder = new StatusBuilder();
		Status status = statusBuilder.buildObject(issuerNamespaceURI, Status.DEFAULT_ELEMENT_LOCAL_NAME, "samlp");
		
		StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
		StatusCode statusCode = statusCodeBuilder.buildObject(issuerNamespaceURI, Issuer.DEFAULT_ELEMENT_LOCAL_NAME,"saml");
		statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Succes");
		status.setStatusCode(statusCode);
		logOutResponse.setID(generator.generateIdentifier());
		logOutResponse.setVersion(SAMLVersion.VERSION_20);
		logOutResponse.setIssueInstant(issueInstant);
		logOutResponse.setIssuer(issuer);
		logOutResponse.setInResponseTo(sessionIndex);
		
		return logOutResponse;
	}
	private static String encodeAuthnRequest(AuthnRequest authnRequest)
			throws MarshallingException, IOException, SignatureException {
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(authnRequest);
		Element authDOM = null;
		authDOM = marshaller.marshall(authnRequest);
		//Signer.signObject(authnRequest.getSignature());
		
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		String requestMessage = rspWrt.toString();
		//log.debug(requestMessage);
		Deflater deflater = new Deflater(8, true);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
		deflaterOutputStream.write(requestMessage.getBytes());
		deflaterOutputStream.close();
		String encodedRequestMessage = org.opensaml.xml.util.Base64.encodeBytes(byteArrayOutputStream.toByteArray(), 8);
		encodedRequestMessage = URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();

		return encodedRequestMessage;
	}
	
	private static String encodeLogOutRequest(LogoutRequest logoutRequest)
			throws MarshallingException, IOException {
		Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(logoutRequest);
		Element authDOM = null;
		authDOM = marshaller.marshall(logoutRequest);
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		String requestMessage = rspWrt.toString();
		
		Deflater deflater = new Deflater(8, true);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
		deflaterOutputStream.write(requestMessage.getBytes());
		deflaterOutputStream.close();
		String encodedRequestMessage = org.opensaml.xml.util.Base64.encodeBytes(byteArrayOutputStream.toByteArray(), 8);
		encodedRequestMessage = URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();
		return encodedRequestMessage;
	}
	
	private static String encodeLogOutResponse(LogoutResponse logoutResponse)
			throws MarshallingException, IOException {
		StatusMarshaller statusMarshaller = new StatusMarshaller();
		Element authDOM = statusMarshaller.marshall(logoutResponse);
		StringWriter rspWrt = new StringWriter();
		XMLHelper.writeNode(authDOM, rspWrt);
		String responseMessage = rspWrt.toString();
		Deflater deflater = new Deflater(8, true);
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
		deflaterOutputStream.write(responseMessage.getBytes());
		deflaterOutputStream.close();
		String encodedResponseMessage = org.opensaml.xml.util.Base64.encodeBytes(byteArrayOutputStream.toByteArray(), 8);
		encodedResponseMessage = URLEncoder.encode(encodedResponseMessage, "UTF-8").trim();
		
		return encodedResponseMessage;
	}	

	public static UserData isValidSAMLResponse(HttpServletRequest request) {
		UserData userData = null;

		try {
			String samlResponse = request.getParameter("SAMLResponse");
			System.out.println("SAMLResponse:"+samlResponse);
			String respStr = new String(Base64.decodeBase64(samlResponse));
			Response response = (Response) unmarshall(respStr);
			HttpSession session = request.getSession();

			List<Assertion> assertions = response.getAssertions();
			Assertion assertion = response.getAssertions().get(0);
			Conditions conditions = assertion.getConditions();
			Subject subject = assertion.getSubject();
			verifyAssertionConditions(conditions);
			verifySubject(subject, (AuthnRequest) session.getAttribute("authnRequest"));
			DateTime issueInstant = assertion.getIssueInstant();
			DateTime notBeforeTime = conditions.getNotBefore();
			DateTime notOnOrAfter = conditions.getNotOnOrAfter();
			DateTime dateTime = new DateTime();

			Signature signature = assertion.getSignature();

			/*String cert = signature.getKeyInfo().getX509Datas().get(0).getX509Certificates().get(0).getValue();
			byte[] certData = Base64.decodeBase64(cert);
			javax.security.cert.X509Certificate certificate = javax.security.cert.X509Certificate.getInstance(certData);

			PublicKey pubKey = certificate.getPublicKey();*/

			BasicCredential credential = new BasicCredential();
			credential.setPublicKey(idpMetaData.getPublicKey());

			SignatureValidator validator = new SignatureValidator(credential);
			Key validationKey = SecurityHelper.extractVerificationKey(credential);

			validator.validate(signature);
			String sessionIndex = assertion.getAuthnStatements().get(0).getSessionIndex();
			// Added to get user id from SAML response
			AttributeStatement attributeStatement =assertion.getAttributeStatements().get(0);
		    List<Attribute> attributes =attributeStatement.getAttributes();
		    for (Attribute attribute : attributes) {
		      if (!"sAMAccountName".equals(attribute.getName())) {continue;}
		      for (XMLObject attributeValue : attribute.getAttributeValues()) {
		    	  Element attributeValueElement=attributeValue.getDOM();
		    	  String username=attributeValueElement.getTextContent();
		    	  userData = new UserData(username, null);
		      }
			}
			userData.setSessionIndex(sessionIndex);
			
		} catch (Exception e) {
			log.error("Exception in isValidSAMLResponse method of SAMLUtils", e);
		}

		return userData;
	}

	private static XMLObject unmarshall(String responseMessage) {
		XMLObject xmlObj = null;
		try {
			DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
			documentBuilderFactory.setNamespaceAware(true);
			DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
			Document document = docBuilder.parse(new ByteArrayInputStream(responseMessage.trim().getBytes()));
			Element element = document.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
			xmlObj = unmarshaller.unmarshall(element);

		} catch (Exception e) {
			log.error("Exception in unmarshall method of SAMLUtils", e);
		}

		return xmlObj;
	}

	private static void verifyAssertionConditions(Conditions conditions)
			throws SAMLException {
		if (conditions.getNotBefore().isAfterNow() && conditions.getNotOnOrAfter().isBeforeNow()) {
			throw new SAMLException("SAML response is not valid");
		}
	}

	private static void verifySubject(Subject subject, AuthnRequest request)
			throws SAMLException {

		String BEARER_CONFIRMATION = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

		for (SubjectConfirmation confirmation : subject
				.getSubjectConfirmations()) {
			if (BEARER_CONFIRMATION.equals(confirmation.getMethod())) {
				SubjectConfirmationData data = confirmation.getSubjectConfirmationData();

				// Bearer must have confirmation 554
				if (data == null) {
					System.err.println("Assertion invalidated by missing confirmation data");
					throw new SAMLException("SAML Assertion is invalid");
				}

				// Validate not on or after
				if (data.getNotOnOrAfter().isBeforeNow()) {
					throw new SAMLException("SAML Assertion is invalid");
				}

				// Validate in response to
				if (request != null) {
					if (data.getInResponseTo() == null) {
						System.err.println("Assertion invalidated by subject confirmation - missing inResponseTo field");
						throw new SAMLException("SAML Assertion is invalid");
					} else {
						if (!data.getInResponseTo().equals(request.getID())) {
							System.err.println("Assertion invalidated by subject confirmation - invalid in response to");
							throw new SAMLException("SAML Assertion is invalid");
						}
					}
				}

				// Validate recipient
				if (data.getRecipient() == null) {
					System.err.println("Assertion invalidated by subject confirmation - recipient is missing in bearer confirmation");
					throw new SAMLException("SAML Assertion is invalid");
				}
			}

		}

	}

	public static IDPMetaData getIDPMetaData() {
		return idpMetaData;
	}

	public static SPMetaData getSPMetaData() {
		return spMetaData;
	}
	
	public static String decode(String message){
		//String message = URLDecoder.decode(ss);
		byte[] input = null;
		try {
			input = org.opensaml.xml.util.Base64.decode(removeNewLineChars(message));
		} catch (Exception e) {
			log.error("Exception in decode method of SAMLUtils", e);
		}
        // Decompress the bytes
        Inflater inflater = new Inflater(true);
        inflater.setInput(input);
        byte[] result = new byte[2048]; // Note that this is fixed length
        // buffer, could be a problem
        int resultLength = 0;
        try {
            resultLength = inflater.inflate(result);
        } catch (DataFormatException dfe) {
        	log.error("Exception in decode method of SAMLUtils", dfe);
        }
        inflater.end();
        
        // Decode the bytes into a String
        String outputString = null;
        try {
            outputString = new
                    String(result, 0, resultLength, "UTF-8");
        } catch (UnsupportedEncodingException uee) {
        	log.error("Exception in decode method of SAMLUtils", uee);
        }
        
        return outputString;
	}
	
	public static String removeNewLineChars(String s) {
        String retString = null;
        if ((s != null) && (s.length() > 0) && (s.indexOf('\n') != -1)) {
            char[] chars = s.toCharArray();
            int len = chars.length;
            StringBuffer sb = new StringBuffer(len);
            for (int i = 0; i < len; i++) {
                char c = chars[i];
                if (c != '\n') {
                    sb.append(c);
                }
            }
            retString = sb.toString();
        } else {
            retString = s;
        }
        return retString;
    }
	
	public static LogoutResponse extractLogOutResponse(String logOutResponse){
		String logOutResp = SAMLUtils.decode(logOutResponse);
		LogoutResponse response = (LogoutResponse) unmarshall(logOutResp);
		return response;
		
	}
}

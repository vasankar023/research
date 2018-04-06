package com.csaa.lyft.domain;

import java.io.Serializable;
import java.security.PublicKey;

import org.opensaml.xml.signature.Signature;

public class IDPMetaData implements Serializable {
	private static final long serialVersionUID = 694237471707017422L;
	
	private String entityID;
	private String ssoServiceUrl;
	private boolean signed;
	private boolean wantAuthRequestSigned;
	private PublicKey publicKey;
	private String logOutServiceUrl;
	
	public String getEntityID() {
		return entityID;
	}
	
	public void setEntityID(String entityID) {
		this.entityID = entityID;
	}
	
	public String getSsoServiceUrl() {
		return ssoServiceUrl;
	}
	
	public void setSsoServiceUrl(String ssoServiceUrl) {
		this.ssoServiceUrl = ssoServiceUrl;
	}
	
	public boolean isSigned() {
		return signed;
	}
	
	public void setSigned(boolean signed) {
		this.signed = signed;
	}
	
	public boolean isWantAuthRequestSigned() {
		return wantAuthRequestSigned;
	}
	
	public void setWantAuthRequestSigned(boolean wantAuthRequestSigned) {
		this.wantAuthRequestSigned = wantAuthRequestSigned;
	}
	
	public PublicKey getPublicKey() {
		return publicKey;
	}
	
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public String getLogOutServiceUrl() {
		return logOutServiceUrl;
	}

	public void setLogOutServiceUrl(String logOutServiceUrl) {
		this.logOutServiceUrl = logOutServiceUrl;
	}
}

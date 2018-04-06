package com.csaa.lyft.domain;

import java.io.Serializable;

public class SPMetaData implements Serializable {
	private static final long serialVersionUID = 6826361809250840175L;
	
	private String entityID;
	private String issueURL;
	private String acsURL;
	private String providerName;
	private String relayState;
	
	public String getEntityID() {
		return entityID;
	}

	public void setEntityID(String entityID) {
		this.entityID = entityID;
	}

	public String getIssueURL() {
		return issueURL;
	}
	
	public void setIssueURL(String issueURL) {
		this.issueURL = issueURL;
	}
	
	public String getAcsURL() {
		return acsURL;
	}
	
	public void setAcsURL(String acsURL) {
		this.acsURL = acsURL;
	}
	
	public String getProviderName() {
		return providerName;
	}
	
	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}
	
	public String getRelayState() {
		return relayState;
	}
	
	public void setRelayState(String relayState) {
		this.relayState = relayState;
	}
}

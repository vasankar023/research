package com.csaa.lyft.domain;


public class SystemProperty {
	
	private String displayName;
	private String key;
	private String value;
	private String type; //static|runtime
	private String uiTabName; //sharepoint, nutch, workday, lcms

	public String getDisplayName() {
		return displayName;
	}
	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}
	public String getKey() {
		return key;
	}
	public void setKey(String key) {
		this.key = key;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getUiTabName() {
		return uiTabName;
	}
	public void setUiTabName(String uiTabName) {
		this.uiTabName = uiTabName;
	}
	
	
	
}

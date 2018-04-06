package com.csaa.lyft.domain;

public class UserAccessInfo {
	private String userID;
	private String userName;
	private String userAccessType;
	public String getUserID() {
		return userID;
	}
	public void setUserID(String userID) {
		this.userID = userID;
	}
	public String getUserName() {
		return userName;
	}
	public void setUserName(String userName) {
		this.userName = userName;
	}
	public String getUserAccessType() {
		return userAccessType;
	}
	public void setUserAccessType(String userAccessType) {
		this.userAccessType = userAccessType;
	}

}

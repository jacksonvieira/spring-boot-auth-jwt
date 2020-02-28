package com.authentication.jwt.model;

import java.io.Serializable;

/**
 * @author Jackson
 *
 */
public class JwtRequestModel implements Serializable {

	private static final long serialVersionUID = 1L;
	private String username;
	private String password;

	/**
	 * É necessário um construtor default para efetuar o parse do JSON
	 */
	public JwtRequestModel() {
	}

	public JwtRequestModel(String username, String password) {
		this.setUsername(username);
		this.setPassword(password);
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
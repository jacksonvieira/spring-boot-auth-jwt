package com.authentication.jwt.model;

import java.io.Serializable;

/**
 * Essa class é necessária para criar o Response que contém o TWT a ser
 * retornado ao usuário que solicitou
 * 
 * @author Jackson
 *
 */
public class JwtResponse implements Serializable {
	private static final long serialVersionUID = 1L;

	private final String jwttoken;

	public JwtResponse(String jwttoken) {
		this.jwttoken = jwttoken;
	}

	public String getToken() {
		return this.jwttoken;
	}
}

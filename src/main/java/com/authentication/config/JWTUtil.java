package com.authentication.config;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * @author Jackson
 *
 */
@Component
public class JWTUtil implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final long JWT_TOKEN_EXPIRES = 5 * 60 * 60;

	@Value("${jwt.secret}")
	private String secret;

	/**
	 * Busca o username do TOKEN JWT
	 * 
	 * @param token
	 * @return retirna o username
	 */
	public String getUsernameFromToken(String token) {
		return getClaimFromToken(token, Claims::getSubject);
	}

	/**
	 * Busca a data de validade do TOKEN JWT
	 * 
	 * @param token
	 * @return retorna a data de expiração
	 */
	public Date getExpirationDateFromToken(String token) {
		return getClaimFromToken(token, Claims::getExpiration);
	}

	/**
	 * 
	 * @param token
	 * @param claimsResolver
	 * @return
	 */
	public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver) {
		final Claims claims = getAllClaimsFromToken(token);
		return claimsResolver.apply(claims);
	}

	/**
	 * Para recuperar qualquer coisa do TOKEN, precisamos a secret key do projeto
	 * 
	 * @param token
	 * @return retornar a secret key
	 */
	private Claims getAllClaimsFromToken(String token) {
		return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
	}

	/**
	 * Verifica se o token já está expirado
	 * 
	 * @param token
	 * @return true/false - Boolean
	 */
	private Boolean isTokenExpired(String token) {
		final Date expiration = getExpirationDateFromToken(token);
		return expiration.before(new Date());
	}

	/**
	 * Gera um TOKEN para o usuário
	 * 
	 * @param userDetails
	 * @return token - String
	 */
	public String generateToken(UserDetails userDetails) {
		Map<String, Object> claims = new HashMap<>();
		return doGenerateToken(claims, userDetails.getUsername());
	}

	/**
	 * Gerando o token com o subject, data de expiração,id. Gera o hash da senha
	 * usando o algoritmo HS512 Serializa o JWT numa URL safe
	 * 
	 * @param claims
	 * @param subject
	 * @return token - String
	 */
	private String doGenerateToken(Map<String, Object> claims, String subject) {
		return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + JWT_TOKEN_EXPIRES * 1000))
				.signWith(SignatureAlgorithm.HS512, secret).compact();
	}

	/**
	 * Valida o token
	 * 
	 * @param token
	 * @param userDetails
	 * @return true/false - Boolean
	 */
	public Boolean validateToken(String token, UserDetails userDetails) {
		final String username = getUsernameFromToken(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}
}

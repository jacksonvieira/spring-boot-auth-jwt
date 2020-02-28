package com.authentication.user.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.authentication.config.JWTUtil;
import com.authentication.config.JwtUserDetailsService;
import com.authentication.jwt.model.JwtRequestModel;
import com.authentication.jwt.model.JwtResponse;

/**
 * Classe responsável por criar um TOKEN válido
 * 
 * @author Jackson
 *
 */
@RestController
@CrossOrigin
@RequestMapping(value = "/user-tokens")

public class UserTokenAuthJWTController {

	private static final String USER_DISABLE = "USER_DISABLED";
	private static final String INVALID_CREDENTIALS = "INVALID_CREDENTIALS";
	@Autowired
	private AuthenticationManager authenticationManager;

	@Autowired
	private JWTUtil jwtTokenUtil;

	@Autowired
	private JwtUserDetailsService userDetailsService;

	@RequestMapping(method = RequestMethod.POST)
	public ResponseEntity<?> createToken(@RequestBody JwtRequestModel jwtRequest) throws Exception {

		doAuthenticate(jwtRequest.getUsername(), jwtRequest.getPassword());
		final UserDetails userDetails = userDetailsService.loadUserByUsername(jwtRequest.getUsername());
		final String token = jwtTokenUtil.generateToken(userDetails);
		return ResponseEntity.ok(new JwtResponse(token));
	}

	private void doAuthenticate(String username, String password) throws Exception {
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
		} catch (DisabledException e) {
			throw new Exception(USER_DISABLE, e);
		} catch (BadCredentialsException e) {
			throw new Exception(INVALID_CREDENTIALS, e);
		}
	}
}

package br.com.atom.jwt;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

@Component
public class JWTUtils {

	@Value("${atom.app.jwtExpirationMs}")
	private long EXPIRATION_TIME = 860000; //24 HORAS
	
	@Value("${atom.app.secretString}")
	private String secretString = "ChaveDeSeguranca1234567890";
	
	private SecretKey key;
	Logger logger = LoggerFactory.getLogger(JWTUtils.class);
	
	public JWTUtils() {
	    logger.info("Essa é a chave secreta: " + secretString);
	    logger.info("Expira em: " + EXPIRATION_TIME);
		byte[] keyBytes = Base64.getDecoder().decode(secretString.getBytes(StandardCharsets.UTF_8));
		this.key = new SecretKeySpec(keyBytes, "HmacSHA256");
	}

	public String generateToken(UserDetails userDetails) {
		return Jwts.builder()
				.subject(userDetails.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(key)
				.compact();
	}
	
	public String generateRefreshToken(HashMap<String, Object> claims, UserDetails userDetails) {
		return Jwts.builder()
				.claims(claims)
				.subject(userDetails.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(key)
				.compact();
	}
	
	public String extractUsername(String token) {
		return extractClaims(token, Claims::getSubject);
	}
	
	private <T>T extractClaims(String token, Function<Claims, T> claimsTFunction){
		return claimsTFunction.apply(Jwts
				.parser()
				.verifyWith(key)
				.build()
				.parseSignedClaims(token)
				.getPayload());
	}
	
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username =  extractUsername(token);
		return (username.equals(userDetails.getUsername())&&!isTokenExpired(token));
	}

	private boolean isTokenExpired(String token) {
		return extractClaims(token, Claims::getExpiration).before(new Date());
	}

	public long getEXPIRATION_TIME() {
		return EXPIRATION_TIME;
	}

	public void setEXPIRATION_TIME(long eXPIRATION_TIME) {
		EXPIRATION_TIME = eXPIRATION_TIME;
	}

	public String getSecretString() {
		return secretString;
	}

	public void setSecretString(String secretString) {
		this.secretString = secretString;
	}
		
}

package com.zuul.api.gateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter{

	private Environment environment;
	
	@Autowired
	public AuthorizationFilter(AuthenticationManager authenticationManager,Environment environment) {
		super(authenticationManager);
        this.environment = environment;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain)
					throws IOException, ServletException {

		String header = request.getHeader("token");

		if (header == null || !header.startsWith("bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
    }
	
	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest req) {
		
		String token = req.getHeader("token").replace("bearer ", "");
		if(token == null) return null;
		
		String userId = Jwts.parser().setSigningKey("kholi18Saurav21Dhoni7").parseClaimsJws(token).getBody().getSubject();
		
		if(userId == null) return null;
	
		
		return new UsernamePasswordAuthenticationToken(userId, null,new ArrayList<>());
	}
}

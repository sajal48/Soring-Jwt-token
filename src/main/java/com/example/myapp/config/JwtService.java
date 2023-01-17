package com.example.myapp.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
@Service
public class JwtService {

    private static final String SECRET_KEY = "703373367639792442264529482B4D6251655468576D5A7134743777217A2543";
    public String extractUserEmail(String token)
    {
        return extractClaim(token,Claims::getSubject);
    }

    private <T> T extractClaim(String token, Function<Claims,T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public  String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 *60 *24))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();

    }

    public  boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUserEmail(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private Date extractExpiration(String token){
        return  extractClaim(token, Claims::getExpiration);
    }
    private boolean isTokenExpired(String token) {
        return  extractExpiration(token).before(new Date());
    }
}

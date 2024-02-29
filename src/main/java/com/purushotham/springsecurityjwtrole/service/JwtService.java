package com.purushotham.springsecurityjwtrole.service;

import com.purushotham.springsecurityjwtrole.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;

@Service
public class JwtService {
    /*https://asecuritysite.com/encryption/plain

    select 256-bit
    click on Determine
    Copy Hex Key past here
    */

    private final String SECRET_KEY = "f0570d59dc4e04111ba841791f14add4338bb5f4f4cb3a1888cdb4c12e5b7f63";

   public String extractUserName(String token){
       return extractClaim(token, Claims::getSubject);
   }
   public boolean isValid(String token, UserDetails user){
       String userName = extractUserName(token);
       return (userName.equals(user.getUsername())) && !isTokenExpired(token);
   }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String toke, Function<Claims, T> resolver){
        Claims claims = extractAllClaims(toke);
        return resolver.apply(claims);
    }


    private Claims extractAllClaims(String token){
        return Jwts.
                parser()
                .verifyWith(getSignInKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();


    }
    public String generateToke(User user){
        return Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSignInKey())
                .compact();

    }

    private SecretKey getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }


}

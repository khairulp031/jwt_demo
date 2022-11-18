package com.example.jwt_demo.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.ResourceUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicKeyReader {

    static RSAPublicKey rsaPublicKey;
    public static String errorMsg="";
    private static RSAPublicKey getRSAPublicKey() throws Exception {
        if (rsaPublicKey !=null) {
            return rsaPublicKey;
        }
        File file = ResourceUtils.getFile("classpath:cert/rsa.pub.pem");
        InputStream in = new FileInputStream(file);
        byte[] bdata = FileCopyUtils.copyToByteArray(in);
        String publicKey = new String(bdata, StandardCharsets.UTF_8)
                .replace("-----BEGIN PUBLIC KEY-----","")
                .replace("-----END PUBLIC KEY-----","")
                .replace("\n", "")
                .replace("\r", "");
        //System.out.println(publicKey);
        byte[] publicKeyByteArr = Base64.getDecoder().decode(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyByteArr));
        return rsaPublicKey;
    }

    public static boolean verify(String token) {
        try {
            RSAPublicKey rsaPublicKey = getRSAPublicKey();
            Algorithm algorithm = Algorithm.RSA512(rsaPublicKey, null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .build();
            DecodedJWT verifiedJWT = verifier.verify(token);
            return true;
        } catch (Exception e) {
            errorMsg=e.toString();
            return false;
        }
    }

    public static String getPayload(String token) {
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String[] chunks = token.split("\\.");
        String payload = new String(decoder.decode(chunks[1]));
        return payload;
    }
}

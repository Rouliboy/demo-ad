package com.example.azure.ad.demoad;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import org.apache.commons.io.IOUtils;
import org.junit.Test;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import lombok.NoArgsConstructor;

public class ValidateSignatureAD {

  private ObjectMapper mapper = new ObjectMapper();

  @Test
  public void test() throws MalformedURLException, IOException, ParseException {

    final String url =
        "https://login.microsoftonline.com/a3c8d0af-358c-4fed-b0bf-73679c851aa0/v2.0/.well-known/openid-configuration";

    InputStream in = null;
    try {
      in = new URL(url).openStream();
      final String content = IOUtils.toString(in, Charset.defaultCharset());
      System.out.println(content);

      final JsonNode newNode = mapper.readTree(content);
      final JsonNode jwsNode = newNode.get("jwks_uri");
      System.out.println(jwsNode.asText());

      final String jwksUri = jwsNode.asText();

      // access token
      // final String token =
      // "eyJ0eXAiOiJKV1QiLCJub25jZSI6IkFRQUJBQUFBQUFDRWZleFh4amFtUWIzT2VHUTRHdWd2TGdfRVp0dWFXc19LU2dXMERhOGtya2lUQWczX2kxdG50SzFUSkxFQVBEMlBiWEJIY1BzdDJfVTN4c1dNSDl2Y2E1T0o1UWxJTEdzV3lRd3BNSjlTRHlBQSIsImFsZyI6IlJTMjU2IiwieDV0IjoiLXN4TUpNTENJRFdNVFB2WnlKNnR4LUNEeHcwIiwia2lkIjoiLXN4TUpNTENJRFdNVFB2WnlKNnR4LUNEeHcwIn0.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hM2M4ZDBhZi0zNThjLTRmZWQtYjBiZi03MzY3OWM4NTFhYTAvIiwiaWF0IjoxNTUxMjExMjkzLCJuYmYiOjE1NTEyMTEyOTMsImV4cCI6MTU1MTIxNTE5MywiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IjQySmdZQkFNNXNqWjg3NUo2TnZhN0lVK1RrZS9GcThPam9oYzF5elpOYjNPVFc3dDlnY0EiLCJhbXIiOlsicHdkIl0sImFwcF9kaXNwbGF5bmFtZSI6ImVzaXAtbG9jYXRpb24tanZpIiwiYXBwaWQiOiI4YWQ3M2Q0NC1hMjUyLTQyOGMtOTdmZi1hNjc0N2E5OTZkOWIiLCJhcHBpZGFjciI6IjEiLCJmYW1pbHlfbmFtZSI6IlZJRU5ORSIsImdpdmVuX25hbWUiOiJKdWxpZW4iLCJpcGFkZHIiOiI4OC4xNzAuNDEuOTAiLCJuYW1lIjoiVklFTk5FIEp1bGllbiIsIm9pZCI6ImEyOGRhOTNlLTU3M2QtNGNhMC05MGQ4LTFiMTVjYjY4YzY0NyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0xNjE0ODk1NzU0LTIxMTE2ODc2NTUtODM5NTIyMTE1LTMwODA2MSIsInBsYXRmIjoiMTQiLCJwdWlkIjoiMTAwM0JGRkRBRUQ3OUZCMSIsInNjcCI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic3ViIjoiWl9aRXg1X2tQNmpwUEtPWC1kZWcwZmRvdThBZTJsOGFTXzlDMFJiS25uWSIsInRpZCI6ImEzYzhkMGFmLTM1OGMtNGZlZC1iMGJmLTczNjc5Yzg1MWFhMCIsInVuaXF1ZV9uYW1lIjoiSlZJRU5ORUBuZXhpdHkuZnIiLCJ1cG4iOiJKVklFTk5FQG5leGl0eS5mciIsInV0aSI6IjR5aUZKX0lvajBlYWh1Skw5NVVCQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfc3QiOnsic3ViIjoiZEtVZHRra3pWU25MdnZFRzN2QjNsSU5hRW11cGtELVUyZWprSHdpeGo2ayJ9LCJ4bXNfdGNkdCI6MTQzNDYyMTM5Nn0.daIsOqVvARKRDYr6wz20Z4QALXYl30LQjI-3rSIpkypjJvnTUd5EOB9_9NQMSf-DkGzRxMQoisadzQHQfxg8Lygn5c5RuhL1cfhdHppvKeWoEJ36YcUDTPscH2O10WYkDybNGE0gm4uGQk68nfz1QLYcGXVr67mQg_BY-7RFnN2wo0LA6QhpUtUJAJhJY_Z-5MIcFiKR5iLKr399ZkIWaX53nFXf3L5jpVTWurpYxitu4ta918A2Ti1GUik2bz3fbcRioCJdNvAzQghwNQicS_0LVzkZ2Od8Gfa5Z1rZNUtpbd0pS9brvTNcXE3rw4sm7OWAcDMtVDOdAJWoF0ifHw";
      //
      // id token
      final String token =
          "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii1zeE1KTUxDSURXTVRQdlp5SjZ0eC1DRHh3MCJ9.eyJhdWQiOiI4YWQ3M2Q0NC1hMjUyLTQyOGMtOTdmZi1hNjc0N2E5OTZkOWIiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vYTNjOGQwYWYtMzU4Yy00ZmVkLWIwYmYtNzM2NzljODUxYWEwL3YyLjAiLCJpYXQiOjE1NTEzMDY4MzEsIm5iZiI6MTU1MTMwNjgzMSwiZXhwIjoxNTUxMzEwNzMxLCJhaW8iOiJBVFFBeS84S0FBQUFlWHBVdDlRSVZmK1VzQ2xoMSt0bkNubm1BVmtGbGVQWnVkRnZZdThkV3h0bTNWWGgwQVRuU2JnSkVjS3BVL2dEIiwibm9uY2UiOiI3MzYyQ0FFQS05Q0E1LTRCNDMtOUJBMy0zNEQ3QzMwM0VCQTciLCJzdWIiOiJkS1VkdGtrelZTbkx2dkVHM3ZCM2xJTmFFbXVwa0QtVTJlamtId2l4ajZrIiwidGlkIjoiYTNjOGQwYWYtMzU4Yy00ZmVkLWIwYmYtNzM2NzljODUxYWEwIiwidXRpIjoiNGZ1Nm5TS2lrVS1hWXN3Mk8zWURBQSIsInZlciI6IjIuMCJ9.jyXTUih5SNruziYuopQXPZTFXIaMlueTlcASvUmAW3u13YwFcVf2vEbpa2-19lBvgiBj3U4ZeBrSP_DOT4PUVpnYmHXuNhHaJTjfgJxrF6RzduSVhPj6VbQ_Wao8yd2zDntGtGlF0Q2OhV69fh0AnU-bsCgBpm-HdbRRAm6QZmDVm68kCPZSLK9uAxVIiEjkE_4ffiwJIeVdiS7k3yft3PDQkQJQE6DC4CQeX4Aovok3BHDPmoZsniiTtiARmjgTW84zOQIDDIJ0-7C4EHCdVPDvV7c7jjKoTENVscGy7NhhUOQrvNKPzO7WbDpWsjU85VJ2Y25EQOtjosrPauYOxA";

      final SignedJWT jwt = SignedJWT.parse(token);
      System.out.println(jwt.getHeader().getAlgorithm());

      final String kid = jwt.getHeader().getKeyID();
      @SuppressWarnings("deprecation")
      final String x5t = kid; // jwt.getHeader().getX509CertThumbprint().toString();

      in = new URL(jwksUri).openStream();
      final String keysContent = IOUtils.toString(in, Charset.defaultCharset());

      final DiscoveryKeysHandler keysHandler =
          mapper.readValue(keysContent, DiscoveryKeysHandler.class);

      final DiscoveryKey key = keysHandler.getKeys().stream()
          .filter(k -> k.getKid().equals(kid) && k.getX5t().equals(x5t)).findFirst()
          .orElseThrow(() -> new IllegalArgumentException());

      final byte[] certChain = Base64.getDecoder().decode(key.getX5c().get(0));
      final X509Certificate cert = X509CertUtils.parse(certChain);
      final PublicKey pubKeyNew = cert.getPublicKey();
      final Claims claims3 = Jwts.parser().setSigningKey(pubKeyNew).parseClaimsJws(token).getBody();

      jwt.getHeader();

    } finally {
      IOUtils.closeQuietly(in);
    }
  }

  @Test
  public void testSecondApproch() throws MalformedURLException, IOException, ParseException,
      NoSuchAlgorithmException, InvalidKeySpecException {

    final String url =
        "https://login.microsoftonline.com/a3c8d0af-358c-4fed-b0bf-73679c851aa0/v2.0/.well-known/openid-configuration";

    InputStream in = null;
    try {
      in = new URL(url).openStream();
      final String content = IOUtils.toString(in, Charset.defaultCharset());
      System.out.println(content);

      final JsonNode newNode = mapper.readTree(content);
      final JsonNode jwsNode = newNode.get("jwks_uri");
      System.out.println(jwsNode.asText());

      final String jwksUri = jwsNode.asText();

      // access token
      final String token =
          "eyJ0eXAiOiJKV1QiLCJub25jZSI6IkFRQUJBQUFBQUFDRWZleFh4amFtUWIzT2VHUTRHdWd2TGdfRVp0dWFXc19LU2dXMERhOGtya2lUQWczX2kxdG50SzFUSkxFQVBEMlBiWEJIY1BzdDJfVTN4c1dNSDl2Y2E1T0o1UWxJTEdzV3lRd3BNSjlTRHlBQSIsImFsZyI6IlJTMjU2IiwieDV0IjoiLXN4TUpNTENJRFdNVFB2WnlKNnR4LUNEeHcwIiwia2lkIjoiLXN4TUpNTENJRFdNVFB2WnlKNnR4LUNEeHcwIn0.eyJhdWQiOiIwMDAwMDAwMy0wMDAwLTAwMDAtYzAwMC0wMDAwMDAwMDAwMDAiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9hM2M4ZDBhZi0zNThjLTRmZWQtYjBiZi03MzY3OWM4NTFhYTAvIiwiaWF0IjoxNTUxMjExMjkzLCJuYmYiOjE1NTEyMTEyOTMsImV4cCI6MTU1MTIxNTE5MywiYWNjdCI6MCwiYWNyIjoiMSIsImFpbyI6IjQySmdZQkFNNXNqWjg3NUo2TnZhN0lVK1RrZS9GcThPam9oYzF5elpOYjNPVFc3dDlnY0EiLCJhbXIiOlsicHdkIl0sImFwcF9kaXNwbGF5bmFtZSI6ImVzaXAtbG9jYXRpb24tanZpIiwiYXBwaWQiOiI4YWQ3M2Q0NC1hMjUyLTQyOGMtOTdmZi1hNjc0N2E5OTZkOWIiLCJhcHBpZGFjciI6IjEiLCJmYW1pbHlfbmFtZSI6IlZJRU5ORSIsImdpdmVuX25hbWUiOiJKdWxpZW4iLCJpcGFkZHIiOiI4OC4xNzAuNDEuOTAiLCJuYW1lIjoiVklFTk5FIEp1bGllbiIsIm9pZCI6ImEyOGRhOTNlLTU3M2QtNGNhMC05MGQ4LTFiMTVjYjY4YzY0NyIsIm9ucHJlbV9zaWQiOiJTLTEtNS0yMS0xNjE0ODk1NzU0LTIxMTE2ODc2NTUtODM5NTIyMTE1LTMwODA2MSIsInBsYXRmIjoiMTQiLCJwdWlkIjoiMTAwM0JGRkRBRUQ3OUZCMSIsInNjcCI6Im9wZW5pZCBwcm9maWxlIGVtYWlsIiwic3ViIjoiWl9aRXg1X2tQNmpwUEtPWC1kZWcwZmRvdThBZTJsOGFTXzlDMFJiS25uWSIsInRpZCI6ImEzYzhkMGFmLTM1OGMtNGZlZC1iMGJmLTczNjc5Yzg1MWFhMCIsInVuaXF1ZV9uYW1lIjoiSlZJRU5ORUBuZXhpdHkuZnIiLCJ1cG4iOiJKVklFTk5FQG5leGl0eS5mciIsInV0aSI6IjR5aUZKX0lvajBlYWh1Skw5NVVCQUEiLCJ2ZXIiOiIxLjAiLCJ4bXNfc3QiOnsic3ViIjoiZEtVZHRra3pWU25MdnZFRzN2QjNsSU5hRW11cGtELVUyZWprSHdpeGo2ayJ9LCJ4bXNfdGNkdCI6MTQzNDYyMTM5Nn0.daIsOqVvARKRDYr6wz20Z4QALXYl30LQjI-3rSIpkypjJvnTUd5EOB9_9NQMSf-DkGzRxMQoisadzQHQfxg8Lygn5c5RuhL1cfhdHppvKeWoEJ36YcUDTPscH2O10WYkDybNGE0gm4uGQk68nfz1QLYcGXVr67mQg_BY-7RFnN2wo0LA6QhpUtUJAJhJY_Z-5MIcFiKR5iLKr399ZkIWaX53nFXf3L5jpVTWurpYxitu4ta918A2Ti1GUik2bz3fbcRioCJdNvAzQghwNQicS_0LVzkZ2Od8Gfa5Z1rZNUtpbd0pS9brvTNcXE3rw4sm7OWAcDMtVDOdAJWoF0ifHw";

      // id token
      // final String token =
      // "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ii1zeE1KTUxDSURXTVRQdlp5SjZ0eC1DRHh3MCJ9.eyJhdWQiOiI4YWQ3M2Q0NC1hMjUyLTQyOGMtOTdmZi1hNjc0N2E5OTZkOWIiLCJpc3MiOiJodHRwczovL2xvZ2luLm1pY3Jvc29mdG9ubGluZS5jb20vYTNjOGQwYWYtMzU4Yy00ZmVkLWIwYmYtNzM2NzljODUxYWEwL3YyLjAiLCJpYXQiOjE1NTEzMDY4MzEsIm5iZiI6MTU1MTMwNjgzMSwiZXhwIjoxNTUxMzEwNzMxLCJhaW8iOiJBVFFBeS84S0FBQUFlWHBVdDlRSVZmK1VzQ2xoMSt0bkNubm1BVmtGbGVQWnVkRnZZdThkV3h0bTNWWGgwQVRuU2JnSkVjS3BVL2dEIiwibm9uY2UiOiI3MzYyQ0FFQS05Q0E1LTRCNDMtOUJBMy0zNEQ3QzMwM0VCQTciLCJzdWIiOiJkS1VkdGtrelZTbkx2dkVHM3ZCM2xJTmFFbXVwa0QtVTJlamtId2l4ajZrIiwidGlkIjoiYTNjOGQwYWYtMzU4Yy00ZmVkLWIwYmYtNzM2NzljODUxYWEwIiwidXRpIjoiNGZ1Nm5TS2lrVS1hWXN3Mk8zWURBQSIsInZlciI6IjIuMCJ9.jyXTUih5SNruziYuopQXPZTFXIaMlueTlcASvUmAW3u13YwFcVf2vEbpa2-19lBvgiBj3U4ZeBrSP_DOT4PUVpnYmHXuNhHaJTjfgJxrF6RzduSVhPj6VbQ_Wao8yd2zDntGtGlF0Q2OhV69fh0AnU-bsCgBpm-HdbRRAm6QZmDVm68kCPZSLK9uAxVIiEjkE_4ffiwJIeVdiS7k3yft3PDQkQJQE6DC4CQeX4Aovok3BHDPmoZsniiTtiARmjgTW84zOQIDDIJ0-7C4EHCdVPDvV7c7jjKoTENVscGy7NhhUOQrvNKPzO7WbDpWsjU85VJ2Y25EQOtjosrPauYOxA";

      final SignedJWT jwt = SignedJWT.parse(token);
      System.out.println(jwt.getHeader().getAlgorithm());

      final String kid = jwt.getHeader().getKeyID();
      @SuppressWarnings("deprecation")
      final String x5t = kid; // jwt.getHeader().getX509CertThumbprint().toString();

      in = new URL(jwksUri).openStream();
      final String keysContent = IOUtils.toString(in, Charset.defaultCharset());

      final DiscoveryKeysHandler keysHandler =
          mapper.readValue(keysContent, DiscoveryKeysHandler.class);

      final DiscoveryKey key = keysHandler.getKeys().stream()
          .filter(k -> k.getKid().equals(kid) && k.getX5t().equals(x5t)).findFirst()
          .orElseThrow(() -> new IllegalArgumentException());

      final byte[] modulusBytes = Base64.getUrlDecoder().decode(key.getN());
      final byte[] exponentBytes = Base64.getUrlDecoder().decode(key.getE());
      final BigInteger modulusInt = new BigInteger(1, modulusBytes);
      final BigInteger exponentInt = new BigInteger(1, exponentBytes);

      final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      final RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulusInt, exponentInt);
      final RSAPublicKey pubKey = (RSAPublicKey) keyFactory.generatePublic(publicSpec);
      final Jwt<JwsHeader, Claims> c = Jwts.parser().setSigningKey(pubKey).parseClaimsJws(token);

      jwt.getHeader();

    } finally {
      IOUtils.closeQuietly(in);
    }
  }

  @Data
  @NoArgsConstructor
  public static class DiscoveryKeysHandler {

    private List<DiscoveryKey> keys;

  }

  @Data
  @NoArgsConstructor
  public static class DiscoveryKey {

    private String kty;
    private String use;
    private String kid;
    private String x5t;
    private String n;
    private String e;
    private List<String> x5c;
    private String issuer;

  }
}

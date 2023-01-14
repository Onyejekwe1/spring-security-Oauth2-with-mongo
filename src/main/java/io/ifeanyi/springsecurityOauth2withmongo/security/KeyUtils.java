package io.ifeanyi.springsecurityOauth2withmongo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Objects;

@Component
@Slf4j
public class KeyUtils {
    @Autowired
    Environment environment;

    @Value("${access-token.private}")
    private String accessTokenPrivateKeyPath;

    @Value("${access-token.public}")
    private String accessTokenPublicKeyPath;

    @Value("${refresh-token.private}")
    private String refreshTokenPrivateKeyPath;

    @Value("${refresh-token.public}")
    private String refreshTokenPublicKeyPath;

    private KeyPair _accessTokenKeyPair;
    private KeyPair _refreshTokenKeyPair;

    private KeyPair getAccessTokenPair() {
        if (Objects.isNull(_accessTokenKeyPair)) {
            _accessTokenKeyPair = getKeyPair(accessTokenPublicKeyPath, accessTokenPrivateKeyPath);
        }
        return _accessTokenKeyPair;
    }

    private KeyPair getKeyPair(String publicKeyPath, String privateKeyPath) {
        KeyPair keyPair;

        File publicKeyFile = new File(publicKeyPath);
        File privateKeyFile = new File(privateKeyPath);

        if (publicKeyFile.exists() && privateKeyFile.exists()){
            log.info("Loading keys from file: {}, {}", publicKeyPath, privateKeyPath);
           try {
               KeyFactory keyFactory = KeyFactory.getInstance("RSA");

               byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
               EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
               PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);

               byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
               EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
               PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

               keyPair = new KeyPair(publicKey, privateKey);
               return keyPair;
           } catch (NoSuchAlgorithmException | IOException | InvalidKeySpecException e) {
               throw new RuntimeException(e);
           }
        } else {
            if(Arrays.stream(environment.getActiveProfiles()).anyMatch(s -> s.equals("prod"))){
                throw new RuntimeException("public and private keys don't exist");
            }

            File directory = new File("access-refresh-token-keys");
            if(!directory.exists()){
                directory.mkdirs();
            }
            try{
                log.info("Generating keys from file: {}, {}", publicKeyPath, privateKeyPath);
                KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                keyPairGenerator.initialize(2048);
                keyPair = keyPairGenerator.generateKeyPair();
                try (FileOutputStream fileOutputStream = new FileOutputStream(publicKeyPath)) {
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
                    fileOutputStream.write(keySpec.getEncoded());
                }

                try (FileOutputStream fileOutputStream = new FileOutputStream(privateKeyPath)) {
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
                    fileOutputStream.write(keySpec.getEncoded());
                }
            } catch (NoSuchAlgorithmException | IOException e) {
                throw new RuntimeException(e);
            }
        }
        return keyPair;
    }

    private KeyPair getRefreshTokenPair() {
        if (Objects.isNull(_refreshTokenKeyPair)) {
            _refreshTokenKeyPair = getKeyPair(refreshTokenPublicKeyPath, refreshTokenPrivateKeyPath);
        }
        return _refreshTokenKeyPair;
    }

    public RSAPublicKey getAccessTokenPublicKey() {
        return (RSAPublicKey) getAccessTokenPair().getPublic();
    };
    public RSAPrivateKey getAccessTokenPrivateKey() {
        return (RSAPrivateKey) getAccessTokenPair().getPrivate();
    };
    public RSAPublicKey getRefreshTokenPublicKey() {
        return (RSAPublicKey) getRefreshTokenPair().getPublic();
    };
    public RSAPrivateKey getRefreshTokenPrivateKey() {
        return (RSAPrivateKey) getRefreshTokenPair().getPrivate();
    };
}

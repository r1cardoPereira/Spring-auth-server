package br.com.ricardopereira.authserver;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * A classe TokenStoreConfig é uma classe de configuração do Spring, responsável
 * por configurar as chaves usadas para assinar e decodificar o token de acesso
 * usado pelas requisições autenticadas.
 * 
 * Dentro da classe, temos três métodos principais: jwkSource(),
 * jwtDecoder(JWKSource<SecurityContext> jwkSource) e generateRsaKey().
 * 
 * O método generateRsaKey() é um método privado que gera um par de chaves RSA.
 * Ele usa a classe KeyPairGenerator para gerar um par de chaves RSA de 2048
 * bits. Se ocorrer algum erro durante a geração das chaves, uma exceção
 * IllegalStateException é lançada.
 * 
 * O método jwkSource() é um bean do Spring que cria uma fonte de chave JSON Web
 * Key (JWK) a partir do par de chaves RSA gerado pelo método generateRsaKey().
 * Ele extrai a chave pública e privada do par de chaves, cria uma chave RSA JWK
 * com essas chaves e um ID de chave gerado aleatoriamente, e então coloca essa
 * chave em um conjunto de chaves JWK. Finalmente, ele retorna uma versão
 * imutável desse conjunto de chaves JWK.
 * 
 * O método jwtDecoder(JWKSource<SecurityContext> jwkSource) é outro bean do
 * Spring que cria um decodificador JWT. Ele usa a configuração do servidor de
 * autorização OAuth2 do Spring para criar o decodificador JWT a partir da fonte
 * de chave JWK fornecida. Este decodificador JWT pode ser usado para
 * decodificar tokens de acesso JWT.
 */

@Configuration
public class TokenStoreConfig {

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

}

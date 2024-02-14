package br.com.ricardopereira.authserver;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/**
 * Classe de configuração do Spring responsável por configurar os clientes
 * OAuth2 que podem se conectar ao servidor de autorização.
 * 
 * O método `registeredClientRepository()` é um bean do Spring que configura um
 * cliente OAuth2 e o armazena em um repositório de clientes em memória.
 * 
 * Detalhes da configuração do cliente:
 * - O ID do cliente é gerado aleatoriamente.
 * - O ID do cliente é definido como "client-server".
 * - O segredo do cliente é definido como "{noop}secret", indicando que o
 * segredo do cliente não está codificado.
 * - O método de autenticação do cliente é definido como
 * `ClientAuthenticationMethod.CLIENT_SECRET_BASIC`, o que significa que o
 * cliente deve autenticar-se usando seu ID de cliente e segredo.
 * - São definidos três tipos de concessão de autorização: `AUTHORIZATION_CODE`,
 * `REFRESH_TOKEN` e `CLIENT_CREDENTIALS`.
 * - A URI de redirecionamento é definida como
 * "http://127.0.0.1:8080/login/oauth2/code/client-server". Esta é a URI para a
 * qual o servidor de autorização redirecionará o usuário após a autenticação.
 * - São definidos dois escopos: `OPENID` e `PROFILE`. O escopo `OPENID` é
 * necessário para o protocolo OpenID Connect, enquanto o escopo `PROFILE`
 * permite ao cliente acessar o perfil do usuário.
 * - As configurações do cliente são definidas para exigir o consentimento de
 * autorização.
 * 
 * O cliente configurado é armazenado em um `InMemoryRegisteredClientRepository`
 * e o repositório é retornado.
 * Este repositório armazena os detalhes do cliente em memória e pode ser usado
 * para recuperar os detalhes do cliente durante a autenticação.
 */

@Configuration
public class ClientStoreConfig {

    @Bean
    RegisteredClientRepository registeredClientRepository() {

        var registeredClient = RegisteredClient
                .withId(UUID.randomUUID().toString())
                .clientId("client-server")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/client-server-oidc")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

}

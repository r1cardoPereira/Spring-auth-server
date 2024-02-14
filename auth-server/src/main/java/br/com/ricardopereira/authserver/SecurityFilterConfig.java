package br.com.ricardopereira.authserver;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * Classe de configuração de segurança do Spring.
 * 
 * Esta classe define duas cadeias de filtros de segurança que são aplicadas a
 * diferentes tipos de solicitações.
 * 
 * A primeira cadeia de filtros, definida pelo método
 * `authServSecurityFilterChain(HttpSecurity http)`, é aplicada a solicitações
 * para o servidor de autorização OAuth2.
 * 
 * 1. Aplica a segurança padrão do servidor de autorização OAuth2, que inclui
 * proteções contra ataques comuns, como CSRF.
 * 
 * 2. Configura o suporte para o protocolo OpenID Connect (OIDC) com
 * configurações padrão. OIDC é uma camada de identidade construída sobre o
 * protocolo OAuth2, que permite a autenticação do usuário final.
 * 
 * 3. Configura um ponto de entrada de autenticação personalizado que
 * redireciona os usuários não autenticados para a página de login. Isso é útil
 * para fornecer uma experiência de usuário personalizada para autenticação.
 * 
 * 4. Configura o servidor de recursos OAuth2 para usar tokens JWT. JWTs são
 * tokens de acesso que contêm informações sobre o usuário e são usados para
 * proteger as rotas da API.
 * 
 * A segunda cadeia de filtros, definida pelo método
 * `defaulSecurityFilterChain(HttpSecurity http)`, é aplicada a todas as outras
 * solicitações.
 * 
 * 1. Exige que todas as solicitações sejam autenticadas. Isso significa que o
 * usuário deve estar logado para acessar qualquer rota protegida por este
 * filtro.
 *
 *  2. Configura o login do formulário com configurações padrão. Isso permite que
 * os usuários se autentiquem usando um formulário de login padrão.
 * 
 * Cada método retorna uma cadeia de filtros de segurança construída que é
 * aplicada às solicitações correspondentes.
 */

@Configuration
public class SecurityFilterConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authServSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(
                withDefaults())
                .and()
                .exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(
                        new LoginUrlAuthenticationEntryPoint("/login")))
                .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();

    }

    @Bean
    @Order(2)
    SecurityFilterChain defaulSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
                .formLogin(withDefaults());

        return http.build();
    }

}

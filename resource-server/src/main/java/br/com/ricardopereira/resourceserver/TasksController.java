package br.com.ricardopereira.resourceserver;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("tasks")
public class TasksController {
    @GetMapping
    public String getTasks(
            @AuthenticationPrincipal Jwt jwt) {

        return """
                <h1> Top Secret tasks for %s</h1>
                <ol>
                    <li>primeiro item</li>
                    <li>segundo item</li>
                    <li>terceiro item</li>
                </ol>
                    """.formatted(jwt.getSubject());
    }
}

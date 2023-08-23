package se.mkk.springboot3oauth2loginkeycloak;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping
    public Map<String, String> getUser(HttpServletRequest request, Principal principal) {
        Map<String, String> rtn = new LinkedHashMap<>();
        rtn.put("request.getRemoteUser()", request.getRemoteUser());
        rtn.put("request.isUserInRole(\"USER\")", Boolean.toString(request.isUserInRole("USER")));
        rtn.put("request.getUserPrincipal().getClass()", request.getUserPrincipal().getClass().getName());
        rtn.put("principal.getClass().getName()", principal.getClass().getName());
        rtn.put("principal.getName()", principal.getName());
        if (principal instanceof OAuth2AuthenticationToken token) {
            List<String> authorities = token.getAuthorities().stream()
                    .map(grantedAuthority -> grantedAuthority.getAuthority()).toList();
            rtn.put("OAuth2AuthenticationToken.getAuthorities()", authorities.toString());
        }
        return rtn;
    }
}

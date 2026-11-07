/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License,
or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>
 */
package fr.f4fez.authorizationserver.authorization

import io.swagger.v3.oas.annotations.Hidden
import org.springframework.http.HttpStatus
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.stereotype.Controller
import org.springframework.ui.Model
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.server.ResponseStatusException
import java.security.Principal

@Hidden
@Controller
class ConsentController(
    private val registeredClientRepository: RegisteredClientRepository,
) {
    @GetMapping("/oauth2/consent")
    fun consent(
        principal: Principal,
        @RequestParam(OAuth2ParameterNames.CLIENT_ID) clientId: String,
        @RequestParam(OAuth2ParameterNames.SCOPE) scope: String,
        @RequestParam(OAuth2ParameterNames.STATE) state: String,
        model: Model,
    ): String {
        registeredClientRepository.findByClientId(clientId)
            ?: throw ResponseStatusException(HttpStatus.BAD_REQUEST)

        model.addAttribute("clientId", clientId)
        model.addAttribute("state", state)
        model.addAttribute(
            "scopes",
            scope.split(" ").filter { it.isNotBlank() && it != OidcScopes.OPENID },
        )
        model.addAttribute("username", principal.name)
        return "consent"
    }
}

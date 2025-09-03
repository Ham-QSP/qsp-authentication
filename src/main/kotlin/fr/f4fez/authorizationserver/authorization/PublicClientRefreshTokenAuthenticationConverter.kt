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


import jakarta.servlet.http.HttpServletRequest
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.Transient
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator
import org.springframework.security.crypto.keygen.StringKeyGenerator
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator
import org.springframework.security.web.authentication.AuthenticationConverter
import java.time.Instant
import java.util.*

/***
 * Source: https://github.com/spring-projects/spring-authorization-server/pull/1432
 *
 * Spring authorization server doesn't support issuing refresh tokens for public clients.
 * To support this feature, we have to implement a custom authentication converter, authentication
 * provider and refresh token generator [CustomRefreshTokenGenerator]
 */

class PublicClientRefreshTokenAuthenticationConverter : AuthenticationConverter {
    override fun convert(request: HttpServletRequest): Authentication? {
        // grant_type (REQUIRED)
        val grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE)
        if (AuthorizationGrantType.REFRESH_TOKEN.value != grantType) {
            return null
        }
        // client_id (REQUIRED)
        val clientId = request.getParameter(OAuth2ParameterNames.CLIENT_ID)
        if (clientId.isNullOrBlank()) {
            return null
        }

        return PublicClientRefreshTokenAuthenticationToken(clientId)
    }
}

@Transient
class PublicClientRefreshTokenAuthenticationToken : OAuth2ClientAuthenticationToken {

    constructor(clientId: String) : super(clientId, ClientAuthenticationMethod.NONE, null, null)

    constructor(registeredClient: RegisteredClient) : super(registeredClient, ClientAuthenticationMethod.NONE, null)
}

class PublicClientRefreshTokenAuthenticationProvider(private val registeredClientRepository: RegisteredClientRepository) :
    AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication? {
        val publicClientAuthentication: PublicClientRefreshTokenAuthenticationToken =
            authentication as PublicClientRefreshTokenAuthenticationToken

        if (!ClientAuthenticationMethod.NONE.equals(publicClientAuthentication.clientAuthenticationMethod)) {
            return null
        }

        val clientId: String = publicClientAuthentication.principal.toString()
        val registeredClient = registeredClientRepository.findByClientId(clientId)
        if (registeredClient == null) {
            throwInvalidClient(OAuth2ParameterNames.CLIENT_ID)
        }

        if (!registeredClient!!.clientAuthenticationMethods.contains(
                publicClientAuthentication.clientAuthenticationMethod,
            )
        ) {
            throwInvalidClient("authentication_method")
        }

        return PublicClientRefreshTokenAuthenticationToken(registeredClient)
    }

    override fun supports(authentication: Class<*>): Boolean {
        return PublicClientRefreshTokenAuthenticationToken::class.java.isAssignableFrom(authentication)
    }

    companion object {
        private fun throwInvalidClient(parameterName: String) {
            val error = OAuth2Error(
                OAuth2ErrorCodes.INVALID_CLIENT,
                "Public client authentication failed: $parameterName",
                null,
            )
            throw OAuth2AuthenticationException(error)
        }
    }
}

/**
 * Custom refresh token generator that overrides [org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator]
 * to allow generating a refresh token for public clients
 */
class CustomRefreshTokenGenerator : OAuth2TokenGenerator<OAuth2RefreshToken?> {
    private val refreshTokenGenerator: StringKeyGenerator =
        Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96)

    override fun generate(context: OAuth2TokenContext): OAuth2RefreshToken? {
        if (!OAuth2TokenType.REFRESH_TOKEN.equals(context.tokenType)) {
            return null
        }

        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(context.registeredClient.tokenSettings.refreshTokenTimeToLive)

        return OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt)
    }
}
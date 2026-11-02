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
package fr.f4fez.authorizationserver.user

import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.CredentialsExpiredException
import org.springframework.security.authentication.LockedException
import org.springframework.security.authentication.dao.DaoAuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * Password authentication that refuses a username locked by [LoginAttemptLimiter], before looking it up,
 * so that locked and unknown usernames get the same answer.
 */
class ThrottledDaoAuthenticationProvider(
    userDetailsService: UserDetailsService,
    passwordEncoder: PasswordEncoder,
    private val loginAttemptLimiter: LoginAttemptLimiter,
) : DaoAuthenticationProvider(userDetailsService) {
    companion object {
        const val LOCKED_MESSAGE = "Too many failed attempts, try again later"
    }

    init {
        setPasswordEncoder(passwordEncoder)
    }

    override fun authenticate(authentication: Authentication): Authentication {
        val username = authentication.name
        if (loginAttemptLimiter.isLocked(username)) {
            throw LockedException(LOCKED_MESSAGE)
        }
        try {
            return super.authenticate(authentication).also { loginAttemptLimiter.recordSuccess(username) }
        } catch (e: BadCredentialsException) {
            loginAttemptLimiter.recordFailure(username)
            throw e
        } catch (e: CredentialsExpiredException) {
            // Raised only after the password matched
            loginAttemptLimiter.recordSuccess(username)
            throw e
        }
    }
}

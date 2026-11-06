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

import fr.f4fez.authorizationserver.authentication.LoginAttemptLimiter
import fr.f4fez.authorizationserver.authentication.ThrottledDaoAuthenticationProvider
import org.springframework.http.HttpStatus
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.server.ResponseStatusException
import java.time.LocalDateTime
import java.util.UUID

@Service
class UserService(
    private val userRepository: UserRepository,
    private val passwordEncoder: PasswordEncoder,
    private val authorityRepository: AuthorityRepository,
    private val passwordPolicy: PasswordPolicy,
    private val loginAttemptLimiter: LoginAttemptLimiter,
) {
    companion object {
        private const val DEFAULT_AUTHORITY = "ROLE_USER"
    }

    fun findAll(): List<User> = userRepository.findAll().toList()

    fun findById(id: UUID): User =
        userRepository
            .findById(id)
            .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND, "User '$id' not found") }

    fun findByEmail(email: String): List<User> = userRepository.findAllByEmailIgnoreCase(email.trim())

    fun findByUsernameOrNull(username: String): User? = userRepository.findByUsername(username)

    fun findByUsername(username: String): User =
        userRepository.findByUsername(username)
            ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User '$username' not found")

    @Transactional
    fun create(request: CreateUserRequest): User {
        if (userRepository.existsByUsername(request.username)) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "Username '${request.username}' is already taken")
        }
        if (userRepository.existsByEmail(request.email)) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "Email '${request.email}' is already used")
        }

        passwordPolicy.requireValid(request.username, request.password)

        val user =
            User(
                username = request.username,
                password = passwordEncoder.encode(request.password)!!,
                enabled = request.enabled,
                email = request.email,
                emailValidated = false,
                authorities = setOf(UserAuthority(DEFAULT_AUTHORITY)),
            )
        return userRepository.save(user)
    }

    @Transactional
    fun update(
        id: UUID,
        request: UpdateUserRequest,
    ): User {
        val existing = findById(id)
        if (existing.email != request.email && userRepository.existsByEmail(request.email)) {
            throw ResponseStatusException(HttpStatus.CONFLICT, "Email '${request.email}' is already used")
        }

        request.roles?.let(::requireKnownRoles)
        request.password?.let { passwordPolicy.requireValid(existing.username, it) }

        val updated =
            existing.copy(
                email = request.email,
                enabled = request.enabled,
                passwordExpiration =
                    when {
                        request.passwordExpiration != null -> request.passwordExpiration.orElse(null)

                        // A password chosen by an admin must be replaced by the user at the next login
                        request.password != null -> LocalDateTime.now()

                        else -> existing.passwordExpiration
                    },
                password = request.password?.let { passwordEncoder.encode(it)!! } ?: existing.password,
                passwordChangedAt = if (request.password != null) LocalDateTime.now() else existing.passwordChangedAt,
                authorities = request.roles?.mapTo(mutableSetOf(), ::UserAuthority) ?: existing.authorities,
            )
        return userRepository.save(updated)
    }

    fun changePassword(
        username: String,
        request: ChangePasswordRequest,
    ) {
        val user =
            userRepository.findByUsername(username)
                ?: throw ResponseStatusException(HttpStatus.NOT_FOUND, "User '$username' not found")
        if (loginAttemptLimiter.isLocked(username)) {
            throw ResponseStatusException(
                HttpStatus.TOO_MANY_REQUESTS,
                ThrottledDaoAuthenticationProvider.LOCKED_MESSAGE,
            )
        }
        if (!passwordEncoder.matches(request.currentPassword, user.password)) {
            loginAttemptLimiter.recordFailure(username)
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Current password is incorrect")
        }
        loginAttemptLimiter.recordSuccess(username)
        passwordPolicy.requireValid(user.username, request.newPassword)
        storePassword(user, request.newPassword)
    }

    fun renewExpiredPassword(
        username: String,
        newPassword: String,
    ) {
        val user = findByUsername(username)
        if (passwordEncoder.matches(newPassword, user.password)) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "The new password must differ from the expired one")
        }
        passwordPolicy.requireValid(user.username, newPassword)
        storePassword(user, newPassword)
    }

    fun delete(id: UUID) {
        if (!userRepository.existsById(id)) {
            throw ResponseStatusException(HttpStatus.NOT_FOUND, "User '$id' not found")
        }
        userRepository.deleteById(id)
    }

    private fun storePassword(
        user: User,
        newPassword: String,
    ) {
        userRepository.save(
            user.copy(
                password = passwordEncoder.encode(newPassword)!!,
                passwordExpiration = null,
                passwordChangedAt = LocalDateTime.now(),
            ),
        )
    }

    private fun requireKnownRoles(roles: Set<String>) {
        val unknown = roles - authorityRepository.findAllById(roles).mapTo(mutableSetOf()) { it.authority }
        if (unknown.isNotEmpty()) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown roles: ${unknown.sorted().joinToString()}")
        }
    }
}

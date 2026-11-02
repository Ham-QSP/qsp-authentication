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

import org.springframework.http.HttpStatus
import org.springframework.jdbc.core.JdbcTemplate
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
    private val jdbcTemplate: JdbcTemplate,
    private val passwordPolicy: PasswordPolicy,
    private val loginAttemptLimiter: LoginAttemptLimiter,
) {
    companion object {
        private const val DEFAULT_AUTHORITY = "ROLE_USER"
    }

    fun findAll(): List<User> {
        val users = userRepository.findAll().toList()
        val rolesByUsername = loadRoles()
        return users.map { it.copy(roles = rolesByUsername[it.username].orEmpty()) }
    }

    fun findById(id: UUID): User =
        userRepository
            .findById(id)
            .orElseThrow { ResponseStatusException(HttpStatus.NOT_FOUND, "User '$id' not found") }
            .let(::withRoles)

    fun findByEmail(email: String): List<User> = userRepository.findAllByEmailIgnoreCase(email.trim())

    fun findByUsernameOrNull(username: String): User? = userRepository.findByUsername(username)?.let(::withRoles)

    fun findByUsername(username: String): User =
        userRepository.findByUsername(username)?.let(::withRoles)
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
            )
        val saved = userRepository.save(user)
        replaceRoles(saved.username, setOf(DEFAULT_AUTHORITY))
        return withRoles(saved)
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
                passwordExpiration = request.passwordExpiration,
                password = request.password?.let { passwordEncoder.encode(it)!! } ?: existing.password,
                passwordChangedAt = if (request.password != null) LocalDateTime.now() else existing.passwordChangedAt,
            )
        val saved = userRepository.save(updated)
        request.roles?.let { replaceRoles(saved.username, it) }
        return withRoles(saved)
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

    private fun withRoles(user: User): User = user.copy(roles = loadRoles(user.username)[user.username].orEmpty())

    private fun loadRoles(username: String? = null): Map<String, Set<String>> {
        val sql =
            "select username, authority from qsp_auth_user_authorities" +
                if (username != null) " where username = ?" else ""
        val args = listOfNotNull(username).toTypedArray()
        val rows = jdbcTemplate.query(sql, { rs, _ -> rs.getString("username") to rs.getString("authority") }, *args)
        return rows.groupBy({ it.first }, { it.second }).mapValues { it.value.toSet() }
    }

    private fun requireKnownRoles(roles: Set<String>) {
        val known: Set<String> =
            jdbcTemplate
                .queryForList(
                    "select authority from qsp_auth_authorities",
                    String::class.java,
                ).filterNotNull()
                .toSet()
        val unknown = roles - known
        if (unknown.isNotEmpty()) {
            throw ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown roles: ${unknown.sorted().joinToString()}")
        }
    }

    private fun replaceRoles(
        username: String,
        roles: Set<String>,
    ) {
        jdbcTemplate.update("delete from qsp_auth_user_authorities where username = ?", username)
        roles.forEach {
            jdbcTemplate.update(
                "insert into qsp_auth_user_authorities (username, authority) values (?, ?)",
                username,
                it,
            )
        }
    }
}

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

package fr.f4fez.authorizationserver.config

import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl
import java.time.LocalDateTime

/**
 * Loads users with their password expiration, so that an expired password is rejected at login.
 * The users query must return username, password, enabled and password_expiration, in that order.
 */
class PasswordExpirationAwareJdbcDao : JdbcDaoImpl() {
    override fun loadUsersByUsername(username: String): List<UserDetails> =
        requireNotNull(jdbcTemplate).query(
            usersByUsernameQuery,
            { rs, _ ->
                val passwordExpiration = rs.getTimestamp(4)?.toLocalDateTime()
                User(
                    rs.getString(1),
                    rs.getString(2),
                    rs.getBoolean(3),
                    true,
                    passwordExpiration == null || passwordExpiration.isAfter(LocalDateTime.now()),
                    true,
                    AuthorityUtils.NO_AUTHORITIES,
                )
            },
            username,
        )
}

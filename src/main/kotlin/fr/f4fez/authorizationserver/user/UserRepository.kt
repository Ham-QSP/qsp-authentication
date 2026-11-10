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

import org.springframework.data.jdbc.repository.query.Query
import org.springframework.data.repository.CrudRepository
import java.util.UUID

/**
 * Lookups take identifiers already normalized by [Usernames] and [Emails]; only the stored side is folded,
 * so that a row written in another case is still found.
 */
interface UserRepository : CrudRepository<User, UUID> {
    @Query("select * from qsp_auth_users where upper(username) = :username")
    fun findByNormalizedUsername(username: String): User?

    @Query("select count(*) > 0 from qsp_auth_users where upper(username) = :username")
    fun existsByNormalizedUsername(username: String): Boolean

    @Query("select count(*) > 0 from qsp_auth_users where lower(email) = :email")
    fun existsByNormalizedEmail(email: String): Boolean

    @Query("select * from qsp_auth_users where lower(email) = :email")
    fun findAllByNormalizedEmail(email: String): List<User>
}

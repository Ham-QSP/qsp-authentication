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

import java.util.Locale

/**
 * Usernames are made of ASCII letters, digits and '_', and are stored and compared in uppercase.
 */
object Usernames {
    private val VALID = Regex("[A-Z0-9_]+")

    /**
     * Only ASCII letters are uppercased: folding other characters (ß → SS, ı → I) would let a look-alike
     * reach an existing account.
     */
    fun normalize(username: String): String =
        buildString {
            username.trim().forEach { append(if (it in 'a'..'z') it.uppercaseChar() else it) }
        }

    fun isValid(normalizedUsername: String): Boolean = VALID.matches(normalizedUsername)
}

/**
 * Emails are stored and compared in lowercase.
 */
object Emails {
    fun normalize(email: String): String = email.trim().lowercase(Locale.ROOT)
}

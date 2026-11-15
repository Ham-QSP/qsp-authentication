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
package fr.f4fez.authorizationserver.registration

/**
 * Callsign format accepted at self-registration: ITU-style prefix, digit(s), suffix ending with a letter.
 * Portable suffixes such as "/P" are not part of a login.
 */
object Callsigns {
    private val VALID = Regex("(?:[A-Z]{1,2}|[0-9][A-Z]|[A-Z][0-9])[0-9]{1,4}[A-Z0-9]{0,3}[A-Z]")

    fun isValid(normalizedCallsign: String): Boolean = VALID.matches(normalizedCallsign)
}

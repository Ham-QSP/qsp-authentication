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

import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.ValueSource
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CallsignsTest {
    @ParameterizedTest
    @ValueSource(strings = ["F4FEZ", "K1ABC", "HB9ABC", "2E0ABC", "9A1A", "3D2AG", "TM100XX"])
    fun `accepts legal amateur radio callsigns`(callsign: String) {
        assertTrue(Callsigns.isValid(callsign))
    }

    @ParameterizedTest
    @ValueSource(strings = ["FEZ", "F4_FEZ", "F4FEZ/P", "", "12345", "f4fez", "F4FEZ ", "ABCDE", "F4"])
    fun `rejects anything else`(callsign: String) {
        assertFalse(Callsigns.isValid(callsign))
    }
}

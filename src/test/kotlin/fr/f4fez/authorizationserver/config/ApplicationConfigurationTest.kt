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

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean
import org.springframework.core.io.FileSystemResource
import kotlin.test.assertNotEquals

/**
 * Checks the shipped configuration, which the test configuration in src/test/resources hides from Spring tests.
 */
class ApplicationConfigurationTest {
    private val properties =
        requireNotNull(
            YamlPropertiesFactoryBean()
                .apply { setResources(FileSystemResource("src/main/resources/application.yaml")) }
                .getObject(),
        )

    @Test
    fun `request parameters and headers are never logged, even at DEBUG level`() {
        assertNotEquals("true", properties.getProperty("spring.mvc.log-request-details"))
    }
}

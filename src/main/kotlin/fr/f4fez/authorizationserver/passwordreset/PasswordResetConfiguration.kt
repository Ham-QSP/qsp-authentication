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
package fr.f4fez.authorizationserver.passwordreset

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

@Configuration
class PasswordResetConfiguration {
    companion object {
        const val MAIL_EXECUTOR = "passwordResetMailExecutor"
        private const val QUEUE_CAPACITY = 100
    }

    /** Sending on a background thread keeps the SMTP round trip out of the response time. */
    @Bean(MAIL_EXECUTOR)
    fun passwordResetMailExecutor(properties: PasswordResetProperties): Executor =
        if (properties.asyncMail) {
            ThreadPoolExecutor(
                1,
                2,
                30,
                TimeUnit.SECONDS,
                LinkedBlockingQueue(QUEUE_CAPACITY),
            ) { runnable -> Thread(runnable, "password-reset-mail").apply { isDaemon = true } }
        } else {
            Executor { it.run() }
        }
}

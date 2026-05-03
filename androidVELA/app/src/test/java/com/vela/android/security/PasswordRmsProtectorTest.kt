package com.vela.android.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

class PasswordRmsProtectorTest {
    @Test
    fun passwordWrapAndUnwrapRoundTripsRms() {
        val dir = Files.createTempDirectory("vela-password-rms").toFile()
        val protector = PasswordRmsProtector(dir)
        val rms = ByteArray(32).also { SecureRandom().nextBytes(it) }

        assertFalse(protector.hasWrappedRms())
        protector.wrap(rms, "correct horse battery staple".toCharArray())

        assertTrue(protector.hasWrappedRms())
        assertArrayEquals(rms, protector.unwrap("correct horse battery staple".toCharArray()))
    }

    @Test(expected = AEADBadTagException::class)
    fun wrongPasswordDoesNotUnwrapRms() {
        val dir = Files.createTempDirectory("vela-password-rms-wrong").toFile()
        val protector = PasswordRmsProtector(dir)
        val rms = ByteArray(32).also { SecureRandom().nextBytes(it) }

        protector.wrap(rms, "correct password".toCharArray())
        protector.unwrap("wrong password".toCharArray())
    }
}

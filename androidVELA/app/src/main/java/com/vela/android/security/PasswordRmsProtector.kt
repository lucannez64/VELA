package com.vela.android.security

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

class PasswordRmsProtector(private val storeDir: File) {
    private val blobFile = File(storeDir, "rms_password.blob")

    fun hasWrappedRms(): Boolean = blobFile.exists()

    fun wrap(rms: ByteArray, password: CharArray) {
        val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
        val iv = ByteArray(IV_LEN).also { SecureRandom().nextBytes(it) }
        val key = deriveKey(password, salt)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(rms)

        storeDir.mkdirs()
        DataOutputStream(blobFile.outputStream()).use { out ->
            out.writeInt(VERSION)
            out.writeInt(ITERATIONS)
            out.writeInt(salt.size)
            out.write(salt)
            out.writeInt(iv.size)
            out.write(iv)
            out.writeInt(ciphertext.size)
            out.write(ciphertext)
        }
    }

    fun unwrap(password: CharArray): ByteArray {
        val blob = readBlob()
        val key = deriveKey(password, blob.salt, blob.iterations)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, blob.iv))
        return cipher.doFinal(blob.ciphertext)
    }

    fun delete() {
        blobFile.delete()
    }

    private fun deriveKey(
        password: CharArray,
        salt: ByteArray,
        iterations: Int = ITERATIONS
    ): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, iterations, KEY_BITS)
        val encoded = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
        return SecretKeySpec(encoded, "AES")
    }

    private fun readBlob(): WrappedPasswordBlob {
        DataInputStream(blobFile.inputStream()).use { input ->
            require(input.readInt() == VERSION) { "Unsupported password RMS blob version" }
            // Every field below is length- or cost-bearing and the file is
            // writable by anything that can touch app storage: a corrupted or
            // tampered blob must be rejected, not obeyed. An unclamped
            // iteration count would hang every future unlock on a
            // hours-long KDF with no recovery short of wiping the vault.
            val iterations = input.readInt()
            require(iterations in MIN_ITERATIONS..MAX_ITERATIONS) {
                "Unreasonable PBKDF2 iteration count: $iterations"
            }
            val salt = input.readBounded(SALT_LEN, "salt")
            require(salt.size == SALT_LEN) { "Unexpected salt length: ${salt.size}" }
            val iv = input.readBounded(IV_LEN, "iv")
            require(iv.size == IV_LEN) { "Unexpected iv length: ${iv.size}" }
            val ciphertext = input.readBounded(MAX_CIPHERTEXT_LEN, "ciphertext")
            return WrappedPasswordBlob(iterations, salt, iv, ciphertext)
        }
    }

    /** Reads a length-prefixed array, refusing lengths beyond [maxBytes]. */
    private fun DataInputStream.readBounded(maxBytes: Int, what: String): ByteArray {
        val length = readInt()
        require(length in 0..maxBytes) { "Unreasonable $what length: $length" }
        val bytes = ByteArray(length)
        readFully(bytes)
        return bytes
    }

    private data class WrappedPasswordBlob(
        val iterations: Int,
        val salt: ByteArray,
        val iv: ByteArray,
        val ciphertext: ByteArray
    )

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val VERSION = 1
        private const val ITERATIONS = 210_000
        // Bounds a tampered blob may not exceed (see readBlob). The upper
        // iteration bound still allows deliberately stronger blobs while
        // keeping an unlock bounded to seconds.
        private const val MIN_ITERATIONS = 100_000
        private const val MAX_ITERATIONS = 2_000_000
        private const val KEY_BITS = 256
        private const val SALT_LEN = 16
        private const val IV_LEN = 12
        // The wrapped payload is always a 32-byte RMS; the GCM tag adds 16.
        private const val MAX_CIPHERTEXT_LEN = 128
    }
}

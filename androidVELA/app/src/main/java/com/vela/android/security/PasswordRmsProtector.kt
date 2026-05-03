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
            val iterations = input.readInt()
            val salt = ByteArray(input.readInt())
            input.readFully(salt)
            val iv = ByteArray(input.readInt())
            input.readFully(iv)
            val ciphertext = ByteArray(input.readInt())
            input.readFully(ciphertext)
            return WrappedPasswordBlob(iterations, salt, iv, ciphertext)
        }
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
        private const val KEY_BITS = 256
        private const val SALT_LEN = 16
        private const val IV_LEN = 12
    }
}

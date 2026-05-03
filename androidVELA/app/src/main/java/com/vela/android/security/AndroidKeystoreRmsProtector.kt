package com.vela.android.security

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

class AndroidKeystoreRmsProtector(private val storeDir: File) {
    private val blobFile = File(storeDir, "rms_biometric.blob")

    fun hasWrappedRms(): Boolean = blobFile.exists() && keyExists()

    fun beginWrapCipher(): Cipher {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        return cipher
    }

    fun beginUnwrapCipher(): Cipher {
        val blob = readBlob()
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), javax.crypto.spec.GCMParameterSpec(128, blob.iv))
        return cipher
    }

    fun finishWrap(cipher: Cipher, rms: ByteArray) {
        val ciphertext = cipher.doFinal(rms)
        writeBlob(cipher.iv, ciphertext)
    }

    fun finishUnwrap(cipher: Cipher): ByteArray {
        val blob = readBlob()
        return cipher.doFinal(blob.ciphertext)
    }

    fun delete() {
        blobFile.delete()
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (keyStore.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val specBuilder = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            specBuilder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        keyGenerator.init(specBuilder.build())
        return keyGenerator.generateKey()
    }

    private fun keyExists(): Boolean {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.containsAlias(KEY_ALIAS)
    }

    private fun writeBlob(iv: ByteArray, ciphertext: ByteArray) {
        storeDir.mkdirs()
        DataOutputStream(blobFile.outputStream()).use { out ->
            out.writeInt(VERSION)
            out.writeInt(iv.size)
            out.write(iv)
            out.writeInt(ciphertext.size)
            out.write(ciphertext)
        }
    }

    private fun readBlob(): WrappedBlob {
        DataInputStream(blobFile.inputStream()).use { input ->
            require(input.readInt() == VERSION) { "Unsupported biometric RMS blob version" }
            val iv = ByteArray(input.readInt())
            input.readFully(iv)
            val ciphertext = ByteArray(input.readInt())
            input.readFully(ciphertext)
            return WrappedBlob(iv, ciphertext)
        }
    }

    private data class WrappedBlob(val iv: ByteArray, val ciphertext: ByteArray)

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "VELA_RMS_ANDROID"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val VERSION = 1
    }
}

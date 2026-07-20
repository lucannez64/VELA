package com.vela.android.security

import com.vela.android.core.NativeVelaCore
import com.vela.android.core.VaultJson
import com.vela.android.core.VaultStore
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class EncryptedVaultStore(private val storeDir: File) {
    private val vaultFile = File(storeDir, "vault.enc")

    fun exists(): Boolean = vaultFile.exists()

    fun load(rms: ByteArray): VaultStore {
        if (!vaultFile.exists()) return VaultStore()
        val blob = readBlob()
        if (blob is EncryptedVaultBlob.Native) {
            val vaultJson = NativeVelaCore.decryptVaultJson(rms, blob.payload)
                ?: error("Native VELA bridge is required to decrypt this vault")
            return VaultJson.decode(vaultJson.toByteArray(Charsets.UTF_8))
        }

        blob as EncryptedVaultBlob.Kotlin
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, deriveVaultKey(rms), GCMParameterSpec(128, blob.iv))
        return VaultJson.decode(cipher.doFinal(blob.ciphertext))
    }

    fun save(rms: ByteArray, store: VaultStore) {
        val plaintext = VaultJson.encode(store)
        // KNOWN LIMITATION: `.toString(UTF_8)` below creates an immutable JVM
        // String holding the full decrypted vault (every password, card
        // number, note). Unlike the ByteArray it's derived from, a String
        // cannot be wiped — `plaintext.fill(0)` only zeroes the original
        // array, not this copy, which lingers on the heap until GC reclaims
        // it. Fixing this fully would mean redesigning the JNI bridge to pass
        // raw bytes instead of a JSON-string envelope end-to-end (it's used
        // by every NativeVelaCore call, not just this one) — out of scope
        // here. Exploiting this specific gap requires memory-dump access to
        // this app's process (root / a kernel exploit), a much stronger
        // capability than the sandboxing Android otherwise provides.
        NativeVelaCore.encryptVaultJson(rms, plaintext.toString(Charsets.UTF_8))?.let { ciphertextB64 ->
            plaintext.fill(0)
            writeNativeBlob(java.util.Base64.getDecoder().decode(ciphertextB64))
            return
        }

        val iv = ByteArray(IV_LEN).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, deriveVaultKey(rms), GCMParameterSpec(128, iv))
        val ciphertext = cipher.doFinal(plaintext)
        plaintext.fill(0)
        writeKotlinBlob(iv, ciphertext)
    }

    fun delete() {
        vaultFile.delete()
    }

    private fun deriveVaultKey(rms: ByteArray): SecretKeySpec {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(rms, "HmacSHA256"))
        return SecretKeySpec(mac.doFinal(VAULT_KEY_CONTEXT.toByteArray(Charsets.UTF_8)), "AES")
    }

    private fun writeKotlinBlob(iv: ByteArray, ciphertext: ByteArray) {
        storeDir.mkdirs()
        DataOutputStream(vaultFile.outputStream()).use { out ->
            out.writeInt(VERSION_KOTLIN)
            out.writeInt(iv.size)
            out.write(iv)
            out.writeInt(ciphertext.size)
            out.write(ciphertext)
        }
    }

    private fun writeNativeBlob(payload: ByteArray) {
        storeDir.mkdirs()
        DataOutputStream(vaultFile.outputStream()).use { out ->
            out.writeInt(VERSION_NATIVE)
            out.writeInt(payload.size)
            out.write(payload)
        }
    }

    private fun readBlob(): EncryptedVaultBlob {
        DataInputStream(vaultFile.inputStream()).use { input ->
            return when (val version = input.readInt()) {
                VERSION_KOTLIN -> {
                    val iv = ByteArray(input.readInt())
                    input.readFully(iv)
                    val ciphertext = ByteArray(input.readInt())
                    input.readFully(ciphertext)
                    EncryptedVaultBlob.Kotlin(iv, ciphertext)
                }
                VERSION_NATIVE -> {
                    val payload = ByteArray(input.readInt())
                    input.readFully(payload)
                    EncryptedVaultBlob.Native(payload)
                }
                else -> error("Unsupported vault file version: $version")
            }
        }
    }

    private sealed interface EncryptedVaultBlob {
        data class Kotlin(val iv: ByteArray, val ciphertext: ByteArray) : EncryptedVaultBlob
        data class Native(val payload: ByteArray) : EncryptedVaultBlob
    }

    companion object {
        private const val VERSION_KOTLIN = 1
        private const val VERSION_NATIVE = 2
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val IV_LEN = 12
        private const val VAULT_KEY_CONTEXT = "vela vault encryption v1"
    }
}

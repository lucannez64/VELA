package com.vela.android.security

import java.util.Arrays

/**
 * Synchronized ownership of the in-memory root message secret (RMS).
 *
 * Every read, copy, replacement and zeroization runs under one small monitor.
 * Previously [SecureVaultManager.lock] zeroized the backing array while a
 * concurrent [currentRmsCopy] copied it, so a caller could persist a torn or
 * all-zero 32-byte key and advance rollback floors under the wrong cipher.
 *
 * Semantics a caller may rely on:
 * - [copy] returns a detached snapshot taken while the monitor was held. It is
 *   a coherent key: it is never torn and never observes a concurrent clear.
 * - A snapshot already returned may be used after [clear]. `lock()` therefore
 *   does not cancel in-flight I/O (vault save, chunk decrypt, upload); it only
 *   prevents *new* snapshots. A captured operation may still finish with the
 *   old key. Callers that must refuse a locked session check
 *   [SecureVaultManager.session] before persisting, as the admitted-sync path
 *   already does.
 * - No asynchronous I/O is performed while the monitor is held.
 */
internal class RmsHolder {
    private val monitor = Any()
    private var rms: ByteArray? = null

    fun isUnlocked(): Boolean = synchronized(monitor) { rms != null }

    fun copy(): ByteArray? = synchronized(monitor) { rms?.copyOf() }

    /** Replace the key, zeroizing the previous one, then wipe the caller's input. */
    fun replaceAndWipeInput(imported: ByteArray) {
        try {
            synchronized(monitor) {
                rms?.fill(0)
                rms = imported.copyOf()
            }
        } finally {
            Arrays.fill(imported, 0)
        }
    }

    /** Zeroize the stored key and become locked. */
    fun clear() {
        synchronized(monitor) {
            rms?.fill(0)
            rms = null
        }
    }
}

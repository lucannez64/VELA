package com.vela.android.core

import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class AdmittedChunkFailureTest {
    @Test
    fun legacyUnsealedRefusalBecomesAnActionableMigrationError() {
        // Exact shape produced by callNative wrapping the Rust bridge error.
        val bridge = IllegalStateException(
            "Native VELA bridge call failed: legacy unsealed chunk ciphertext cannot be " +
                "admitted; migrate it through the explicit pre-C-2 path"
        )
        val mapped = mapAdmittedChunkFailure(bridge)
        assertTrue(mapped is VaultChunkNeedsMigrationException)
        assertTrue(mapped.message!!.contains("explicit migration path"))
    }

    @Test
    fun rollbackAndAuthenticationRefusalsAreNotRelabelled() {
        val rollback = IllegalStateException(
            "Native VELA bridge call failed: server returned an older revision of " +
                "vault-data-000000 (clock 3, last seen 7); refusing to admit it"
        )
        assertSame(rollback, mapAdmittedChunkFailure(rollback))
    }
}

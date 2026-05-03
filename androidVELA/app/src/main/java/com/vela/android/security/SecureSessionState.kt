package com.vela.android.security

enum class UnlockProvider {
    Biometric,
    Password
}

data class SecureSessionState(
    val unlocked: Boolean = false,
    val provider: UnlockProvider? = null,
    val hasBiometricVault: Boolean = false,
    val hasPasswordVault: Boolean = false,
    val error: String? = null
)

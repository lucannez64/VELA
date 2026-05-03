package com.vela.android.core

data class SharedCoreStatus(
    val nativeBridgeAvailable: Boolean,
    val version: String?
)

object SharedCore {
    fun status(): SharedCoreStatus =
        SharedCoreStatus(
            nativeBridgeAvailable = NativeVelaCore.isAvailable(),
            version = NativeVelaCore.versionOrNull()
        )
}

package com.vela.android.core

import com.vela.android.sync.IdentityBindingMode
import com.vela.android.sync.SyncSettings
import com.vela.android.sync.bindVerifiedUserId
import com.vela.android.sync.mergeSeenLamports
import com.vela.android.sync.requireMatchingSyncEpoch
import com.vela.android.sync.requireSyncBaselineAccount
import com.vela.android.sync.syncBaselineScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File

/**
 * Bounded exhaustive conformance of the Android sync download/admission path
 * against an independent reference model of the shared Rust sync rules.
 *
 * The reference model ([RefState]) is written from the semantics in
 * `libVELA/vela-sync-policy/src/lib.rs` and
 * `security/assurance/18-mobile-sync-admission.md`; it does not call the code
 * under test. The Android side ([AndroidAdmission]) is a harness around the
 * production Kotlin decisions that are reachable on a plain JVM:
 *
 *  - `requireSyncBaselineAccount` (durable token needs an account pin),
 *  - `requireMatchingSyncEpoch` (the Rust `plan_sync_epoch_match` mobile gate),
 *  - `syncBaselineScope` (server ‖ account ‖ epoch namespace, no empty account),
 *  - `bindVerifiedUserId(EXISTING, …)` (an account switch cannot re-pin),
 *  - `mergeSeenLamports` plus the same merge/max body as
 *    `SyncSettingsStore.recordAdmittedBaselines` (never lower a floor).
 *
 * The JNI admission call is not available off-device. The harness therefore
 * fakes only the native *chunk policy* (sealed header, positive clock, clock
 * not below the per-chunk floor). The native bridge redundantly checks epoch
 * equality too; that check is deliberately not duplicated in the fake so a
 * weakened Kotlin epoch gate is observable by this test.
 *
 * ## Universe and commands
 *
 * One server, accounts `alice`/`bob`, two chunk ids, clocks 0..3, epochs 1..3.
 * Commands model what a malicious or stale server can return to a download:
 * a chunk at (clock, epoch, seal) with `SEALED`/`WRONG_AAD`/`UNSEALED`
 * ciphertext, a manifest-only response, an epoch-adoption offer with/without a
 * bound capsule, a replay of an earlier response, an account switch, a lost
 * account pin, a deliberate local reset, and a delayed stale baseline write.
 *
 * Every sequence up to `VELA_ANDROID_SYNC_DEPTH` (default 3) over the full
 * 99-command alphabet is applied to the model and to the harness. After every
 * step the test compares the accepted/refused verdict, the adopted epoch, every
 * namespaced chunk and manifest floor, and the admitted vault content. A
 * refusal must leave all state byte-identical.
 *
 * At depth 4 the full alphabet is ~96M traces per initial state, so the
 * `VELA_ANDROID_SYNC_DEPTH=4` run additionally explores a documented 29-command
 * reduced alphabet (one chunk id, epoch local/local+1, sealed/unsealed, one
 * account switch, two replay kinds, reset, pin loss, stale write) to depth 4.
 *
 * ## What this is not
 *
 * Bounded executable evidence, not a proof. It does not execute JNI/native
 * crypto, Keystore/EncryptedSharedPreferences, the real filesystem/HTTPS stack,
 * or a second process. It does not model multi-chunk manifest maxima (each
 * chunk response's clock is also its manifest maximum) or crash ordering
 * between vault persistence and floor recording.
 */
class SyncAdmissionModelTest {
    private val server = "https://vault.example"
    private val accountA = "alice"
    private val accountB = "bob"
    private val chunkA = "vault-data-000000"
    private val chunkB = "vault-data-000001"
    private val chunks = listOf(chunkA, chunkB)
    private val clocks = 0..3
    private val epochs = 1..3
    private val accounts = listOf(accountA, accountB)
    private val keyCache = mutableMapOf<Pair<String, Int>, String>()

    private fun implKey(account: String, epoch: Int): String =
        keyCache.getOrPut(account to epoch) {
            syncBaselineScope(server, account, epoch.toLong()).key
        }

    // ── Reference model (independent of the Android code) ──────────────────

    private enum class Seal { SEALED, WRONG_AAD, UNSEALED }

    private enum class Capsule { BOUND, ABSENT, FOREIGN }

    private enum class Verdict { ACCEPTED, REFUSED, APPLIED }

    private enum class ReplayKind { LAST, FIRST, LAST_ACCEPTED }

    private sealed interface Cmd {
        val kind: String

        data class Chunk(
            val chunkId: String,
            val clock: Int,
            val epoch: Int,
            val seal: Seal,
        ) : Cmd {
            override val kind: String get() = "Chunk"
        }

        data class Manifest(val clock: Int) : Cmd {
            override val kind: String get() = "Manifest"
        }

        data class EpochOffer(val epoch: Int, val capsule: Capsule) : Cmd {
            override val kind: String get() = "EpochOffer"
        }

        data class Replay(val replay: ReplayKind) : Cmd {
            override val kind: String get() = "Replay"
        }

        data class AccountSwitch(val account: String) : Cmd {
            override val kind: String get() = "AccountSwitch"
        }

        data object LosePin : Cmd {
            override val kind: String get() = "LosePin"
        }

        data class Reset(val account: String) : Cmd {
            override val kind: String get() = "Reset"
        }

        data class StaleRecord(val chunkId: String, val clock: Int) : Cmd {
            override val kind: String get() = "StaleRecord"
        }
    }

    /** A namespaced baseline context, independently represented. */
    private data class Scope(val account: String, val epoch: Int)

    private data class RefState(
        val epoch: Int,
        val pinned: String?,
        val floors: Map<Scope, Map<String, Int>>,
        val manifestFloors: Map<Scope, Int>,
        val vault: Map<String, Int>,
    ) {
        companion object {
            fun initial(
                epoch: Int,
                pinned: String?,
                floors: Map<Scope, Map<String, Int>> = emptyMap(),
                manifestFloors: Map<Scope, Int> = emptyMap(),
            ): RefState = RefState(epoch, pinned, floors, manifestFloors, emptyMap())
        }
    }

    private data class RefResult(val state: RefState, val verdict: Verdict)

    /**
     * The Rust rules, stated independently:
     *
     *  - a download needs a pinned account (missing pin is not an empty
     *    namespace), the manifest epoch equal to the local positive epoch, a
     *    sealed ciphertext that opened under the expected AAD, a positive
     *    clock, and a clock at least the recorded per-chunk and manifest floors;
     *  - floors are namespaced by (account, epoch) and only ever rise;
     *  - a rotation is adopted only when it is exactly local+1 *and* a capsule
     *    bound to that transition is present (the mobile download path adopts
     *    nothing; see [adoptionLadderNeverAdoptsRollbackOrJump]).
     */
    private fun RefState.apply(command: Cmd): RefResult {
        when (command) {
            is Cmd.Chunk -> {
                val pin = pinned ?: return refused()
                if (command.epoch != epoch || command.epoch < 1) return refused()
                if (command.seal == Seal.UNSEALED) return refused()
                if (command.seal == Seal.WRONG_AAD) return refused()
                if (command.clock < 1) return refused()
                val scope = Scope(pin, epoch)
                val manifestFloor = manifestFloors[scope]
                if (manifestFloor != null && command.clock < manifestFloor) return refused()
                val chunkFloor = floors[scope]?.get(command.chunkId)
                if (chunkFloor != null && command.clock < chunkFloor) return refused()
                val nextChunks = floors[scope].orEmpty() +
                    (command.chunkId to maxOf(chunkFloor ?: 0, command.clock))
                return accepted(
                    copy(
                        floors = floors + (scope to nextChunks),
                        manifestFloors =
                            manifestFloors + (scope to maxOf(manifestFloor ?: 0, command.clock)),
                        vault = vault + (command.chunkId to command.clock),
                    )
                )
            }

            is Cmd.Manifest -> {
                val pin = pinned ?: return refused()
                if (command.clock < 0) return refused()
                val scope = Scope(pin, epoch)
                val manifestFloor = manifestFloors[scope]
                if (manifestFloor != null && command.clock < manifestFloor) return refused()
                // The manifest gate itself records nothing; only an admitted write does.
                return RefResult(this, Verdict.ACCEPTED)
            }

            is Cmd.EpochOffer -> {
                pinned ?: return refused()
                if (command.epoch < 1) return refused()
                // `plan_sync_epoch_match`: mobile downloads never adopt a rotation.
                if (command.epoch != epoch) return refused()
                return RefResult(this, Verdict.ACCEPTED)
            }

            is Cmd.AccountSwitch -> {
                val pin = pinned ?: return refused()
                if (pin != command.account) return refused()
                return RefResult(this, Verdict.ACCEPTED)
            }

            Cmd.LosePin -> return RefResult(copy(pinned = null), Verdict.APPLIED)

            is Cmd.Reset -> return RefResult(
                RefState(
                    epoch = epoch,
                    pinned = command.account,
                    floors = emptyMap(),
                    manifestFloors = emptyMap(),
                    vault = emptyMap(),
                ),
                Verdict.APPLIED,
            )

            is Cmd.StaleRecord -> {
                val pin = pinned ?: return RefResult(this, Verdict.APPLIED)
                val scope = Scope(pin, epoch)
                val floor = floors[scope]?.get(command.chunkId) ?: 0
                val manifestFloor = manifestFloors[scope] ?: 0
                val nextChunks =
                    if (command.clock > floor) {
                        floors[scope].orEmpty() + (command.chunkId to command.clock)
                    } else {
                        floors[scope].orEmpty()
                    }
                val nextManifest = maxOf(manifestFloor, command.clock)
                return RefResult(
                    copy(
                        floors = if (nextChunks.isEmpty()) floors else floors + (scope to nextChunks),
                        manifestFloors =
                            if (nextManifest <= 0) manifestFloors
                            else manifestFloors + (scope to nextManifest),
                    ),
                    Verdict.APPLIED,
                )
            }

            is Cmd.Replay -> error("replays are resolved before the model is applied")
        }
    }

    private fun RefState.refused(): RefResult = RefResult(this, Verdict.REFUSED)

    private fun RefState.accepted(next: RefState): RefResult =
        RefResult(next, Verdict.ACCEPTED)

    // ── Android path harness (uses the production Kotlin decisions) ────────

    private data class ImplState(
        val settings: SyncSettings,
        val pinned: String?,
        val vault: Map<String, Int>,
    )

    private fun initialImpl(
        epoch: Int,
        pinned: String?,
        floors: Map<String, Map<String, Long>> = emptyMap(),
        manifestFloors: Map<String, Long> = emptyMap(),
    ): ImplState = ImplState(
        settings = SyncSettings(
            serverUrl = server,
            bearerToken = "durable-token",
            keyEpoch = epoch.toLong(),
            seenLamportByContext = floors,
            manifestLamportByContext = manifestFloors,
        ),
        pinned = pinned,
        vault = emptyMap(),
    )

    private inner class AndroidAdmission(initial: ImplState) {
        var state: ImplState = initial
            private set

        fun restore(snapshot: ImplState) {
            state = snapshot
        }

        /**
         * Apply one command. A refusal is represented by a thrown exception
         * from a production gate (or the faked native policy); state must be
         * untouched in that case.
         */
        fun apply(command: Cmd, replayTarget: Cmd.Chunk?): Verdict {
            val before = state
            val verdict = try {
                when (command) {
                    is Cmd.Replay ->
                        if (replayTarget == null) Verdict.APPLIED else download(replayTarget)

                    is Cmd.Chunk -> download(command)
                    is Cmd.Manifest -> manifest(command)
                    is Cmd.EpochOffer -> epochOffer(command)
                    is Cmd.AccountSwitch -> accountSwitch(command)
                    Cmd.LosePin -> {
                        state = state.copy(pinned = null)
                        Verdict.APPLIED
                    }

                    is Cmd.Reset -> {
                        state = state.copy(
                            settings = state.settings.copy(
                                seenLamportByContext = emptyMap(),
                                manifestLamportByContext = emptyMap(),
                            ),
                            pinned = command.account,
                            vault = emptyMap(),
                        )
                        Verdict.APPLIED
                    }

                    is Cmd.StaleRecord -> {
                        if (state.pinned == null) {
                            // A delayed write can only carry a scope that was
                            // computed while the pin was still readable.
                            Verdict.APPLIED
                        } else {
                            staleRecord(command)
                            Verdict.APPLIED
                        }
                    }
                }
            } catch (_: Exception) {
                Verdict.REFUSED
            }
            if (verdict == Verdict.REFUSED && state != before) {
                error("a refused command mutated the Android admission state")
            }
            return verdict
        }

        /** The pre-request gate: a durable token may not use an unknown account. */
        private fun pinnedAccount(): String {
            val account = requireSyncBaselineAccount(
                hasDurableToken = state.settings.bearerToken.isNotBlank(),
                pinnedUserId = state.pinned,
            )
            return requireNotNull(account) { "durable token must have a pin" }
        }

        private fun download(command: Cmd.Chunk): Verdict {
            val account = pinnedAccount()
            requireMatchingSyncEpoch(command.epoch.toLong(), state.settings.keyEpoch)
            val scope = syncBaselineScope(server, account, state.settings.keyEpoch)
            check(!state.settings.baselineCorrupt) { "unreadable baseline" }

            // Whole-manifest rollback gate (`VaultSyncManager.rejectRollback`).
            val lastSeen = state.settings.manifestLamportByContext[scope.key]
            if (lastSeen != null && lastSeen > 0 && command.clock.toLong() < lastSeen) {
                error("manifest rollback")
            }

            // Faked JNI chunk policy: sealed header, positive clock, per-chunk
            // floor. Epoch equality is intentionally attributed to the Kotlin
            // gate above; the real Rust bridge also checks it.
            if (command.seal == Seal.UNSEALED) error("legacy unsealed chunk")
            if (command.seal == Seal.WRONG_AAD) error("AAD mismatch")
            if (command.clock < 1) error("nonpositive clock")
            val chunkSeen = state.settings.seenLamportByContext[scope.key]?.get(command.chunkId)
            if (chunkSeen != null && command.clock.toLong() < chunkSeen) {
                error("chunk rollback")
            }

            state = state.copy(
                settings = record(
                    state.settings,
                    scope,
                    mapOf(command.chunkId to command.clock.toLong()),
                    command.clock.toLong(),
                ),
                vault = state.vault + (command.chunkId to command.clock),
            )
            return Verdict.ACCEPTED
        }

        private fun manifest(command: Cmd.Manifest): Verdict {
            val account = pinnedAccount()
            require(state.settings.keyEpoch >= 1) { "epoch must be positive" }
            val scope = syncBaselineScope(server, account, state.settings.keyEpoch)
            val lastSeen = state.settings.manifestLamportByContext[scope.key]
            if (lastSeen != null && lastSeen > 0 && command.clock.toLong() < lastSeen) {
                error("manifest rollback")
            }
            return Verdict.ACCEPTED
        }

        private fun epochOffer(command: Cmd.EpochOffer): Verdict {
            pinnedAccount()
            requireMatchingSyncEpoch(command.epoch.toLong(), state.settings.keyEpoch)
            return Verdict.ACCEPTED
        }

        private fun accountSwitch(command: Cmd.AccountSwitch): Verdict {
            bindVerifiedUserId(IdentityBindingMode.EXISTING, state.pinned, command.account)
            state = state.copy(pinned = command.account)
            return Verdict.ACCEPTED
        }

        private fun staleRecord(command: Cmd.StaleRecord) {
            val account = pinnedAccount()
            val scope = syncBaselineScope(server, account, state.settings.keyEpoch)
            state = state.copy(
                settings = record(
                    state.settings,
                    scope,
                    mapOf(command.chunkId to command.clock.toLong()),
                    command.clock.toLong(),
                )
            )
        }

        /**
         * The body of `SyncSettingsStore.recordAdmittedBaselines`, kept in
         * step with it: merge chunk floors by max, take the max manifest
         * floor, and refuse to overwrite an unreadable baseline.
         */
        private fun record(
            current: SyncSettings,
            scope: com.vela.android.sync.SyncBaselineScope,
            chunkClocks: Map<String, Long>,
            manifestClock: Long,
        ): SyncSettings {
            if (chunkClocks.isEmpty() && manifestClock <= 0) return current
            check(!current.baselineCorrupt)
            val mergedChunks = mergeSeenLamports(
                current.seenLamportByContext[scope.key].orEmpty(),
                chunkClocks,
            )
            val mergedManifest = maxOf(
                current.manifestLamportByContext[scope.key] ?: 0,
                manifestClock,
            )
            return current.copy(
                seenLamportByContext =
                    if (mergedChunks.isEmpty()) current.seenLamportByContext
                    else current.seenLamportByContext + (scope.key to mergedChunks),
                manifestLamportByContext =
                    if (mergedManifest <= 0) current.manifestLamportByContext
                    else current.manifestLamportByContext + (scope.key to mergedManifest),
            )
        }
    }

    // ── Alphabet and exploration ───────────────────────────────────────────

    private fun fullAlphabet(): List<Cmd> = buildList {
        for (chunk in chunks) {
            for (clock in clocks) {
                for (epoch in epochs) {
                    for (seal in Seal.entries) add(Cmd.Chunk(chunk, clock, epoch, seal))
                }
            }
        }
        for (clock in clocks) add(Cmd.Manifest(clock))
        for (epoch in epochs) {
            for (capsule in Capsule.entries) add(Cmd.EpochOffer(epoch, capsule))
        }
        for (replay in ReplayKind.entries) add(Cmd.Replay(replay))
        for (account in accounts) add(Cmd.AccountSwitch(account))
        add(Cmd.LosePin)
        for (account in accounts) add(Cmd.Reset(account))
        for (chunk in chunks) {
            for (clock in 1..3) add(Cmd.StaleRecord(chunk, clock))
        }
    }

    /** Documented reduced alphabet for the optional depth-4 run. */
    private fun deepAlphabet(): List<Cmd> = buildList {
        for (clock in clocks) {
            for (epoch in listOf(1, 2)) {
                for (seal in listOf(Seal.SEALED, Seal.UNSEALED)) {
                    add(Cmd.Chunk(chunkA, clock, epoch, seal))
                }
            }
        }
        for (clock in listOf(0, 1, 3)) add(Cmd.Manifest(clock))
        add(Cmd.Chunk(chunkA, 2, 1, Seal.WRONG_AAD))
        for (epoch in listOf(1, 2)) {
            for (capsule in listOf(Capsule.BOUND, Capsule.ABSENT)) {
                add(Cmd.EpochOffer(epoch, capsule))
            }
        }
        add(Cmd.Replay(ReplayKind.LAST))
        add(Cmd.Replay(ReplayKind.LAST_ACCEPTED))
        add(Cmd.AccountSwitch(accountA))
        add(Cmd.LosePin)
        add(Cmd.Reset(accountB))
        add(Cmd.StaleRecord(chunkA, 1))
    }

    private data class HistoryEntry(val command: Cmd.Chunk, val accepted: Boolean)

    private fun replayTarget(command: Cmd, history: List<HistoryEntry>): Cmd.Chunk? =
        when (command) {
            is Cmd.Replay -> when (command.replay) {
                ReplayKind.LAST -> history.lastOrNull()?.command
                ReplayKind.FIRST -> history.firstOrNull()?.command
                ReplayKind.LAST_ACCEPTED -> history.lastOrNull { it.accepted }?.command
            }

            else -> null
        }

    private class Coverage {
        val verdicts = mutableMapOf<Pair<String, Verdict>, Int>()
        var sealedAccepted = 0
        var wrongAadRefused = 0
        var unsealedRefused = 0
        var clockZeroRefused = 0
        var clockPositiveAccepted = 0
        var epochEqualAccepted = 0
        var epochRollbackRefused = 0
        var epochJumpRefused = 0
        var chunkRollbackRefused = 0
        var equalClockAccepted = 0
        var manifestRollbackRefused = 0
        var replayAccepted = 0
        var replayRefused = 0
        var accountSwitchAccepted = 0
        var accountSwitchRefused = 0
        var missingPinRefused = 0
        var crossAccountRefused = 0
        var refusedUnchanged = 0
        var vaultWrites = 0
        val acceptedEpochs = mutableSetOf<Int>()

        fun record(kind: String, verdict: Verdict) {
            verdicts[kind to verdict] = (verdicts[kind to verdict] ?: 0) + 1
        }

        fun count(kind: String, verdict: Verdict): Int = verdicts[kind to verdict] ?: 0
    }

    private fun requestedDepth(): Int =
        (System.getenv("VELA_ANDROID_SYNC_DEPTH")
            ?: System.getProperty("VELA_ANDROID_SYNC_DEPTH"))
            ?.trim()?.toIntOrNull() ?: 3

    private fun initialPair(
        epoch: Int,
        pinned: String?,
        chunkFloors: Map<String, Long> = emptyMap(),
        manifestFloor: Long? = null,
    ): Pair<ImplState, RefState> {
        val impl = initialImpl(
            epoch = epoch,
            pinned = pinned,
            floors = if (pinned == null || chunkFloors.isEmpty()) {
                emptyMap()
            } else {
                mapOf(implKey(pinned, epoch) to chunkFloors)
            },
            manifestFloors = if (pinned == null || manifestFloor == null) {
                emptyMap()
            } else {
                mapOf(implKey(pinned, epoch) to manifestFloor)
            },
        )
        val ref = RefState.initial(
            epoch = epoch,
            pinned = pinned,
            floors = if (pinned == null || chunkFloors.isEmpty()) {
                emptyMap()
            } else {
                mapOf(
                    Scope(pinned, epoch) to
                        chunkFloors.mapValues { it.value.toInt() }
                )
            },
            manifestFloors = if (pinned == null || manifestFloor == null) {
                emptyMap()
            } else {
                mapOf(Scope(pinned, epoch) to manifestFloor.toInt())
            },
        )
        return impl to ref
    }

    private fun explore(
        label: String,
        depth: Int,
        alphabet: List<Cmd>,
        initials: List<Pair<ImplState, RefState>>,
        expectedEpochs: Set<Int> = setOf(1, 2, 3),
    ) {
        val coverage = Coverage()
        var traces = 0L
        var steps = 0L

        for ((initial, startRef) in initials) {
            val startImpl = AndroidAdmission(initial)
            exploreFrom(
                label = label,
                depth = depth,
                alphabet = alphabet,
                ref = startRef,
                impl = startImpl,
                history = emptyList(),
                step = 0,
                coverage = coverage,
                onTrace = { traces++ },
                onStep = { steps++ },
            )
        }

        val expectedTraces = initials.size.toLong() * pow(alphabet.size.toLong(), depth)
        val expectedSteps = initials.size.toLong() * expectedStepCount(alphabet.size.toLong(), depth)
        assertTrue(
            "$label explored only $traces of $expectedTraces traces",
            traces == expectedTraces,
        )
        assertTrue(
            "$label explored only $steps of $expectedSteps steps",
            steps == expectedSteps,
        )
        assertNonVacuous(label, coverage, expectedEpochs)

        val summary = buildString {
            appendLine("$label")
            appendLine("  alphabet=${alphabet.size} depth=$depth initialStates=${initials.size}")
            appendLine("  traces=$traces steps=$steps")
            appendLine("  verdicts=${coverage.verdicts.toSortedMap(compareBy({ it.first }, { it.second }))}")
            appendLine("  sealedAccepted=${coverage.sealedAccepted} vaultWrites=${coverage.vaultWrites}")
            appendLine("  refusedUnchanged=${coverage.refusedUnchanged} missingPinRefused=${coverage.missingPinRefused}")
            appendLine("  epochEqualAccepted=${coverage.epochEqualAccepted}")
            appendLine("  epochRollbackRefused=${coverage.epochRollbackRefused} epochJumpRefused=${coverage.epochJumpRefused}")
            appendLine("  chunkRollbackRefused=${coverage.chunkRollbackRefused} equalClockAccepted=${coverage.equalClockAccepted}")
            appendLine("  manifestRollbackRefused=${coverage.manifestRollbackRefused}")
            appendLine("  replayAccepted=${coverage.replayAccepted} replayRefused=${coverage.replayRefused}")
            appendLine("  accountSwitchAccepted=${coverage.accountSwitchAccepted} accountSwitchRefused=${coverage.accountSwitchRefused} crossAccountRefused=${coverage.crossAccountRefused}")
            appendLine("  acceptedEpochs=${coverage.acceptedEpochs}")
        }
        println(summary)
        writeEvidence("$label.txt", summary)
    }

    private fun exploreFrom(
        label: String,
        depth: Int,
        alphabet: List<Cmd>,
        ref: RefState,
        impl: AndroidAdmission,
        history: List<HistoryEntry>,
        step: Int,
        coverage: Coverage,
        onTrace: () -> Unit,
        onStep: () -> Unit,
    ) {
        if (step == depth) {
            onTrace()
            return
        }
        for (command in alphabet) {
            val target = if (command is Cmd.Chunk) command else replayTarget(command, history)
            val beforeRef = ref
            val beforeImpl = impl.state

            val expected = when {
                command is Cmd.Replay ->
                    if (target == null) RefResult(ref, Verdict.APPLIED) else ref.apply(target)

                else -> ref.apply(command)
            }
            val actual = impl.apply(command, target)
            onStep()

            if (expected.verdict != actual) {
                fail(
                    "$label: verdict mismatch at step ${step + 1} of $history " +
                        "command=$command target=$target expected=${expected.verdict} actual=$actual"
                )
            }
            assertConforms(
                label = label,
                step = step,
                command = command,
                target = target,
                beforeRef = beforeRef,
                beforeImpl = beforeImpl,
                expected = expected,
                actual = actual,
                impl = impl,
            )
            classify(command, target, beforeImpl, actual, coverage)

            val nextHistory =
                if (command is Cmd.Chunk) {
                    history + HistoryEntry(command, actual == Verdict.ACCEPTED)
                } else {
                    history
                }
            exploreFrom(
                label,
                depth,
                alphabet,
                expected.state,
                impl,
                nextHistory,
                step + 1,
                coverage,
                onTrace,
                onStep,
            )
            impl.restore(beforeImpl)
        }
    }

    private fun assertConforms(
        label: String,
        step: Int,
        command: Cmd,
        target: Cmd.Chunk?,
        beforeRef: RefState,
        beforeImpl: ImplState,
        expected: RefResult,
        actual: Verdict,
        impl: AndroidAdmission,
    ) {
        val now = impl.state
        if (expected.state.epoch != now.settings.keyEpoch.toInt()) {
            fail("$label step ${step + 1} $command: epoch ${expected.state.epoch} != ${now.settings.keyEpoch}")
        }
        if (expected.state.pinned != now.pinned) {
            fail("$label step ${step + 1} $command: pin ${expected.state.pinned} != ${now.pinned}")
        }
        if (expected.state.vault != now.vault) {
            fail("$label step ${step + 1} $command: vault ${expected.state.vault} != ${now.vault}")
        }
        if (!floorsMatch(expected.state, now)) {
            fail(
                "$label step ${step + 1} $command: chunk floors " +
                    "${expectedFloors(expected.state)} != ${now.settings.seenLamportByContext}"
            )
        }
        if (!manifestFloorsMatch(expected.state, now)) {
            fail(
                "$label step ${step + 1} $command: manifest floors " +
                    "${expectedManifestFloors(expected.state)} != ${now.settings.manifestLamportByContext}"
            )
        }
        if (actual == Verdict.REFUSED && now != beforeImpl) {
            fail("$label step ${step + 1} $command: refusal mutated state $beforeImpl -> $now")
        }
        assertFloorsNeverDecrease(label, step, command, beforeImpl, now)
        // The reference model must also keep its own floors monotonic, except
        // for the one documented deliberate transition: a local-security reset
        // clears every context.
        assertRefFloorsNeverDecrease(label, step, command, beforeRef, expected.state)
        // The adopted epoch may only be an explicit local+1 transition with a
        // bound capsule, and the mobile download path adopts nothing at all.
        if (expected.state.epoch != beforeRef.epoch) {
            fail("$label step ${step + 1} $command: the download path adopted an epoch")
        }
        if (actual == Verdict.ACCEPTED && target != null &&
            target.epoch != now.settings.keyEpoch.toInt()
        ) {
            fail("$label step ${step + 1} $command: admitted a chunk at epoch ${target.epoch}")
        }
    }

    private fun floorsMatch(ref: RefState, impl: ImplState): Boolean {
        val actual = impl.settings.seenLamportByContext
        if (ref.floors.isEmpty()) return actual.isEmpty()
        if (ref.floors.size != actual.size) return false
        for ((scope, floors) in ref.floors) {
            val got = actual[implKey(scope.account, scope.epoch)] ?: return false
            if (got.size != floors.size) return false
            for ((chunk, clock) in floors) {
                if (got[chunk] != clock.toLong()) return false
            }
        }
        return true
    }

    private fun manifestFloorsMatch(ref: RefState, impl: ImplState): Boolean {
        val actual = impl.settings.manifestLamportByContext
        if (ref.manifestFloors.isEmpty()) return actual.isEmpty()
        if (ref.manifestFloors.size != actual.size) return false
        for ((scope, clock) in ref.manifestFloors) {
            if (actual[implKey(scope.account, scope.epoch)] != clock.toLong()) return false
        }
        return true
    }

    private fun expectedFloors(ref: RefState): Map<String, Map<String, Long>> =
        ref.floors.entries.associate { (scope, floors) ->
            implKey(scope.account, scope.epoch) to floors.mapValues { it.value.toLong() }
        }

    private fun expectedManifestFloors(ref: RefState): Map<String, Long> =
        ref.manifestFloors.entries.associate { (scope, clock) ->
            implKey(scope.account, scope.epoch) to clock.toLong()
        }

    private fun assertFloorsNeverDecrease(
        label: String,
        step: Int,
        command: Cmd,
        before: ImplState,
        after: ImplState,
    ) {
        // A deliberate local-security reset is the documented exception: it
        // starts a fresh context and clears every floor (MainActivity onReset ->
        // SyncSettingsStore.clearBaselines). No server response may do this.
        if (command is Cmd.Reset) return
        for ((scope, floors) in before.settings.seenLamportByContext) {
            for ((chunk, floor) in floors) {
                val now = after.settings.seenLamportByContext[scope]?.get(chunk)
                if (now == null || now < floor) {
                    fail("$label step ${step + 1} $command: chunk floor $scope/$chunk lowered $floor -> $now")
                }
            }
        }
        for ((scope, floor) in before.settings.manifestLamportByContext) {
            val now = after.settings.manifestLamportByContext[scope]
            if (now == null || now < floor) {
                fail("$label step ${step + 1} $command: manifest floor $scope lowered $floor -> $now")
            }
        }
    }

    private fun assertRefFloorsNeverDecrease(
        label: String,
        step: Int,
        command: Cmd,
        before: RefState,
        after: RefState,
    ) {
        if (command is Cmd.Reset) return
        for ((scope, floors) in before.floors) {
            for ((chunk, floor) in floors) {
                val now = after.floors[scope]?.get(chunk)
                if (now == null || now < floor) {
                    fail("$label step ${step + 1} $command: model floor lowered")
                }
            }
        }
    }

    private fun classify(
        command: Cmd,
        target: Cmd.Chunk?,
        before: ImplState,
        actual: Verdict,
        coverage: Coverage,
    ) {
        coverage.record(command.kind, actual)
        if (actual == Verdict.REFUSED) coverage.refusedUnchanged++
        val chunk = target
        if (chunk != null) {
            val local = before.settings.keyEpoch.toInt()
            if (actual == Verdict.ACCEPTED) {
                coverage.acceptedEpochs += chunk.epoch
                coverage.vaultWrites++
                if (chunk.seal == Seal.SEALED) coverage.sealedAccepted++
                if (chunk.clock >= 1) coverage.clockPositiveAccepted++
                if (chunk.epoch == local) {
                    coverage.epochEqualAccepted++
                    val floor = before.settings
                        .seenLamportByContext[
                            syncBaselineScope(server, requireNotNull(before.pinned), before.settings.keyEpoch).key
                        ]?.get(chunk.chunkId)
                    if (floor != null && floor == chunk.clock.toLong()) {
                        coverage.equalClockAccepted++
                    }
                }
            } else if (actual == Verdict.REFUSED) {
                if (before.pinned == null) coverage.missingPinRefused++
                when (chunk.seal) {
                    Seal.WRONG_AAD -> coverage.wrongAadRefused++
                    Seal.UNSEALED -> coverage.unsealedRefused++
                    Seal.SEALED -> Unit
                }
                if (chunk.clock == 0) coverage.clockZeroRefused++
                if (chunk.seal == Seal.SEALED && before.pinned != null) {
                    if (chunk.epoch < local) coverage.epochRollbackRefused++
                    if (chunk.epoch > local) coverage.epochJumpRefused++
                    if (chunk.epoch == local) {
                        val scope = syncBaselineScope(
                            server,
                            requireNotNull(before.pinned),
                            before.settings.keyEpoch,
                        )
                        val chunkFloor = before.settings.seenLamportByContext[scope.key]
                            ?.get(chunk.chunkId)
                        val manifestFloor =
                            before.settings.manifestLamportByContext[scope.key]
                        if (manifestFloor != null && chunk.clock.toLong() < manifestFloor) {
                            coverage.manifestRollbackRefused++
                        } else if (chunkFloor != null && chunk.clock.toLong() < chunkFloor) {
                            coverage.chunkRollbackRefused++
                        }
                    }
                }
            }
            if (command is Cmd.Replay) {
                if (actual == Verdict.ACCEPTED) coverage.replayAccepted++
                if (actual == Verdict.REFUSED) coverage.replayRefused++
            }
        }
        if (command is Cmd.Manifest && actual == Verdict.REFUSED && before.pinned != null) {
            val scope = syncBaselineScope(
                server,
                requireNotNull(before.pinned),
                before.settings.keyEpoch,
            )
            val floor = before.settings.manifestLamportByContext[scope.key]
            if (floor != null && command.clock.toLong() < floor) {
                coverage.manifestRollbackRefused++
            }
        }
        if (command is Cmd.AccountSwitch) {
            if (actual == Verdict.ACCEPTED) coverage.accountSwitchAccepted++
            if (actual == Verdict.REFUSED) {
                coverage.accountSwitchRefused++
                if (before.pinned != null && before.pinned != command.account) {
                    coverage.crossAccountRefused++
                }
            }
        }
    }

    private fun assertNonVacuous(
        label: String,
        coverage: Coverage,
        expectedEpochs: Set<Int>,
    ) {
        for (kind in listOf("Chunk", "Manifest", "EpochOffer", "Replay", "AccountSwitch")) {
            assertTrue(
                "$label: $kind was never accepted: ${coverage.verdicts}",
                coverage.count(kind, Verdict.ACCEPTED) > 0,
            )
            assertTrue(
                "$label: $kind was never refused: ${coverage.verdicts}",
                coverage.count(kind, Verdict.REFUSED) > 0,
            )
        }
        for (kind in listOf("LosePin", "Reset", "StaleRecord")) {
            assertTrue(
                "$label: $kind was never applied: ${coverage.verdicts}",
                coverage.count(kind, Verdict.APPLIED) > 0,
            )
        }
        assertTrue("$label: no sealed chunk was accepted", coverage.sealedAccepted > 0)
        assertTrue("$label: wrong-AAD ciphertext was never refused", coverage.wrongAadRefused > 0)
        assertTrue("$label: unsealed ciphertext was never refused", coverage.unsealedRefused > 0)
        assertTrue("$label: clock 0 was never refused", coverage.clockZeroRefused > 0)
        assertTrue("$label: a positive clock was never accepted", coverage.clockPositiveAccepted > 0)
        assertTrue("$label: equal epoch was never accepted", coverage.epochEqualAccepted > 0)
        assertTrue("$label: older epoch was never refused", coverage.epochRollbackRefused > 0)
        assertTrue("$label: skipped epoch was never refused", coverage.epochJumpRefused > 0)
        assertTrue("$label: chunk rollback was never refused", coverage.chunkRollbackRefused > 0)
        assertTrue("$label: equal-clock redelivery was never accepted", coverage.equalClockAccepted > 0)
        assertTrue(
            "$label: whole-manifest rollback was never refused",
            coverage.manifestRollbackRefused > 0,
        )
        assertTrue("$label: replay was never accepted", coverage.replayAccepted > 0)
        assertTrue("$label: replay was never refused", coverage.replayRefused > 0)
        assertTrue(
            "$label: account switch was never accepted",
            coverage.accountSwitchAccepted > 0,
        )
        assertTrue(
            "$label: account switch was never refused",
            coverage.accountSwitchRefused > 0,
        )
        assertTrue(
            "$label: cross-account switch was never refused",
            coverage.crossAccountRefused > 0,
        )
        assertTrue("$label: a missing pin was never refused", coverage.missingPinRefused > 0)
        assertTrue("$label: refusals were never exercised", coverage.refusedUnchanged > 0)
        assertTrue("$label: no chunk ever reached the vault", coverage.vaultWrites > 0)
        assertEquals(
            "$label: not every local epoch admitted a chunk",
            expectedEpochs,
            coverage.acceptedEpochs,
        )
    }

    private fun pow(base: Long, exponent: Int): Long {
        var result = 1L
        repeat(exponent) { result *= base }
        return result
    }

    /** Number of applied commands in all sequences of length 1..depth. */
    private fun expectedStepCount(base: Long, depth: Int): Long {
        var result = 0L
        var power = 1L
        for (length in 1..depth) {
            power *= base
            result += power
        }
        return result
    }

    // ── Exhaustive bounded traces ──────────────────────────────────────────

    @Test
    fun everyBoundedSyncTraceMatchesTheReferenceModel() {
        val depth = minOf(requestedDepth(), 3)
        explore(
            label = "full",
            depth = depth,
            alphabet = fullAlphabet(),
            initials = listOf(
                initialPair(1, accountA),
                initialPair(2, accountA),
                initialPair(3, accountA),
                initialPair(1, null),
                // A recorded per-chunk floor without a whole-manifest floor:
                // the per-chunk gate must refuse independently of the manifest.
                initialPair(1, accountA, chunkFloors = mapOf(chunkA to 2L)),
            ),
        )
    }

    /**
     * Optional deeper run: `VELA_ANDROID_SYNC_DEPTH=4`. The full alphabet is
     * too large for depth 4, so this explores a documented reduced alphabet.
     * The full alphabet is still explored to depth 3 above in the same run.
     */
    @Test
    fun reducedAlphabetDepthFourMatchesTheReferenceModel() {
        val requested = requestedDepth()
        assumeTrue("set VELA_ANDROID_SYNC_DEPTH=4 to run the depth-4 exploration", requested >= 4)
        explore(
            label = "deep",
            depth = requested,
            alphabet = deepAlphabet(),
            initials = listOf(
                initialPair(1, accountA),
                initialPair(2, accountA),
                initialPair(1, accountA, chunkFloors = mapOf(chunkA to 2L)),
            ),
            expectedEpochs = setOf(1, 2),
        )
    }

    // ── Focused properties ─────────────────────────────────────────────────

    private enum class Adoption { KEEP, FETCH, ADOPT, REJECT }

    /** `plan_epoch_adoption`'s ladder, written independently. */
    private fun adoption(local: Int, offered: Int, capsule: Capsule): Adoption = when {
        local < 1 || offered < 1 -> Adoption.REJECT
        offered == local -> Adoption.KEEP
        offered != local + 1 -> Adoption.REJECT
        capsule == Capsule.BOUND -> Adoption.ADOPT
        capsule == Capsule.ABSENT -> Adoption.FETCH
        else -> Adoption.REJECT
    }

    @Test
    fun adoptionLadderNeverAdoptsRollbackOrJump() {
        var adopted = 0
        var fetched = 0
        var refused = 0
        var rollbackRefused = 0
        var jumpRefused = 0
        for (local in 1..3) {
            for (offered in 1..3) {
                for (capsule in Capsule.entries) {
                    when (val decision = adoption(local, offered, capsule)) {
                        Adoption.ADOPT -> {
                            adopted++
                            // Exactly the next epoch, with a capsule bound to it.
                            assertEquals(local + 1, offered)
                            assertEquals(Capsule.BOUND, capsule)
                        }

                        Adoption.FETCH -> {
                            fetched++
                            assertEquals(local + 1, offered)
                            assertEquals(Capsule.ABSENT, capsule)
                        }

                        Adoption.KEEP -> {
                            assertEquals(local, offered)
                        }

                        Adoption.REJECT -> {
                            refused++
                            if (offered < local) rollbackRefused++
                            if (offered > local + 1) jumpRefused++
                            // A bound capsule is never sufficient on its own:
                            // the offer must be exactly the next epoch.
                            assertTrue(
                                "unbound/foreign capsule $capsule was adopted",
                                capsule != Capsule.BOUND || offered != local + 1,
                            )
                        }
                    }
                }
            }
        }
        assertTrue(adopted > 0)
        assertTrue(fetched > 0)
        assertTrue(refused > 0)
        assertTrue("rollback was never refused", rollbackRefused > 0)
        assertTrue("a skipped transition was never refused", jumpRefused > 0)

        // Android's download path has no adoption step: it refuses every
        // non-equal offer, including a legitimate local+1+BOUND transition.
        for (local in 1..3) {
            for (offered in 1..3) {
                val accepted = runCatching {
                    requireMatchingSyncEpoch(offered.toLong(), local.toLong())
                }.isSuccess
                assertEquals(
                    "mobile epoch gate must be exact equality",
                    offered == local,
                    accepted,
                )
                if (adoption(local, offered, Capsule.BOUND) == Adoption.ADOPT) {
                    assertTrue(
                        "the mobile download path must not adopt without an explicit flow",
                        !accepted,
                    )
                }
            }
        }
    }

    @Test
    fun adoptionStartsAFreshFloorNamespaceWithoutErasingTheOldOne() {
        val oldScope = Scope(accountA, 1)
        val before = RefState.initial(
            epoch = 1,
            pinned = accountA,
            floors = mapOf(oldScope to mapOf(chunkA to 3)),
            manifestFloors = mapOf(oldScope to 3),
        )
        // Only the ladder's exact local+1+BOUND shape may transition.
        assertEquals(Adoption.ADOPT, adoption(1, 2, Capsule.BOUND))
        assertEquals(Adoption.FETCH, adoption(1, 2, Capsule.ABSENT))
        assertEquals(Adoption.REJECT, adoption(1, 3, Capsule.BOUND))

        val adopted = before.copy(epoch = 2)
        // The old epoch's floors are preserved, not rewritten.
        assertEquals(before.floors, adopted.floors)
        assertEquals(before.manifestFloors, adopted.manifestFloors)

        // The adopted epoch restarts the server's counters: clock 1 is first
        // contact even though epoch 1 recorded clock 3 for the same chunk.
        val accepted = adopted.apply(Cmd.Chunk(chunkA, 1, 2, Seal.SEALED))
        assertEquals(Verdict.ACCEPTED, accepted.verdict)
        assertEquals(2, accepted.state.epoch)
        assertEquals(1, accepted.state.floors[Scope(accountA, 2)]?.get(chunkA))
        assertEquals(3, accepted.state.floors[oldScope]?.get(chunkA))

        // The old epoch keeps its own rollback protection.
        assertEquals(
            Verdict.REFUSED,
            before.apply(Cmd.Chunk(chunkA, 1, 1, Seal.SEALED)).verdict,
        )
    }

    @Test
    fun epochOffersNeverChangeTheDownloadEpoch() {
        for (local in 1..3) {
            for (offered in 1..3) {
                for (capsule in Capsule.entries) {
                    val impl = AndroidAdmission(initialImpl(local, accountA))
                    val verdict = impl.apply(Cmd.EpochOffer(offered, capsule), null)
                    val expected = if (offered == local) Verdict.ACCEPTED else Verdict.REFUSED
                    assertEquals("offer $local->$offered/$capsule", expected, verdict)
                    assertEquals(local.toLong(), impl.state.settings.keyEpoch)
                }
            }
        }
    }

    @Test
    fun missingPinRefusesBeforeAnyFloorRead() {
        val impl = AndroidAdmission(
            ImplState(
                settings = SyncSettings(
                    serverUrl = server,
                    bearerToken = "durable-token",
                    keyEpoch = 1,
                    seenLamportByContext = mapOf(
                        implKey(accountA, 1) to mapOf(chunkA to 3L)
                    ),
                    manifestLamportByContext = mapOf(implKey(accountA, 1) to 3L),
                ),
                pinned = null,
                vault = emptyMap(),
            )
        )
        val before = impl.state
        for (command in listOf(
            Cmd.Chunk(chunkA, 3, 1, Seal.SEALED),
            Cmd.Manifest(3),
            Cmd.EpochOffer(1, Capsule.BOUND),
        )) {
            assertEquals(
                "missing pin must refuse $command",
                Verdict.REFUSED,
                impl.apply(command, if (command is Cmd.Chunk) command else null),
            )
            assertEquals("refusal mutated state for $command", before, impl.state)
        }
        assertTrue(impl.state.vault.isEmpty())
    }

    @Test
    fun firstContactChunkBehindTheManifestFloorIsRefused() {
        val settings = SyncSettings(
            serverUrl = server,
            bearerToken = "durable-token",
            keyEpoch = 1,
            seenLamportByContext = mapOf(implKey(accountA, 1) to mapOf(chunkB to 3L)),
            manifestLamportByContext = mapOf(implKey(accountA, 1) to 3L),
        )
        val impl = AndroidAdmission(ImplState(settings, accountA, emptyMap()))
        // chunkA has no per-chunk floor, but the whole-manifest floor is 3.
        assertEquals(
            Verdict.REFUSED,
            impl.apply(Cmd.Chunk(chunkA, 1, 1, Seal.SEALED), Cmd.Chunk(chunkA, 1, 1, Seal.SEALED)),
        )
        assertTrue("a refused chunk reached the vault", impl.state.vault.isEmpty())
        assertEquals(3L, impl.state.settings.manifestLamportByContext.getValue(implKey(accountA, 1)))

        assertEquals(
            Verdict.ACCEPTED,
            impl.apply(Cmd.Chunk(chunkA, 3, 1, Seal.SEALED), Cmd.Chunk(chunkA, 3, 1, Seal.SEALED)),
        )
        assertEquals(3, impl.state.vault[chunkA])
        // The per-chunk floors were recorded under the admitted clock only.
        assertEquals(
            mapOf(chunkB to 3L, chunkA to 3L),
            impl.state.settings.seenLamportByContext.getValue(implKey(accountA, 1)),
        )
    }

    @Test
    fun accountFloorNamespacesAreIsolated() {
        val alice = implKey(accountA, 1)
        val bob = implKey(accountB, 1)
        assertTrue("accounts must not share a namespace", alice != bob)

        val settings = SyncSettings(
            serverUrl = server,
            bearerToken = "durable-token",
            keyEpoch = 1,
            seenLamportByContext = mapOf(alice to mapOf(chunkA to 3L)),
            manifestLamportByContext = mapOf(alice to 3L),
        )
        // Bob's context is first contact even though Alice's floor exists.
        assertEquals(null, settings.seenLamportByContext[bob])
        assertEquals(null, settings.manifestLamportByContext[bob])

        // Recording Bob's floor cannot lower or replace Alice's.
        val merged = settings.copy(
            seenLamportByContext = settings.seenLamportByContext + (
                bob to mergeSeenLamports(
                    settings.seenLamportByContext[bob].orEmpty(),
                    mapOf(chunkA to 1L),
                )
                ),
            manifestLamportByContext =
                settings.manifestLamportByContext + (bob to 1L),
        )
        assertEquals(mapOf(chunkA to 3L), merged.seenLamportByContext[alice])
        assertEquals(3L, merged.manifestLamportByContext[alice])
        assertEquals(mapOf(chunkA to 1L), merged.seenLamportByContext[bob])

        // And a stale write inside Bob's namespace still cannot lower Bob.
        assertEquals(
            mapOf(chunkA to 1L),
            mergeSeenLamports(
                merged.seenLamportByContext.getValue(bob),
                mapOf(chunkA to 0L),
            ),
        )
    }

    @Test
    fun refusedCiphertextsNeverReachTheVault() {
        val impl = AndroidAdmission(initialImpl(1, accountA))
        val accepted = Cmd.Chunk(chunkA, 2, 1, Seal.SEALED)
        assertEquals(Verdict.ACCEPTED, impl.apply(accepted, accepted))
        val vaultAfterAccept = impl.state.vault
        val floorsAfterAccept = impl.state.settings

        val refused = listOf(
            Cmd.Chunk(chunkA, 1, 1, Seal.SEALED),        // older clock
            Cmd.Chunk(chunkB, 0, 1, Seal.SEALED),        // nonpositive clock
            Cmd.Chunk(chunkB, 2, 2, Seal.SEALED),        // epoch jump
            Cmd.Chunk(chunkB, 2, 1, Seal.WRONG_AAD),     // opened under wrong AAD
            Cmd.Chunk(chunkB, 2, 1, Seal.UNSEALED),      // legacy unsealed
        )
        for (command in refused) {
            assertEquals(
                "expected refusal for $command",
                Verdict.REFUSED,
                impl.apply(command, command),
            )
            assertEquals("refused $command changed the vault", vaultAfterAccept, impl.state.vault)
            assertEquals("refused $command changed the floors", floorsAfterAccept, impl.state.settings)
        }
        assertEquals(mapOf(chunkA to 2), impl.state.vault)
    }

    @Test
    fun floorMergeNeverLowersAndReplayOfAnOlderResponseIsRefused() {
        // The primitive used by `recordAdmittedBaselines`.
        assertEquals(
            mapOf(chunkA to 7L),
            mergeSeenLamports(mapOf(chunkA to 7L), mapOf(chunkA to 3L)),
        )
        assertEquals(
            mapOf(chunkA to 7L, chunkB to 1L),
            mergeSeenLamports(mapOf(chunkA to 7L), mapOf(chunkB to 1L)),
        )

        val impl = AndroidAdmission(initialImpl(1, accountA))
        val newer = Cmd.Chunk(chunkA, 3, 1, Seal.SEALED)
        assertEquals(Verdict.ACCEPTED, impl.apply(newer, newer))
        // Replaying the same response (equal clock) is allowed...
        assertEquals(Verdict.ACCEPTED, impl.apply(newer, newer))
        // ...but replaying an earlier response after the floor advanced is not.
        val older = Cmd.Chunk(chunkA, 1, 1, Seal.SEALED)
        assertEquals(Verdict.REFUSED, impl.apply(older, older))
        assertEquals(3L, impl.state.settings.seenLamportByContext.getValue(implKey(accountA, 1))[chunkA])
    }

    private fun writeEvidence(name: String, text: String) {
        val directory = System.getenv("VELA_ANDROID_SYNC_EVIDENCE") ?: return
        runCatching {
            File(directory).mkdirs()
            File(directory, name).writeText(text)
        }
    }
}

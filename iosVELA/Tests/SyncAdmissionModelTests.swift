import Foundation
import XCTest

@testable import VELA

// MARK: - Reference model
//
// Written from the shared Rust policy (`libVELA/vela-sync-policy`:
// `plan_sync_epoch_match` and `plan_chunk_download`) plus the one iOS-level
// guard `SyncEngine.rejectRollback` documents. Nothing below calls the code
// under test; it is a plain state machine over floors and epochs.
//
// Per context (server + account + key epoch) the model keeps:
//   * a per-chunk floor: the highest clock admitted for that chunk, or none;
//   * a whole-manifest floor: the highest clock admitted in that context.
// A missing floor is explicit first contact, never clock 0 (the Rust
// `Option<i64>` baseline).
//
// Round trip for a manifest that carries one chunk:
//   1. the manifest epoch must be positive and exactly the device's
//      authenticated epoch — iOS never adopts an epoch on the download path;
//   2. the Swift manifest guard refuses a manifest whose highest clock is below
//      the context's manifest floor;
//   3. the Swift per-chunk guard refuses a chunk below its recorded floor;
//   4. the Rust kernel refuses a blob that is not sealed (legacy), a blob whose
//      AEAD open fails (mislabelled clock), and a clock below 1 or below the
//      supplied baseline;
//   5. only then is content admitted, and the floors become max(old, clock).
private enum AdmissionRefusal: String, Hashable {
    case epochMismatch
    case rollback
    case unreadable
    case legacy
}

private enum AdmissionOutcome: Equatable {
    case accepted(chunkID: String, clock: Int)
    case refused(AdmissionRefusal)
    case switchedContext
}

/// One server response a stale or hostile peer can produce. Every command also
/// states what the model can do with it, so non-vacuity is checked exactly.
private enum ModelCommand: String, CaseIterable, Hashable {
    // Correctly sealed chunks (epoch-1 or epoch-2 AAD, generated per context).
    case chunkZeroClockZero = "chunk0-clock0-sealed"
    case chunkZeroClockTwo = "chunk0-clock2-sealed"
    case chunkZeroClockThree = "chunk0-clock3-sealed"
    case chunkOneClockTwo = "chunk1-clock2-sealed"
    // A blob sealed for clock 1 but served as clock 2: the AEAD must refuse it.
    case chunkZeroWrongAAD = "chunk0-served2-sealed1"
    // A blob without the sealed header: the pre-C-2 legacy shape.
    case chunkZeroUnsealed = "chunk0-clock2-unsealed"
    // Epoch offers for a manifest that carries a chunk. The capsule is not part
    // of the /vault/sync wire shape; iOS has no adoption path here, so a bound
    // and an unbound offer must be indistinguishable (both refused).
    case epochOfferNextBound = "epoch-offer-next-bound-capsule"
    case epochOfferNextUnbound = "epoch-offer-next-unbound-capsule"
    case epochOfferJumpBound = "epoch-offer-jump-bound-capsule"
    // Move to the next context (account A epoch 1 -> account B epoch 1 ->
    // account A epoch 2 -> account A epoch 1).
    case switchContext = "account-switch"

    enum Kind: Equatable {
        case download
        case epochOffer
        case accountSwitch
    }

    enum Payload: Equatable {
        case sealed
        case wrongAAD
        case unsealed
    }

    enum Expectation {
        case alwaysAccepted
        case alwaysRefused
        case both
        case noDecision
    }

    var kind: Kind {
        switch self {
        case .switchContext: return .accountSwitch
        case .epochOfferNextBound, .epochOfferNextUnbound, .epochOfferJumpBound:
            return .epochOffer
        default: return .download
        }
    }

    var payload: Payload {
        switch self {
        case .chunkZeroWrongAAD: return .wrongAAD
        case .chunkZeroUnsealed: return .unsealed
        default: return .sealed
        }
    }

    var chunkID: String {
        switch self {
        case .chunkOneClockTwo: return SyncAdmissionModelTests.chunkOne
        default: return SyncAdmissionModelTests.chunkZero
        }
    }

    var clock: Int {
        switch self {
        case .chunkZeroClockZero: return 0
        case .chunkZeroClockTwo, .chunkZeroWrongAAD, .chunkZeroUnsealed,
             .chunkOneClockTwo:
            return 2
        case .chunkZeroClockThree, .epochOfferNextBound,
             .epochOfferNextUnbound, .epochOfferJumpBound:
            return 3
        case .switchContext: return 0
        }
    }

    /// How far above the device's authenticated epoch the manifest claims to be.
    /// Offers above `0` are exactly the adoption shapes the Rust ladder can
    /// reach; the iOS download path must refuse all of them.
    var epochDelta: Int {
        switch self {
        case .epochOfferNextBound, .epochOfferNextUnbound: return 1
        case .epochOfferJumpBound: return 2
        default: return 0
        }
    }

    var expectation: Expectation {
        switch self {
        case .chunkZeroClockTwo, .chunkOneClockTwo: return .both
        case .chunkZeroClockThree: return .alwaysAccepted
        case .chunkZeroClockZero, .chunkZeroWrongAAD, .chunkZeroUnsealed,
             .epochOfferNextBound, .epochOfferNextUnbound, .epochOfferJumpBound:
            return .alwaysRefused
        case .switchContext: return .noDecision
        }
    }
}

private struct ReferenceModel {
    struct Context {
        let localEpoch: Int
        var chunkFloors: [String: Int] = [:]
        var manifestFloor: Int = 0
    }

    private(set) var contexts: [Context]
    private(set) var active: Int

    init(localEpochs: [Int]) {
        contexts = localEpochs.map { Context(localEpoch: $0) }
        active = 0
    }

    /// Apply one server response. Mutates only on an admitted download.
    mutating func step(_ command: ModelCommand) -> AdmissionOutcome {
        if command.kind == .accountSwitch {
            active = (active + 1) % contexts.count
            return .switchedContext
        }

        var context = contexts[active]
        let offeredEpoch = context.localEpoch + command.epochDelta
        // iOS download admission requires exact agreement; a sequential offer is
        // not adopted here, and a skipped one certainly is not.
        guard offeredEpoch == context.localEpoch else {
            return .refused(.epochMismatch)
        }
        // Whole-vault floor (SyncEngine.rejectRollback): the manifest's highest
        // clock may not fall behind the clock this context already synced.
        if context.manifestFloor > 0, command.clock < context.manifestFloor {
            return .refused(.rollback)
        }
        // Per-chunk floor (the same function, and the Rust baseline).
        if let recorded = context.chunkFloors[command.chunkID],
           command.clock < recorded {
            return .refused(.rollback)
        }
        switch command.payload {
        case .unsealed:
            return .refused(.legacy)
        case .wrongAAD:
            return .refused(.unreadable)
        case .sealed:
            break
        }
        // Rust kernel: clocks must be positive. (The epoch is positive for every
        // context here, and the AAD opened, so the remaining conjuncts hold.)
        if command.clock < 1 {
            return .refused(.unreadable)
        }

        context.chunkFloors[command.chunkID] = max(
            context.chunkFloors[command.chunkID] ?? 0, command.clock)
        context.manifestFloor = max(context.manifestFloor, command.clock)
        contexts[active] = context
        return .accepted(chunkID: command.chunkID, clock: command.clock)
    }
}

/// The observable floor state, in a shape both sides can produce: one entry per
/// (context, chunk) and one whole-manifest entry per context. `nil` is "no
/// recorded baseline" (first contact), not clock 0.
private struct FloorSnapshot: Equatable {
    var chunk: [[Int?]]
    var manifest: [Int?]

    static func empty(contexts: Int, chunks: Int) -> FloorSnapshot {
        FloorSnapshot(
            chunk: Array(repeating: Array(repeating: nil, count: chunks), count: contexts),
            manifest: Array(repeating: nil, count: contexts))
    }
}

// MARK: - Transport stub

/// A request-serving URLProtocol with its own handler, so this file does not
/// share mutable state with `MockURLProtocol` in Phase4Tests. The handler is
/// replaced before every sync and the sync is awaited, so requests never race.
private final class SyncAdmissionURLProtocol: URLProtocol {
    static var respond: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let respond = SyncAdmissionURLProtocol.respond else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        do {
            let (response, data) = try respond(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

// MARK: - Tests

/// Bounded exhaustive conformance for the iOS sync **download/admission** path.
///
/// The system under test is the real production composition:
/// `SyncEngine.sync` -> `VelaClient.syncManifest`/`getChunk` ->
/// `SyncEngine.rejectRollback` -> `VelaCoreFFI.decryptVaultChunkAdmittedOrThrow`
/// (the Rust bridge: epoch agreement, real AEAD open, `plan_chunk_download`) ->
/// `VaultMerge.mergeStores` -> `VaultRepository.save` ->
/// `SyncEngine.recordAdmitted`.
///
/// Every command sequence of length 1...3 over the 10-command alphabet runs
/// against the model and against that path, comparing the accept/refuse
/// decision, its reason, the admitted content, every floor and the vault store
/// after each step.
final class SyncAdmissionModelTests: XCTestCase {
    // 1 server, 2 accounts, 2 key epochs, 2 chunk ids, clocks 0...3.
    fileprivate static let chunkZero = "vault-data-000000"
    fileprivate static let chunkOne = "vault-data-000001"
    private static let chunkIDs: [String] = ["vault-data-000000", "vault-data-000001"]
    private static let contexts: [(account: String, epoch: Int)] = [
        (account: "account-a", epoch: 1),
        (account: "account-b", epoch: 1),
        (account: "account-a", epoch: 2),
    ]
    private static let depth = 3
    private static let rms = Data(repeating: 0x5A, count: 32)

    // MARK: Exhaustive model

    func testBoundedExhaustiveSequencesUpToDepthThreeConform() async throws {
        SyncEngine.clearBaselines()
        defer { SyncEngine.clearBaselines() }

        let rms = Self.rms
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [SyncAdmissionURLProtocol.self]
        let client = VelaClient(
            baseURL: URL(string: "https://vault.example")!,
            session: URLSession(configuration: config))
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vela-sync-conformance-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let repo = VaultRepository(directory: directory)
        let engines = Self.contexts.map { context in
            SyncEngine(client: client, repo: repo, keyEpoch: context.epoch,
                       accountID: context.account)
        }
        let blobs = try makeBlobs(rms: rms)

        // Every non-empty sequence of length 1...depth, in a fixed order.
        var traces: [[ModelCommand]] = []
        var prefix: [ModelCommand] = []
        extendTraces(&traces, prefix: &prefix, limit: Self.depth)
        XCTAssertEqual(traces.count, 1110,
                       "10 + 10^2 + 10^3 sequences at depth 3 over 10 commands")

        let emptySnapshot = FloorSnapshot.empty(
            contexts: engines.count, chunks: Self.chunkIDs.count)
        var stepCount = 0
        var syncCount = 0
        var acceptedByCommand: [ModelCommand: Int] = [:]
        var refusedByCommand: [ModelCommand: Int] = [:]
        var switchedByCommand: [ModelCommand: Int] = [:]
        var refusalCounts: [AdmissionRefusal: Int] = [:]
        var crossContextWitness = false
        var storeUnchangedChecks = 0

        for trace in traces {
            // Each trace starts from a clean device: no floors, no vault.
            SyncEngine.clearBaselines()
            repo.reset()
            var model = ReferenceModel(localEpochs: Self.contexts.map { $0.epoch })
            var previous = try snapshot(engines: engines)
            XCTAssertEqual(previous, emptySnapshot,
                           "trace did not start clean: \(Self.name(trace))")

            for (index, command) in trace.enumerated() {
                stepCount += 1
                let expected = model.step(command)
                let label = "\(Self.name(trace)) step \(index) (\(command.rawValue))"

                let storeBefore = try? repo.load(rms: rms)
                guard let observed = await run(
                    command, engine: engines[model.active],
                    localEpoch: Self.contexts[model.active].epoch,
                    blobs: blobs, rms: rms, repo: repo, label: label)
                else {
                    break
                }
                if command.kind != .accountSwitch { syncCount += 1 }

                XCTAssertEqual(observed, expected, "\(label): decision diverged from the model")
                switch observed {
                case .accepted:
                    acceptedByCommand[command, default: 0] += 1
                case .refused(let reason):
                    refusedByCommand[command, default: 0] += 1
                    refusalCounts[reason, default: 0] += 1
                case .switchedContext:
                    switchedByCommand[command, default: 0] += 1
                }

                // Refused responses must not touch the persisted vault. This is
                // checked against the real repository, not the returned value.
                if case .refused = expected {
                    storeUnchangedChecks += 1
                    let storeAfter = try? repo.load(rms: rms)
                    XCTAssertEqual(
                        storeAfter, storeBefore,
                        "\(label): a refused download changed the vault store")
                }

                // Floors must match the model exactly and may never go down.
                let current = try snapshot(engines: engines)
                XCTAssertEqual(current, snapshot(model: model),
                               "\(label): recorded floors diverged from the model")
                assertFloorsDoNotDecrease(previous, current, label)
                previous = current

                // Cross-context independence witness: a revision admitted in one
                // namespace that another namespace's own floor would refuse.
                if case .accepted(let chunkID, let clock) = expected {
                    for (other, state) in model.contexts.enumerated()
                    where other != model.active {
                        if let recorded = state.chunkFloors[chunkID],
                           recorded > clock {
                            crossContextWitness = true
                        }
                    }
                }
            }
        }

        // Constant-work guards: the enumeration is exactly the one documented.
        XCTAssertEqual(stepCount, 3210, "10*1 + 100*2 + 1000*3 command applications")
        XCTAssertEqual(syncCount, 2889, "3210 applications minus 321 account switches")

        // Non-vacuity: every command behaves exactly as the model says it can.
        for command in ModelCommand.allCases {
            let accepted = acceptedByCommand[command] ?? 0
            let refused = refusedByCommand[command] ?? 0
            let switched = switchedByCommand[command] ?? 0
            switch command.expectation {
            case .alwaysAccepted:
                XCTAssertGreaterThan(accepted, 0, "\(command.rawValue) was never admitted")
                XCTAssertEqual(refused, 0, "\(command.rawValue) was unexpectedly refused")
            case .alwaysRefused:
                XCTAssertGreaterThan(refused, 0, "\(command.rawValue) was never refused")
                XCTAssertEqual(accepted, 0, "\(command.rawValue) was unexpectedly admitted")
            case .both:
                XCTAssertGreaterThan(accepted, 0, "\(command.rawValue) was never admitted")
                XCTAssertGreaterThan(refused, 0, "\(command.rawValue) was never refused")
            case .noDecision:
                XCTAssertEqual(accepted, 0)
                XCTAssertEqual(refused, 0)
                XCTAssertGreaterThan(switched, 0, "no account switch was exercised")
            }
        }
        // Every refusal class is reached, including both rollback gates.
        for refusal in [AdmissionRefusal.epochMismatch, .rollback, .unreadable, .legacy] {
            XCTAssertGreaterThan(refusalCounts[refusal] ?? 0, 0,
                                 "refusal class \(refusal.rawValue) was never exercised")
        }
        XCTAssertGreaterThan(storeUnchangedChecks, 0)
        XCTAssertTrue(
            crossContextWitness,
            "no trace admitted a revision that another context's floor would refuse")
    }

    // MARK: Boundary grid against the Rust kernel directly

    /// The production path's Swift floor guard fires before the Rust kernel, so
    /// the kernel's own rollback branch is only reachable through this entry
    /// point. Grid over clocks, baselines, AAD binding and epoch pairs, compared
    /// to the predicate stated independently in `admissible` below.
    func testAdmissionKernelBoundaryGridMatchesIndependentPredicate() throws {
        let rms = Self.rms
        let chunkID = Self.chunkZero
        let plaintext = #"{"items":[],"tombstones":[]}"#
        let clocks = [-1, 0, 1, 2, 5]
        let baselines: [Int64?] = [nil, 0, 1, 2, 5, 7]
        let epochPairs: [(server: Int, local: Int)] = [
            (server: 1, local: 1),
            (server: 1, local: 2),
            (server: 2, local: 1),
            (server: 0, local: 0),
            (server: -1, local: 1),
            (server: 1, local: 0),
        ]

        var sealed: [Int: String] = [:]
        for clock in clocks {
            sealed[clock] = try XCTUnwrap(
                VelaCoreFFI.encryptVaultChunk(
                    rms: rms, chunkID: chunkID, vaultJSON: plaintext,
                    lamportClock: clock, keyEpoch: 1),
                "could not seal clock \(clock)")
        }

        var accepted = 0
        var rejected = 0
        for clock in clocks {
            for baseline in baselines {
                for aadCorrect in [true, false] {
                    // A relabelled blob: sealed at `clock`, served one revision later.
                    let served = aadCorrect ? clock : clock + 1
                    for pair in epochPairs {
                        let observed = VelaCoreFFI.decryptVaultChunkAdmitted(
                            rms: rms, chunkID: chunkID,
                            ciphertextBase64: sealed[clock]!,
                            lamportClock: Int64(served),
                            keyEpoch: pair.server, localKeyEpoch: pair.local,
                            lastSeenLamport: baseline)
                        let notOlder = baseline.map { Int64(served) >= $0 } ?? true
                        let admissible = pair.server == pair.local
                            && pair.server >= 1
                            && served >= 1
                            && notOlder
                            && aadCorrect
                        let label = "clock \(clock) served \(served) "
                            + "baseline \(String(describing: baseline)) "
                            + "epochs \(pair.server)/\(pair.local) aad \(aadCorrect)"
                        if admissible {
                            XCTAssertEqual(observed?.lamportClock, Int64(served),
                                           "permit must carry the admitted clock: \(label)")
                            XCTAssertEqual(observed?.vaultJSON, plaintext,
                                           "admitted content must be the sealed plaintext: \(label)")
                            accepted += 1
                        } else {
                            XCTAssertNil(observed, "inadmissible download admitted: \(label)")
                            rejected += 1
                        }
                    }
                }
            }
        }
        XCTAssertGreaterThan(accepted, 0)
        XCTAssertGreaterThan(rejected, 0)
    }

    // MARK: Named witnesses

    /// INT-1's skip case: an offer of epoch local+2, even bound to a capsule,
    /// is refused and no namespace moves. The local+1 offers are refused here
    /// too (iOS does not adopt on download); see the evidence README.
    func testEpochJumpOfferIsRefusedAndNoNamespaceMoves() async throws {
        SyncEngine.clearBaselines()
        defer { SyncEngine.clearBaselines() }
        let rms = Self.rms
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vela-sync-epoch-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let repo = VaultRepository(directory: directory)
        let engines = Self.contexts.map { context in
            SyncEngine(client: mockClient(), repo: repo, keyEpoch: context.epoch,
                       accountID: context.account)
        }
        let blobs = try makeBlobs(rms: rms)

        // account-a/epoch-1 is offered epoch 3 (a jump of two) with a capsule.
        configureProtocol(
            manifestEpoch: 3, chunkID: Self.chunkZero, clock: 3,
            blob: blobs[Self.blobKey(.epochOfferJumpBound, epoch: 1)]!,
            command: .epochOfferJumpBound)
        await assertRefused(
            engine: engines[0], rms: rms, repo: repo,
            expected: .epochMismatch, label: "epoch jump offer")

        for engine in engines {
            XCTAssertNil(try engine.recordedSeenClock(for: Self.chunkZero))
            XCTAssertNil(try engine.recordedManifestClock())
        }
        if let store = try? repo.load(rms: rms) {
            XCTFail("a refused offer created a vault with \(store.items.count) item(s)")
        }
        // The engine still authenticates the epoch it was built with.
        XCTAssertEqual(engines[0].keyEpoch, 1)
        XCTAssertEqual(engines[2].keyEpoch, 2)
    }

    /// A stale chunk behind a manifest that is not itself stale is refused, the
    /// recorded floor never decreases, and an equal-clock replay stays admitted.
    func testRollbackRefusedFloorNeverDecreasesAndReplayStaysAdmitted() async throws {
        SyncEngine.clearBaselines()
        defer { SyncEngine.clearBaselines() }
        let rms = Self.rms
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vela-sync-rollback-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let repo = VaultRepository(directory: directory)
        let engine = SyncEngine(
            client: mockClient(), repo: repo, keyEpoch: 1, accountID: "account-a")
        let blobs = try makeBlobs(rms: rms)

        configureProtocol(
            manifestEpoch: 1, chunkID: Self.chunkZero, clock: 3,
            blob: blobs[Self.blobKey(.chunkZeroClockThree, epoch: 1)]!,
            command: .chunkZeroClockThree)
        _ = try await engine.sync(rms: rms, localStore: VaultStore(items: []))
        XCTAssertEqual(try engine.recordedSeenClock(for: Self.chunkZero), 3)
        XCTAssertEqual(try engine.recordedManifestClock(), 3)
        let admittedStore = try repo.load(rms: rms)

        // Revision 2, correctly sealed for its own clock, is still a rollback.
        configureProtocol(
            manifestEpoch: 1, chunkID: Self.chunkZero, clock: 2,
            blob: blobs[Self.blobKey(.chunkZeroClockTwo, epoch: 1)]!,
            command: .chunkZeroClockTwo)
        await assertRefused(
            engine: engine, rms: rms, repo: repo,
            expected: .rollback, label: "stale chunk")
        XCTAssertEqual(try engine.recordedSeenClock(for: Self.chunkZero), 3)
        XCTAssertEqual(try engine.recordedManifestClock(), 3)
        XCTAssertEqual(try repo.load(rms: rms), admittedStore,
                       "the refused rollback replaced the local vault")

        // Equal-clock re-delivery of the same revision is admitted and idempotent.
        configureProtocol(
            manifestEpoch: 1, chunkID: Self.chunkZero, clock: 3,
            blob: blobs[Self.blobKey(.chunkZeroClockThree, epoch: 1)]!,
            command: .chunkZeroClockThree)
        let merged = try await engine.sync(rms: rms, localStore: VaultStore(items: []))
        XCTAssertEqual(merged, admittedStore)
        XCTAssertEqual(try engine.recordedSeenClock(for: Self.chunkZero), 3)
        XCTAssertEqual(try repo.load(rms: rms), admittedStore)
    }

    /// Every refusal class leaves a non-empty local vault byte-identical and
    /// records no floor. The exhaustive corpus runs with an empty local store;
    /// this adds the realistic case where the user already has a vault.
    func testRefusedDownloadsLeaveNonEmptyLocalVaultIntact() async throws {
        SyncEngine.clearBaselines()
        defer { SyncEngine.clearBaselines() }
        let rms = Self.rms
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("vela-sync-local-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let repo = VaultRepository(directory: directory)
        let local = VaultStore(items: [Self.markerItem("local-keep")])
        try repo.save(local, rms: rms)
        let engine = SyncEngine(
            client: mockClient(), repo: repo, keyEpoch: 1, accountID: "account-a")
        let blobs = try makeBlobs(rms: rms)

        let cases: [(command: ModelCommand, refusal: AdmissionRefusal)] = [
            (command: .chunkZeroClockZero, refusal: .unreadable),
            (command: .chunkZeroWrongAAD, refusal: .unreadable),
            (command: .chunkZeroUnsealed, refusal: .legacy),
        ]
        for entry in cases {
            configureProtocol(
                manifestEpoch: 1, chunkID: entry.command.chunkID,
                clock: entry.command.clock,
                blob: blobs[Self.blobKey(entry.command, epoch: 1)]!,
                command: entry.command)
            await assertRefused(
                engine: engine, rms: rms, repo: repo,
                expected: entry.refusal, label: entry.command.rawValue)
            XCTAssertEqual(try repo.load(rms: rms), local,
                           "\(entry.command.rawValue) changed the local vault")
            XCTAssertNil(try engine.recordedSeenClock(for: entry.command.chunkID))
            XCTAssertNil(try engine.recordedManifestClock())
        }
    }

    // MARK: Harness

    /// Run one command against the real path. Returns `nil` (after failing) when
    /// the path produced an error outside the modelled set.
    private func run(
        _ command: ModelCommand,
        engine: SyncEngine,
        localEpoch: Int,
        blobs: [String: Data],
        rms: Data,
        repo: VaultRepository,
        label: String
    ) async -> AdmissionOutcome? {
        if command.kind == .accountSwitch { return .switchedContext }
        guard let blob = blobs[Self.blobKey(command, epoch: localEpoch)] else {
            XCTFail("missing sealed fixture for \(command.rawValue) at epoch \(localEpoch)")
            return nil
        }
        configureProtocol(
            manifestEpoch: localEpoch + command.epochDelta,
            chunkID: command.chunkID,
            clock: command.clock,
            blob: blob,
            command: command)
        do {
            let merged = try await engine.sync(rms: rms, localStore: VaultStore(items: []))
            XCTAssertEqual(merged.items.map { $0.id }, ["item-" + command.rawValue],
                           "\(label): admitted content is not the served chunk")
            let persisted = try repo.load(rms: rms)
            XCTAssertEqual(persisted, merged,
                           "\(label): admitted content did not reach the vault store")
            return .accepted(chunkID: command.chunkID, clock: command.clock)
        } catch let error as SyncEngine.SyncError {
            guard let refusal = Self.refusal(for: error) else {
                XCTFail("\(label): unexpected sync error \(error)")
                return nil
            }
            return .refused(refusal)
        } catch {
            XCTFail("\(label): unexpected error \(error)")
            return nil
        }
    }

    private func assertRefused(
        engine: SyncEngine, rms: Data, repo: VaultRepository,
        expected: AdmissionRefusal, label: String
    ) async {
        let before = try? repo.load(rms: rms)
        do {
            _ = try await engine.sync(rms: rms, localStore: VaultStore(items: []))
            XCTFail("\(label): expected the download to be refused")
        } catch let error as SyncEngine.SyncError {
            let observed = Self.refusal(for: error)
            XCTAssertEqual(observed?.rawValue ?? "<none>", expected.rawValue,
                           "\(label): wrong refusal reason (\(error))")
        } catch {
            XCTFail("\(label): unexpected error \(error)")
        }
        XCTAssertEqual(try? repo.load(rms: rms), before,
                       "\(label): a refused download changed the vault store")
    }

    private func configureProtocol(
        manifestEpoch: Int, chunkID: String, clock: Int, blob: Data,
        command: ModelCommand
    ) {
        let manifest = Self.manifestJSON(
            epoch: manifestEpoch, chunkID: chunkID, clock: clock)
        let chunkPath = "/vault/chunk/" + chunkID
        SyncAdmissionURLProtocol.respond = { request in
            let path = request.url?.path ?? ""
            guard let url = request.url else { throw URLError(.badURL) }
            if path == "/vault/sync" {
                let response = HTTPURLResponse(
                    url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
                return (response, Data(manifest.utf8))
            }
            if path == chunkPath {
                let response = HTTPURLResponse(
                    url: url, statusCode: 200, httpVersion: nil,
                    headerFields: [
                        "X-Chunk-Version": "1",
                        "X-Lamport-Clock": String(clock),
                    ])!
                return (response, blob)
            }
            XCTFail("unexpected request path \(path) while running \(command.rawValue)")
            let response = HTTPURLResponse(
                url: url, statusCode: 500, httpVersion: nil, headerFields: nil)!
            return (response, Data())
        }
    }

    private func mockClient() -> VelaClient {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [SyncAdmissionURLProtocol.self]
        return VelaClient(
            baseURL: URL(string: "https://vault.example")!,
            session: URLSession(configuration: config))
    }

    private func snapshot(engines: [SyncEngine]) throws -> FloorSnapshot {
        var snapshot = FloorSnapshot.empty(
            contexts: engines.count, chunks: Self.chunkIDs.count)
        for (context, engine) in engines.enumerated() {
            for (chunk, chunkID) in Self.chunkIDs.enumerated() {
                let recorded = try engine.recordedSeenClock(for: chunkID)
                snapshot.chunk[context][chunk] = recorded.map { Int($0) }
            }
            snapshot.manifest[context] = try engine.recordedManifestClock()
        }
        return snapshot
    }

    private func snapshot(model: ReferenceModel) -> FloorSnapshot {
        var snapshot = FloorSnapshot.empty(
            contexts: model.contexts.count, chunks: Self.chunkIDs.count)
        for (context, state) in model.contexts.enumerated() {
            for (chunk, chunkID) in Self.chunkIDs.enumerated() {
                snapshot.chunk[context][chunk] = state.chunkFloors[chunkID]
            }
            snapshot.manifest[context] = state.manifestFloor == 0 ? nil : state.manifestFloor
        }
        return snapshot
    }

    /// Recorded clocks only ever rise, and a recorded entry never disappears.
    private func assertFloorsDoNotDecrease(
        _ previous: FloorSnapshot, _ current: FloorSnapshot, _ label: String,
        file: StaticString = #file, line: UInt = #line
    ) {
        for context in 0..<min(previous.chunk.count, current.chunk.count) {
            for chunk in 0..<min(previous.chunk[context].count, current.chunk[context].count) {
                if let old = previous.chunk[context][chunk] {
                    guard let new = current.chunk[context][chunk] else {
                        XCTFail("\(label): floor for \(Self.chunkIDs[chunk]) disappeared",
                                file: file, line: line)
                        continue
                    }
                    XCTAssertGreaterThanOrEqual(
                        new, old,
                        "\(label): floor for \(Self.chunkIDs[chunk]) went \(old) -> \(new)",
                        file: file, line: line)
                }
            }
            if let old = previous.manifest[context] {
                guard let new = current.manifest[context] else {
                    XCTFail("\(label): manifest floor for context \(context) disappeared",
                            file: file, line: line)
                    continue
                }
                XCTAssertGreaterThanOrEqual(
                    new, old,
                    "\(label): manifest floor went \(old) -> \(new)",
                    file: file, line: line)
            }
        }
    }

    // MARK: Fixtures

    private func extendTraces(
        _ out: inout [[ModelCommand]], prefix: inout [ModelCommand], limit: Int
    ) {
        guard prefix.count < limit else { return }
        for command in ModelCommand.allCases {
            prefix.append(command)
            out.append(prefix)
            extendTraces(&out, prefix: &prefix, limit: limit)
            prefix.removeLast()
        }
    }

    /// One blob per (command, local epoch). Epoch-1 seals bind chunk id and
    /// clock; epoch-2 seals also bind the epoch, so the same command needs a
    /// different blob in the account-a/epoch-2 context.
    private func makeBlobs(rms: Data) throws -> [String: Data] {
        var blobs: [String: Data] = [:]
        for epoch in [1, 2] {
            for command in ModelCommand.allCases where command.kind != .accountSwitch {
                let plaintext = try Self.markerPlaintext(command)
                switch command.payload {
                case .sealed, .wrongAAD:
                    let sealedClock = command.payload == .wrongAAD
                        ? command.clock - 1
                        : command.clock
                    let sealed = try XCTUnwrap(
                        VelaCoreFFI.encryptVaultChunk(
                            rms: rms, chunkID: command.chunkID,
                            vaultJSON: plaintext, lamportClock: sealedClock,
                            keyEpoch: epoch),
                        "could not seal \(command.rawValue) at epoch \(epoch)")
                    blobs[Self.blobKey(command, epoch: epoch)] =
                        try XCTUnwrap(Data(base64Encoded: sealed))
                case .unsealed:
                    // Any blob without the `VAE1` header takes the bridge's
                    // legacy-unsealed branch (`aead::is_sealed` is false) and is
                    // refused before an AEAD open. Fixed bytes keep this
                    // deterministic (a real legacy ciphertext would use a random
                    // nonce, with a 2^-32 chance of colliding with the magic).
                    blobs[Self.blobKey(command, epoch: epoch)] =
                        Data(repeating: 0xAB, count: 48)
                }
            }
        }
        return blobs
    }

    private static func blobKey(_ command: ModelCommand, epoch: Int) -> String {
        "\(command.rawValue)|epoch-\(epoch)"
    }

    private static func manifestJSON(epoch: Int, chunkID: String, clock: Int) -> String {
        let chunk = "{\"chunk_id\":\"" + chunkID + "\",\"version\":1,"
            + "\"lamport_clock\":" + String(clock) + ",\"last_writer\":null}"
        return "{\"epoch\":" + String(epoch) + ",\"chunks\":[" + chunk + "]}"
    }

    private static func markerPlaintext(_ command: ModelCommand) throws -> String {
        let store = VaultStore(items: [markerItem(command.rawValue)])
        return String(decoding: try JSONEncoder().encode(store), as: UTF8.self)
    }

    /// A deterministic login whose id names the command that served it.
    private static func markerItem(_ tag: String) -> VaultItem {
        var item = VaultItem.newLogin(
            name: tag, url: "https://example.test/\(tag)",
            username: "user-\(tag)", password: "password-\(tag)", totp: nil)
        item.id = "item-" + tag
        item.createdAt = "2026-01-01T00:00:00Z"
        item.updatedAt = "2026-01-01T00:00:00Z"
        return item
    }

    private static func refusal(for error: SyncEngine.SyncError) -> AdmissionRefusal? {
        switch error {
        case .epochMismatch: return .epochMismatch
        case .rollback: return .rollback
        case .unreadableChunk: return .unreadable
        case .legacyChunkNeedsMigration: return .legacy
        case .crypto, .baselineCorrupt: return nil
        }
    }

    private static func name(_ trace: [ModelCommand]) -> String {
        trace.map { $0.rawValue }.joined(separator: " -> ")
    }
}

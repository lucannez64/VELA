const std = @import("std");

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});
    // It's also possible to define more custom flags to toggle optional features
    // of this build script using `b.option()`. All defined flags (including
    // target and optimize options) will be listed when running `zig build --help`
    // in this directory.

    // This creates a module, which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Zig modules are the preferred way of making Zig code available to consumers.
    // addModule defines a module that we intend to make available for importing
    // to our consumers. We must give it a name because a Zig package can expose
    // multiple modules and consumers will need to be able to specify which
    // module they want to access.
    // ── 1. Build the Rust shim (cargo) ──────────────────────────────────
    const cargo = b.addSystemCommand(&.{
        "cargo",           "build",               "--release",
        "--manifest-path", "ntt_shim/Cargo.toml",
    });
    const msvc_compat = b.addModule("msvc_compat", .{
        .root_source_file = b.path("src/compat_msvc.zig"),
        .target = target,
    });
    const mod = b.addModule("zig_ring_arithmetic", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/root.zig"),
        // Later on we'll use this module as the root module of a test executable
        // which requires us to specify a target.
        .target = target,
    });
    mod.addImport("msvc_compat", msvc_compat);

    mod.addLibraryPath(b.path("ntt_shim/target/release"));
    mod.linkSystemLibrary("ntt_shim", .{});
    mod.addIncludePath(b.path("src"));
    mod.link_libc = true;
    mod.link_libcpp = true;
    if (target.result.os.tag == .windows) {
        mod.linkSystemLibrary("ws2_32", .{});
        mod.linkSystemLibrary("userenv", .{});
        mod.linkSystemLibrary("bcrypt", .{});
    }
    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // logic and the CLI into two separate modules.
    //
    // If your goal is to create a Zig library for others to use, consider if
    // it might benefit from also exposing a CLI tool. A parser library for a
    // data serialization format could also bundle a CLI syntax checker, for example.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "zig_ring_arithmetic",
        .root_module = b.createModule(.{
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            // Target and optimization levels must be explicitly wired in when
            // defining an executable or library (in the root module), and you
            // can also hardcode a specific target for an executable or library
            // definition if desireable (e.g. firmware for embedded devices).
            .target = target,
            .optimize = optimize,
            // List of modules available for import in source files part of the
            // root module.
            .imports = &.{
                // Here "zig_ring_arithmetic" is the name you will use in your source code to
                // import this module (e.g. `@import("zig_ring_arithmetic")`). The name is
                // repeated because you are allowed to rename your imports, which
                // can be extremely useful in case of collisions (which can happen
                // importing modules from different packages).
                .{ .name = "zig_ring_arithmetic", .module = mod },
                .{ .name = "msvc_compat", .module = msvc_compat },
            },
        }),
    });
    exe.step.dependOn(&cargo.step);

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Creates an executable that will run `test` blocks from the provided module.
    // Here `mod` needs to define a target, which is why earlier we made sure to
    // set the releative field.
    const test_filter = b.option([]const u8, "test-filter", "Filter string for test names (skip benchmarks with e.g. 'CycloProtocol')");
    const mod_tests = b.addTest(.{
        .root_module = mod,
        .filters = if (test_filter) |f| &.{f} else &.{},
    });

    // Ensure cargo finishes before we try to compile (and link) the test binary.
    mod_tests.step.dependOn(&cargo.step);

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // A top level step for running all tests. dependOn can be called multiple
    // times and since the two run steps do not depend on one another, this will
    // make the two of them run in parallel.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);

    // ── Static library for Rust FFI ─────────────────────────────────────
    const ffi_lib = b.addLibrary(.{
        .name = "cyclo",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cyclo_ffi.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_ring_arithmetic", .module = mod },
                .{ .name = "msvc_compat", .module = msvc_compat },
            },
        }),
    });
    ffi_lib.root_module.link_libc = true;
    ffi_lib.root_module.link_libcpp = true;
    if (target.result.os.tag == .windows) {
        ffi_lib.root_module.linkSystemLibrary("ws2_32", .{});
        ffi_lib.root_module.linkSystemLibrary("userenv", .{});
        ffi_lib.root_module.linkSystemLibrary("bcrypt", .{});
    }
    ffi_lib.step.dependOn(&cargo.step);
    b.installArtifact(ffi_lib);

    const ffi_step = b.step("cyclo-lib", "Build Cyclo static library for Rust FFI");
    ffi_step.dependOn(&b.addInstallArtifact(ffi_lib, .{}).step);

    // ── Benchmark ───────────────────────────────────────────────────────
    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = .ReleaseFast,
        }),
    });

    bench_exe.root_module.addLibraryPath(b.path("ntt_shim/target/release"));
    bench_exe.root_module.linkSystemLibrary("ntt_shim", .{});
    bench_exe.root_module.addIncludePath(b.path("src"));
    bench_exe.root_module.link_libc = true;
    bench_exe.root_module.link_libcpp = true;
    if (target.result.os.tag == .windows) {
        bench_exe.root_module.linkSystemLibrary("ws2_32", .{});
        bench_exe.root_module.linkSystemLibrary("userenv", .{});
        bench_exe.root_module.linkSystemLibrary("bcrypt", .{});
    }
    bench_exe.step.dependOn(&cargo.step);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);

    // ── Examples ─────────────────────────────────────────────────────────
    const vote_exe = b.addExecutable(.{
        .name = "electronic_vote",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/electronic_vote.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_ring_arithmetic", .module = mod },
                .{ .name = "msvc_compat", .module = msvc_compat },
            },
        }),
    });
    vote_exe.step.dependOn(&cargo.step);
    b.installArtifact(vote_exe);

    const run_vote = b.addRunArtifact(vote_exe);
    run_vote.step.dependOn(b.getInstallStep());
    const vote_step = b.step("run-vote", "Run the electronic vote example");
    vote_step.dependOn(&run_vote.step);

    const ticket_exe = b.addExecutable(.{
        .name = "anonymous_ticket_spend",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/anonymous_ticket_spend.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_ring_arithmetic", .module = mod },
                .{ .name = "msvc_compat", .module = msvc_compat },
            },
        }),
    });
    ticket_exe.step.dependOn(&cargo.step);
    b.installArtifact(ticket_exe);

    const run_ticket = b.addRunArtifact(ticket_exe);
    run_ticket.step.dependOn(b.getInstallStep());
    const ticket_step = b.step("run-ticket", "Run the anonymous ticket spend example");
    ticket_step.dependOn(&run_ticket.step);

    const griffin_exe = b.addExecutable(.{
        .name = "griffin_merkle_spend",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/griffin_merkle_spend.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_ring_arithmetic", .module = mod },
                .{ .name = "msvc_compat", .module = msvc_compat },
            },
        }),
    });
    griffin_exe.step.dependOn(&cargo.step);
    b.installArtifact(griffin_exe);

    const run_griffin = b.addRunArtifact(griffin_exe);
    run_griffin.step.dependOn(b.getInstallStep());
    const griffin_step = b.step("run-griffin", "Run the Griffin hash Merkle spend example");
    griffin_step.dependOn(&run_griffin.step);

    const governance_exe = b.addExecutable(.{
        .name = "group_governance",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/group_governance.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zig_ring_arithmetic", .module = mod },
                .{ .name = "msvc_compat", .module = msvc_compat },
            },
        }),
    });
    governance_exe.step.dependOn(&cargo.step);
    b.installArtifact(governance_exe);

    const run_governance = b.addRunArtifact(governance_exe);
    run_governance.step.dependOn(b.getInstallStep());
    const governance_step = b.step("run-group-governance", "Run the group governance circuits example");
    governance_step.dependOn(&run_governance.step);

    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // verbosity) to validate assumptions and diagnose problems.
    //
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}

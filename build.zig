const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Build the library as a static library.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "base58",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/base58.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(lib);

    // Build and run tests.
    const base58_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/base58.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_base58_tests = b.addRunArtifact(base58_tests);
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_base58_tests.step);
}

const std = @import("std");

const Target = struct {
    name: []const u8,
    query: std.Target.Query,
};

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSmall });

    const targets = [_]Target{
        .{ .name = "amd64", .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl } },
        .{ .name = "arm64", .query = .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl } },
        .{ .name = "arm", .query = .{ .cpu_arch = .arm, .os_tag = .linux, .abi = .musleabihf } },
    };

    inline for (targets) |t| {
        addExecutable(b, "dns-gen", t, b.path("dns-gen.zig"), optimize);
    }

    // Check
    const check = b.step("check", "Check if app compiles");
    addCheck(b, check, b.path("dns-gen.zig"), target, optimize);
}

fn addExecutable(b: *std.Build, n: []const u8, t: Target, root: ?std.Build.LazyPath, optimize: std.builtin.OptimizeMode) void {
    const target = b.resolveTargetQuery(t.query);
    const name = b.fmt("{s}-{s}", .{ n, t.name });
    const mod = b.createModule(.{
        .root_source_file = root,
        .target = target,
        .optimize = optimize,
        .strip = true,
        .single_threaded = true,
        .stack_check = false,
        .stack_protector = false,
        .omit_frame_pointer = true,
    });
    const exe = b.addExecutable(.{ .name = name, .root_module = mod });
    b.installArtifact(exe);
}

fn addCheck(b: *std.Build, step: *std.Build.Step, root: ?std.Build.LazyPath, target: std.Build.ResolvedTarget, optimize: std.builtin.OptimizeMode) void {
    const mod = b.createModule(.{ .root_source_file = root, .target = target, .optimize = optimize });
    const exe = b.addExecutable(.{ .name = "test", .root_module = mod });
    step.dependOn(&exe.step);
}

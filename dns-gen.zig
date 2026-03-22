const std = @import("std");

const Server = struct {
    tag: []const u8,
    type: []const u8,
    server: ?[]const u8 = null,
    server_port: ?u16 = null,
    domain_resolver: ?[]const u8 = null,
    detour: ?[]const u8 = null,
};

pub fn main() !void {
    var aa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = aa.allocator();
    defer aa.deinit();

    var args = try std.process.argsWithAllocator(arena);
    defer args.deinit();
    _ = args.skip();

    var servers: std.ArrayList(Server) = .empty;
    defer servers.deinit(arena);

    if (args.next()) |arg| {
        var index: usize = 1;
        var addr_iter = std.mem.splitScalar(u8, arg, ',');
        while (addr_iter.next()) |addr| : (index += 1) {
            const raw = try std.ascii.allocLowerString(arena, addr);
            const short = std.mem.indexOf(u8, raw, "://") == null;
            const url = if (short) try std.fmt.allocPrint(arena, "udp://{s}", .{raw}) else raw;
            const uri = std.Uri.parse(url) catch continue;

            const tag = try std.fmt.allocPrint(arena, "dns-proxy-{}", .{index});

            const host = if (uri.host) |host| switch (host) {
                .raw, .percent_encoded => |h| h,
            } else null;

            const server = Server{
                .tag = tag,
                .type = uri.scheme,
                .server = host,
                .server_port = uri.port,
                .detour = "out",
            };

            try servers.append(arena, server);
        }
    }

    for (servers.items, 0..) |*srv, i|
        srv.domain_resolver = if (i < servers.items.len - 1) servers.items[i + 1].tag else "dns-local";

    try servers.append(arena, Server{
        .tag = "dns-local",
        .type = "local",
    });

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    try std.json.Stringify.value(
        .{ .dns = .{ .servers = servers.items } },
        .{ .emit_null_optional_fields = false, .whitespace = .indent_2 },
        stdout,
    );
}

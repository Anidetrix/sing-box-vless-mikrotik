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
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    defer arena.deinit();

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.skip();

    var servers: std.ArrayList(Server) = .empty;
    defer servers.deinit(allocator);

    if (args.next()) |arg| {
        var index: usize = 1;
        var addr_iter = std.mem.splitScalar(u8, arg, ',');
        while (addr_iter.next()) |addr| {
            const raw = try std.ascii.allocLowerString(allocator, addr);
            const short = std.mem.indexOf(u8, raw, "://") == null;
            const url = if (short) try std.fmt.allocPrint(allocator, "udp://{s}", .{raw}) else raw;
            const uri = std.Uri.parse(url) catch continue;

            const tag = try std.fmt.allocPrint(allocator, "dns-proxy-{}", .{index});

            const host = if (uri.host) |host| switch (host) {
                .raw, .percent_encoded => |h| h,
            } else null;

            const server = Server{
                .tag = tag,
                .type = uri.scheme,
                .server = host,
                .server_port = uri.port,
                .detour = "vless-out",
            };

            try servers.append(allocator, server);
            index += 1;
        }
    }

    for (servers.items, 0..) |*srv, i|
        srv.domain_resolver = if (i < servers.items.len - 1) servers.items[i + 1].tag else "dns-local";

    try servers.append(allocator, Server{
        .tag = "dns-local",
        .type = "local",
    });

    var buf: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&buf);

    try std.json.Stringify.value(
        .{ .dns = .{ .servers = servers.items } },
        .{ .whitespace = .indent_2, .emit_null_optional_fields = false },
        &stdout_writer.interface,
    );

    try stdout_writer.interface.flush();
}

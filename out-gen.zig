const std = @import("std");

const VLESS = struct {
    type: []const u8 = "vless",
    tag: []const u8 = "out",
    server: []const u8,
    server_port: u16,
    uuid: []const u8,
    flow: []const u8,
    tls: struct {
        enabled: bool = true,
        server_name: []const u8,
        utls: struct { enabled: bool = true, fingerprint: []const u8 },
        reality: struct { enabled: bool = true, public_key: []const u8, short_id: []const u8 },
    },
    packet_encoding: []const u8 = "xudp",
};

const Hysteria2 = struct {
    type: []const u8 = "hysteria2",
    tag: []const u8 = "out",
    server: []const u8,
    server_port: u16,
    password: []const u8,
    up_mbps: ?usize,
    down_mbps: ?usize,
    obfs: ?struct { type: []const u8, password: []const u8 },
    tls: struct {
        enabled: bool = true,
        server_name: []const u8,
        alpn: []const []const u8 = &.{"h3"},
        insecure: bool,
    },
};

pub fn parseQuery(arena: std.mem.Allocator, query: std.Uri.Component) !std.StringHashMap([]u8) {
    var result: std.StringHashMap([]u8) = .init(arena);
    errdefer result.deinit();

    var iter = std.mem.splitScalar(u8, query.percent_encoded, '&');
    while (iter.next()) |pair| {
        var kv = std.mem.splitScalar(u8, pair, '=');
        const key = kv.first();
        if (key.len == 0) continue;
        const value = try arena.dupe(u8, kv.rest());
        std.mem.replaceScalar(u8, value, '+', ' ');
        try result.put(key, std.Uri.percentDecodeInPlace(value));
    }

    return result;
}

pub fn hy2(arena: std.mem.Allocator, uri: std.Uri) !Hysteria2 {
    const query = if (uri.query) |q| try parseQuery(arena, q) else return error.MissingQuery;
    const address = if (uri.host) |h| try h.toRawMaybeAlloc(arena) else return error.MissingAddress;
    const user = if (uri.user) |u| try u.toRawMaybeAlloc(arena) else return error.MissingUser;
    const insecure = if (query.get("insecure")) |i| std.mem.eql(u8, i, "1") else false;
    const up, const down = b: {
        const bandwidth = std.process.getEnvVarOwned(arena, "BANDWIDTH") catch break :b .{ null, null };
        var iter = std.mem.splitScalar(u8, bandwidth, '/');
        const up = std.fmt.parseInt(usize, iter.first(), 10) catch break :b .{ null, null };
        const down = std.fmt.parseInt(usize, iter.rest(), 10) catch up;
        break :b .{ up, down };
    };
    return .{
        .server = address,
        .server_port = uri.port orelse 443,
        .password = user,
        .up_mbps = up,
        .down_mbps = down,
        .obfs = if (query.get("obfs-password")) |p| .{ .type = query.get("obfs") orelse "salamander", .password = p } else null,
        .tls = .{ .server_name = query.get("sni") orelse address, .insecure = insecure },
    };
}

pub fn vless(arena: std.mem.Allocator, uri: std.Uri) !VLESS {
    const query = if (uri.query) |q| try parseQuery(arena, q) else return error.MissingQuery;
    const address = if (uri.host) |h| try h.toRawMaybeAlloc(arena) else return error.MissingAddress;
    const uuid = if (uri.user) |u| try u.toRawMaybeAlloc(arena) else return error.MissingUser;
    const sni = query.get("sni") orelse return error.MissingServerName;
    const pbk = query.get("pbk") orelse return error.MissingPublicKey;
    const sid = query.get("sid") orelse return error.MissingShortID;
    return .{
        .server = address,
        .server_port = uri.port orelse 443,
        .uuid = uuid,
        .flow = query.get("flow") orelse "xtls-rprx-vision",
        .tls = .{
            .server_name = sni,
            .utls = .{ .fingerprint = query.get("fp") orelse "chrome" },
            .reality = .{ .public_key = pbk, .short_id = sid },
        },
    };
}

pub fn env(arena: std.mem.Allocator) !VLESS {
    const map = try std.process.getEnvMap(arena);
    const uuid = map.get("ID") orelse return error.MissingUser;
    const address = map.get("REMOTE_ADDRESS") orelse return error.MissingAddress;
    const server_name = map.get("SERVER_NAME") orelse return error.MissingServerName;
    const public_key = map.get("PUBLIC_KEY") orelse return error.MissingPublicKey;
    const short_id = map.get("SHORT_ID") orelse return error.MissingShortID;
    const port = if (map.get("REMOTE_PORT")) |p| try std.fmt.parseInt(u16, p, 10) else 443;
    return .{
        .server = address,
        .server_port = port,
        .uuid = uuid,
        .flow = map.get("FLOW") orelse "xtls-rprx-vision",
        .tls = .{
            .server_name = server_name,
            .utls = .{ .fingerprint = map.get("FINGER_PRINT") orelse "chrome" },
            .reality = .{ .public_key = public_key, .short_id = short_id },
        },
    };
}

pub inline fn is_vless(uri: std.Uri) bool {
    if (std.mem.eql(u8, uri.scheme, "vless")) return true;
    return false;
}

pub inline fn is_hy2(uri: std.Uri) bool {
    if (std.mem.eql(u8, uri.scheme, "hysteria2")) return true;
    if (std.mem.eql(u8, uri.scheme, "hy2")) return true;
    return false;
}

pub fn main() !void {
    var aa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = aa.allocator();
    defer aa.deinit();

    var args = try std.process.argsWithAllocator(arena);
    defer args.deinit();
    _ = args.skip();

    const bypass = .{ .type = "direct", .tag = "bypass" };
    const out: union(enum) { h: Hysteria2, v: VLESS } = if (args.next()) |u| b: {
        const uri = std.Uri.parse(u) catch break :b .{ .v = try env(arena) };
        if (is_vless(uri)) break :b .{ .v = try vless(arena, uri) };
        if (is_hy2(uri)) break :b .{ .h = try hy2(arena, uri) };
        return error.UnsupportedURL;
    } else .{ .v = try env(arena) };

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    switch (out) {
        inline else => |o| try std.json.Stringify.value(
            .{ .outbounds = &.{ o, bypass } },
            .{ .emit_null_optional_fields = false, .whitespace = .indent_2 },
            stdout,
        ),
    }
}

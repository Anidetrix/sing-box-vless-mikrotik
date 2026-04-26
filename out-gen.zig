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

pub fn parseQuery(arena: std.mem.Allocator, query: std.Uri.Component) std.mem.Allocator.Error!std.StringHashMap([]u8) {
    var result: std.StringHashMap([]u8) = .init(arena);
    errdefer result.deinit();

    var iter = std.mem.splitScalar(u8, query.percent_encoded, '&');
    while (iter.next()) |pair| {
        const key, const v = std.mem.cutScalar(u8, pair, '=') orelse continue;
        if (key.len == 0) continue;
        const value = try arena.dupe(u8, v);
        std.mem.replaceScalar(u8, value, '+', ' ');
        try result.put(key, std.Uri.percentDecodeInPlace(value));
    }

    return result;
}

pub fn hy2(arena: std.mem.Allocator, envs: *const std.process.Environ.Map, short: []const u8) !Hysteria2 {
    const uri = try std.Uri.parseAfterScheme(&.{}, short);
    const query = if (uri.query) |q| try parseQuery(arena, q) else return error.MissingQuery;
    const address = if (uri.host) |h| try h.toRawMaybeAlloc(arena) else return error.MissingAddress;
    const user = if (uri.user) |u| try u.toRawMaybeAlloc(arena) else return error.MissingUser;
    const insecure = if (query.get("insecure")) |i| std.mem.eql(u8, i, "1") else false;
    const down, const up = b: {
        const bandwidth = envs.get("BANDWIDTH") orelse break :b .{ null, null };
        var iter = std.mem.splitScalar(u8, bandwidth, '/');
        const down = std.fmt.parseInt(usize, iter.first(), 10) catch break :b .{ null, null };
        const up = std.fmt.parseInt(usize, iter.rest(), 10) catch down;
        break :b .{ down, up };
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

pub fn vless(arena: std.mem.Allocator, short: []const u8) !VLESS {
    const uri = try std.Uri.parseAfterScheme(&.{}, short);
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

pub fn env(map: *const std.process.Environ.Map) !VLESS {
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

pub inline fn is_vless(scheme: []const u8) bool {
    if (std.mem.eql(u8, scheme, "vless")) return true;
    return false;
}

pub inline fn is_hy2(scheme: []const u8) bool {
    if (std.mem.eql(u8, scheme, "hysteria2")) return true;
    if (std.mem.eql(u8, scheme, "hy2")) return true;
    return false;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var threaded: std.Io.Threaded = .init_single_threaded;
    const io = threaded.io();

    var aa = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const arena = aa.allocator();
    defer aa.deinit();

    var args = try init.args.iterateAllocator(arena);
    defer args.deinit();
    _ = args.skip();

    var envs = try init.environ.createMap(arena);
    defer envs.deinit();

    const bypass = .{ .type = "direct", .tag = "bypass" };
    const out: union(enum) { h: Hysteria2, v: VLESS } = if (args.next()) |u| b: {
        const scheme, const short = std.mem.cut(u8, u, "://") orelse break :b .{ .v = try env(&envs) };
        if (is_vless(scheme)) break :b .{ .v = try vless(arena, short) };
        if (is_hy2(scheme)) break :b .{ .h = try hy2(arena, &envs, short) };
        return error.UnsupportedURL;
    } else .{ .v = try env(&envs) };

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
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

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
    obfs: ?struct { type: []const u8, password: []const u8 },
    tls: struct {
        enabled: bool = true,
        server_name: []const u8,
        alpn: []const []const u8 = &.{"h3"},
        insecure: bool,
    },
};

pub fn vless(arena: std.mem.Allocator, uri: std.Uri) !VLESS {
    const uuid = try (uri.user orelse return error.MissingUser).toRawMaybeAlloc(arena);
    const address = try (uri.host orelse return error.MissingAddress).toRawMaybeAlloc(arena);
    const query = (uri.query orelse return error.MissingQuery).percent_encoded;

    const Params = struct { pbk: ?[]const u8 = null, sid: ?[]const u8 = null, sni: ?[]const u8 = null, fp: ?[]const u8 = null, flow: ?[]const u8 = null };
    var params: Params = .{};
    var params_iter = std.mem.splitScalar(u8, query, '&');
    while (params_iter.next()) |pair| {
        var kv = std.mem.splitScalar(u8, pair, '=');
        const key = kv.first();
        if (key.len == 0) continue;

        const value_raw = try std.mem.replaceOwned(u8, arena, kv.rest(), "+", " ");
        const value = std.Uri.percentDecodeInPlace(value_raw);
        if (value.len == 0) continue;

        if (std.meta.stringToEnum(std.meta.FieldEnum(Params), key)) |field| {
            switch (field) {
                inline else => |f| @field(params, @tagName(f)) = value,
            }
        }
    }

    return .{
        .server = address,
        .server_port = uri.port orelse 443,
        .uuid = uuid,
        .flow = params.flow orelse "xtls-rprx-vision",
        .tls = .{
            .server_name = params.sni orelse return error.MissingServerName,
            .utls = .{ .fingerprint = params.fp orelse "chrome" },
            .reality = .{
                .public_key = params.pbk orelse return error.MissingPublicKey,
                .short_id = params.sid orelse return error.MissingShortID,
            },
        },
    };
}

pub fn hy2(arena: std.mem.Allocator, uri: std.Uri) !Hysteria2 {
    const uuid = try (uri.user orelse return error.MissingUser).toRawMaybeAlloc(arena);
    const address = try (uri.host orelse return error.MissingAddress).toRawMaybeAlloc(arena);
    const query = (uri.query orelse return error.MissingQuery).percent_encoded;

    const Params = struct { obfs: ?[]const u8 = null, @"obfs-password": ?[]const u8 = null, sni: ?[]const u8 = null, insecure: bool = false };
    var params: Params = .{};
    var params_iter = std.mem.splitScalar(u8, query, '&');
    while (params_iter.next()) |pair| {
        var kv = std.mem.splitScalar(u8, pair, '=');
        const key = kv.first();
        if (key.len == 0) continue;

        const value_raw = try std.mem.replaceOwned(u8, arena, kv.rest(), "+", " ");
        const value = std.Uri.percentDecodeInPlace(value_raw);
        if (value.len == 0) continue;

        if (std.meta.stringToEnum(std.meta.FieldEnum(Params), key)) |field| {
            switch (field) {
                inline else => |f| @field(params, @tagName(f)) = value,
                .insecure => params.insecure = std.mem.eql(u8, value, "1"),
            }
        }
    }

    return .{
        .server = address,
        .server_port = uri.port orelse 443,
        .password = uuid,
        .obfs = if (params.@"obfs-password") |p| .{ .type = params.obfs orelse "salamander", .password = p } else null,
        .tls = .{ .server_name = params.sni orelse address, .insecure = params.insecure },
    };
}

pub fn env(arena: std.mem.Allocator) !VLESS {
    const map = try std.process.getEnvMap(arena);

    const uuid = map.get("ID") orelse return error.MissingUser;
    const address = map.get("REMOTE_ADDRESS") orelse return error.MissingAddress;
    const server_name = map.get("SERVER_NAME") orelse return error.MissingServerName;
    const public_key = map.get("PUBLIC_KEY") orelse return error.MissingPublicKey;
    const short_id = map.get("SHORT_ID") orelse return error.MissingShortID;

    const flow = map.get("FLOW") orelse "xtls-rprx-vision";
    const fingerprint = map.get("FINGER_PRINT") orelse "chrome";
    const port = b: {
        const str = map.get("REMOTE_PORT") orelse break :b 443;
        break :b try std.fmt.parseInt(u16, str, 10);
    };

    return .{
        .server = address,
        .server_port = port,
        .uuid = uuid,
        .flow = flow,
        .tls = .{
            .server_name = server_name,
            .utls = .{ .fingerprint = fingerprint },
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

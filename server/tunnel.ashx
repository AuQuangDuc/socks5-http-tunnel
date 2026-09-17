<%@ WebHandler Language="C#" Class="TunnelHandler" %>
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web;
using System.Web.Script.Serialization;

public sealed class TunnelHandler : IHttpHandler
{
    private const int MetadataLimit = 8192;
    private const string Token = "CHANGE_ME_BEFORE_PUBLIC_USE";
    private static readonly bool RequireHttps = true;
    private static readonly bool TrustForwardedProto = false;
    private const int ConnectTimeoutSeconds = 8;
    private const int IdleTimeoutSeconds = 300;
    private const int MaxLifetimeSeconds = 3600;
    private const int MaxSendBytes = 262144;
    private const int MaxPendingBytes = 1048576;
    private const int MaxTunnels = 32;
    private const int HeartbeatSeconds = 5;

    private static readonly string StateRoot = Path.Combine(Path.GetTempPath(), "dotnet-socks-tunnel");
    private static readonly string[] AllowedCidrs = new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" };
    private static readonly string[] DeniedCidrs = new[] { "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4" };
    private static readonly int[][] AllowedPorts = new[] { new[] { 22, 22 }, new[] { 80, 80 }, new[] { 443, 443 }, new[] { 445, 445 }, new[] { 3389, 3389 }, new[] { 8123, 8123 } };
    private static readonly Regex TunnelIdPattern = new Regex("^[a-f0-9]{32}$", RegexOptions.Compiled);
    private static readonly Regex SequencePattern = new Regex("^(?:0|[1-9][0-9]{0,17})$", RegexOptions.Compiled);
    private static readonly Regex HostPattern = new Regex("^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", RegexOptions.Compiled);

    private HttpContext _context;
    private bool _streamingStarted;

    public bool IsReusable { get { return false; } }

    public void ProcessRequest(HttpContext context)
    {
        _context = context;
        try
        {
            if (Token.Length == 0 || Token == "CHANGE_ME_BEFORE_PUBLIC_USE")
            {
                RespondJson(503, "tunnel_token_not_configured");
            }
            EnsureDirectory(StateRoot);
            Dispatch();
        }
        catch (StopProcessingException)
        {
        }
        catch (Exception ex)
        {
            context.Trace.Warn("dotnet-socks-tunnel", ex.ToString());
            if (!_streamingStarted)
            {
                WriteJson(500, new Dictionary<string, object> { { "error", "internal_error" } });
            }
        }
    }

    private void Dispatch()
    {
        if (!String.Equals(_context.Request.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
        {
            _context.Response.AppendHeader("Allow", "POST");
            RespondJson(405, "method_not_allowed");
        }
        if (RequireHttps && !IsHttpsRequest())
        {
            RespondJson(400, "https_required");
        }

        Envelope envelope = ReadEnvelope();
        Authenticate(envelope.Metadata);
        string action = GetString(envelope.Metadata, "action");
        switch (action)
        {
            case "open": HandleOpen(envelope.Metadata); return;
            case "run": HandleRun(envelope.Metadata); return;
            case "send": HandleSend(envelope.Metadata, envelope.Payload); return;
            case "close": HandleClose(envelope.Metadata); return;
            default: RespondJson(404, "unknown_action"); return;
        }
    }

    private void HandleOpen(Dictionary<string, object> request)
    {
        CleanupStaleTunnels();
        if (CountActiveTunnels() >= MaxTunnels)
        {
            RespondJson(429, "too_many_tunnels");
        }

        string host = GetString(request, "host").Trim();
        int port = GetInt(request, "port");
        if (host.Length == 0 || port < 1 || port > 65535)
        {
            RespondJson(400, "invalid_target");
        }
        if (!IsPortAllowed(port))
        {
            RespondJson(403, "target_port_not_allowed");
        }

        string ip = ResolveAllowedIpv4(host);
        if (ip == null)
        {
            RespondJson(403, "target_not_allowed");
        }

        string id = RandomHex(16);
        string finalDir = TunnelDir(id);
        string buildDir = Path.Combine(StateRoot, ".creating-" + id + "-" + RandomHex(4));
        Directory.CreateDirectory(buildDir);
        long now = UnixNow();
        try
        {
            Directory.CreateDirectory(Path.Combine(buildDir, "up"));
            WriteMeta(Path.Combine(buildDir, "meta.json"), new TunnelMeta
            {
                id = id,
                host = host,
                ip = ip,
                port = port,
                created_at = now,
                expires_at = now + MaxLifetimeSeconds
            });
            AtomicWriteText(Path.Combine(buildDir, "state.txt"), "opened");
            Directory.Move(buildDir, finalDir);
        }
        catch
        {
            RemoveTree(buildDir);
            throw;
        }

        WriteJson(201, new Dictionary<string, object>
        {
            { "id", id },
            { "expires_at", now + MaxLifetimeSeconds }
        });
        throw new StopProcessingException();
    }

    private void HandleRun(Dictionary<string, object> request)
    {
        string id = RequireTunnelId(request);
        string dir = TunnelDir(id);
        TunnelMeta meta = ReadMeta(dir);
        if (meta == null)
        {
            RespondJson(404, "tunnel_not_found");
        }
        if (meta.expires_at <= UnixNow())
        {
            RespondJson(410, "tunnel_expired");
        }

        FileStream runnerLock;
        try
        {
            runnerLock = new FileStream(Path.Combine(dir, "runner.lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        }
        catch (IOException)
        {
            RespondJson(409, "runner_already_active");
            return;
        }

        Socket target = null;
        bool connected = false;
        try
        {
            try
            {
                target = ConnectTarget(meta.ip, meta.port);
                connected = true;
            }
            catch
            {
                WriteState(dir, "connect_failed");
                runnerLock.Dispose();
                RespondJson(502, "target_connect_failed");
                return;
            }

            WriteState(dir, "running");
            PrepareStreamingResponse();
            _context.Response.BinaryWrite(new byte[4096]);
            _context.Response.Flush();

            byte[] pending = new byte[0];
            int pendingOffset = 0;
            DateTime lastActivity = DateTime.UtcNow;
            DateTime lastHeartbeat = DateTime.UtcNow;
            DateTime lastStateWrite = DateTime.UtcNow;
            byte[] readBuffer = new byte[65536];

            while (true)
            {
                DateTime now = DateTime.UtcNow;
                if (File.Exists(Path.Combine(dir, "close.flag")) || UnixNow() >= meta.expires_at)
                {
                    break;
                }
                if ((now - lastActivity).TotalSeconds >= IdleTimeoutSeconds)
                {
                    break;
                }

                int currentPending = pending.Length - pendingOffset;
                if (currentPending < MaxPendingBytes)
                {
                    byte[] loaded = LoadUpstreamChunks(dir, MaxPendingBytes - currentPending);
                    if (loaded.Length > 0)
                    {
                        byte[] combined = new byte[currentPending + loaded.Length];
                        if (currentPending > 0)
                        {
                            System.Buffer.BlockCopy(pending, pendingOffset, combined, 0, currentPending);
                        }
                        System.Buffer.BlockCopy(loaded, 0, combined, currentPending, loaded.Length);
                        pending = combined;
                        pendingOffset = 0;
                        lastActivity = now;
                    }
                }

                List<Socket> read = new List<Socket> { target };
                List<Socket> write = pending.Length > pendingOffset ? new List<Socket> { target } : new List<Socket>();
                try
                {
                    Socket.Select(read, write, null, 100000);
                }
                catch (SocketException)
                {
                    break;
                }

                if (write.Count > 0 && pending.Length > pendingOffset)
                {
                    int sent;
                    try
                    {
                        sent = target.Send(pending, pendingOffset, pending.Length - pendingOffset, SocketFlags.None);
                    }
                    catch (SocketException)
                    {
                        break;
                    }
                    if (sent <= 0) break;
                    pendingOffset += sent;
                    if (pendingOffset >= pending.Length)
                    {
                        pending = new byte[0];
                        pendingOffset = 0;
                    }
                    lastActivity = DateTime.UtcNow;
                }

                if (read.Count > 0)
                {
                    int received;
                    try
                    {
                        received = target.Receive(readBuffer, 0, readBuffer.Length, SocketFlags.None);
                    }
                    catch (SocketException)
                    {
                        break;
                    }
                    if (received <= 0) break;
                    SendFrame(readBuffer, received);
                    lastActivity = DateTime.UtcNow;
                }

                now = DateTime.UtcNow;
                if ((now - lastHeartbeat).TotalSeconds >= HeartbeatSeconds)
                {
                    SendFrame(new byte[0], 0);
                    lastHeartbeat = now;
                    if (!_context.Response.IsClientConnected) break;
                }
                if ((now - lastStateWrite).TotalSeconds >= 2.0)
                {
                    WriteState(dir, "running");
                    lastStateWrite = now;
                }
            }
        }
        finally
        {
            if (target != null)
            {
                try { target.Shutdown(SocketShutdown.Both); } catch { }
                try { target.Close(); } catch { }
            }
            try { runnerLock.Dispose(); } catch { }
            if (connected)
            {
                WriteState(dir, "closed");
            }
        }
    }

    private void HandleSend(Dictionary<string, object> request, byte[] payload)
    {
        string id = RequireTunnelId(request);
        string sequence = RequireSequence(request);
        string dir = TunnelDir(id);
        TunnelMeta meta = ReadMeta(dir);
        if (meta == null) RespondJson(404, "tunnel_not_found");
        if (meta.expires_at <= UnixNow()) RespondJson(410, "tunnel_expired");
        if (File.Exists(Path.Combine(dir, "close.flag"))) RespondJson(409, "tunnel_closing");
        if (ReadState(dir) != "running") RespondJson(409, "tunnel_not_running");

        if (payload.Length == 0)
        {
            NoContent();
        }

        string upDir = Path.Combine(dir, "up");
        EnsureDirectory(upDir);
        if (QueuedBytes(upDir) + payload.Length > MaxPendingBytes)
        {
            RespondJson(429, "upstream_queue_full");
        }

        string name = sequence.PadLeft(20, '0');
        string temp = Path.Combine(upDir, name + ".tmp");
        string final = Path.Combine(upDir, name + ".bin");
        if (File.Exists(temp) || File.Exists(final))
        {
            RespondJson(409, "duplicate_sequence");
        }

        try
        {
            using (FileStream stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                stream.Write(payload, 0, payload.Length);
                stream.Flush();
            }
            File.Move(temp, final);
        }
        catch
        {
            TryDelete(temp);
            RespondJson(500, "queue_write_failed");
        }
        NoContent();
    }

    private void HandleClose(Dictionary<string, object> request)
    {
        string id = RequireTunnelId(request);
        string dir = TunnelDir(id);
        if (ReadMeta(dir) == null)
        {
            RespondJson(404, "tunnel_not_found");
        }
        using (FileStream stream = new FileStream(Path.Combine(dir, "close.flag"), FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite))
        {
        }
        NoContent();
    }

    private Envelope ReadEnvelope()
    {
        string contentType = (_context.Request.ContentType ?? "").Split(';')[0].Trim().ToLowerInvariant();
        if (contentType != "application/octet-stream")
        {
            RespondJson(415, "unsupported_media_type");
        }

        int limit = 4 + MetadataLimit + MaxSendBytes;
        if (_context.Request.ContentLength > limit)
        {
            RespondJson(413, "request_too_large");
        }
        byte[] raw = ReadLimited(_context.Request.InputStream, limit + 1);
        if (raw.Length > limit) RespondJson(413, "request_too_large");
        if (raw.Length < 4) RespondJson(400, "invalid_envelope");

        int metadataLength = ReadInt32BigEndian(raw, 0);
        if (metadataLength < 2 || metadataLength > MetadataLimit || raw.Length < 4 + metadataLength)
        {
            RespondJson(400, "invalid_envelope");
        }

        Dictionary<string, object> metadata;
        try
        {
            string json = Encoding.UTF8.GetString(raw, 4, metadataLength);
            metadata = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(json);
        }
        catch
        {
            RespondJson(400, "invalid_metadata");
            return null;
        }
        if (metadata == null)
        {
            RespondJson(400, "invalid_metadata");
        }

        int payloadLength = raw.Length - 4 - metadataLength;
        byte[] payload = new byte[payloadLength];
        if (payloadLength > 0)
        {
            System.Buffer.BlockCopy(raw, 4 + metadataLength, payload, 0, payloadLength);
        }
        string action = GetString(metadata, "action");
        if (action != "send" && payload.Length != 0) RespondJson(400, "unexpected_payload");
        if (action == "send" && payload.Length > MaxSendBytes) RespondJson(413, "request_too_large");
        return new Envelope { Metadata = metadata, Payload = payload };
    }

    private void Authenticate(Dictionary<string, object> request)
    {
        string provided = GetString(request, "token");
        if (provided.Length == 0 || !FixedTimeEquals(Token, provided))
        {
            RespondJson(401, "unauthorized");
        }
    }

    private bool IsHttpsRequest()
    {
        if (_context.Request.IsSecureConnection) return true;
        if (!TrustForwardedProto) return false;
        string forwarded = _context.Request.Headers["X-Forwarded-Proto"];
        if (String.IsNullOrEmpty(forwarded)) return false;
        string first = forwarded.Split(',')[0].Trim();
        return String.Equals(first, "https", StringComparison.OrdinalIgnoreCase);
    }

    private static Socket ConnectTarget(string ip, int port)
    {
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        IAsyncResult result = null;
        try
        {
            result = socket.BeginConnect(IPAddress.Parse(ip), port, null, null);
            if (!result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(ConnectTimeoutSeconds)))
            {
                throw new TimeoutException("target connect timed out");
            }
            socket.EndConnect(result);
            return socket;
        }
        catch
        {
            try { socket.Close(); } catch { }
            throw;
        }
        finally
        {
            if (result != null) result.AsyncWaitHandle.Close();
        }
    }

    private void PrepareStreamingResponse()
    {
        _streamingStarted = true;
        HttpResponse response = _context.Response;
        response.Clear();
        response.StatusCode = 200;
        response.TrySkipIisCustomErrors = true;
        response.BufferOutput = false;
        response.ContentType = "application/octet-stream";
        response.Cache.SetCacheability(HttpCacheability.NoCache);
        response.Cache.SetNoStore();
        response.AppendHeader("Cache-Control", "no-store, no-cache, must-revalidate, no-transform");
        response.AppendHeader("Pragma", "no-cache");
        response.AppendHeader("X-Accel-Buffering", "no");
        response.AppendHeader("Content-Encoding", "identity");
    }

    private void SendFrame(byte[] payload, int length)
    {
        byte[] head = new byte[4];
        head[0] = (byte)((length >> 24) & 0xff);
        head[1] = (byte)((length >> 16) & 0xff);
        head[2] = (byte)((length >> 8) & 0xff);
        head[3] = (byte)(length & 0xff);
        _context.Response.BinaryWrite(head);
        if (length > 0)
        {
            if (length == payload.Length)
            {
                _context.Response.BinaryWrite(payload);
            }
            else
            {
                byte[] copy = new byte[length];
                System.Buffer.BlockCopy(payload, 0, copy, 0, length);
                _context.Response.BinaryWrite(copy);
            }
        }
        _context.Response.Flush();
    }

    private static byte[] LoadUpstreamChunks(string dir, int budget)
    {
        if (budget <= 0) return new byte[0];
        string upDir = Path.Combine(dir, "up");
        if (!Directory.Exists(upDir)) return new byte[0];
        string[] files = Directory.GetFiles(upDir, "*.bin");
        Array.Sort(files, StringComparer.Ordinal);
        using (MemoryStream buffer = new MemoryStream())
        {
            foreach (string file in files)
            {
                if (buffer.Length >= budget) break;
                string work = Path.ChangeExtension(file, ".work");
                try { File.Move(file, work); }
                catch { continue; }

                byte[] data;
                try { data = File.ReadAllBytes(work); }
                finally { TryDelete(work); }
                if (data.Length == 0) continue;

                int room = budget - (int)buffer.Length;
                int take = Math.Min(room, data.Length);
                buffer.Write(data, 0, take);
                if (take < data.Length)
                {
                    string requeue = Path.Combine(upDir, Path.GetFileNameWithoutExtension(file) + "-r.bin");
                    byte[] remainder = new byte[data.Length - take];
                    System.Buffer.BlockCopy(data, take, remainder, 0, remainder.Length);
                    File.WriteAllBytes(requeue, remainder);
                    break;
                }
            }
            return buffer.ToArray();
        }
    }

    private static long QueuedBytes(string upDir)
    {
        long total = 0;
        if (!Directory.Exists(upDir)) return 0;
        foreach (string pattern in new[] { "*.bin", "*.tmp", "*.work" })
        {
            foreach (string path in Directory.GetFiles(upDir, pattern))
            {
                try { total += new FileInfo(path).Length; } catch { }
            }
        }
        return total;
    }

    private static string ResolveAllowedIpv4(string host)
    {
        List<IPAddress> ips = new List<IPAddress>();
        IPAddress literal;
        if (IPAddress.TryParse(host, out literal))
        {
            if (literal.AddressFamily != AddressFamily.InterNetwork) return null;
            ips.Add(literal);
        }
        else
        {
            if (!HostPattern.IsMatch(host)) return null;
            try
            {
                foreach (IPAddress candidate in Dns.GetHostAddresses(host))
                {
                    if (candidate.AddressFamily == AddressFamily.InterNetwork) ips.Add(candidate);
                }
            }
            catch { return null; }
            if (ips.Count == 0) return null;
        }

        foreach (IPAddress ip in ips)
        {
            string text = ip.ToString();
            if (MatchesAnyCidr(text, DeniedCidrs)) return null;
            if (!MatchesAnyCidr(text, AllowedCidrs)) return null;
        }
        return ips[0].ToString();
    }

    private static bool IsPortAllowed(int port)
    {
        foreach (int[] rule in AllowedPorts)
        {
            if (port >= rule[0] && port <= rule[1]) return true;
        }
        return false;
    }

    private static bool MatchesAnyCidr(string ip, string[] cidrs)
    {
        foreach (string cidr in cidrs)
        {
            if (CidrContains(cidr, ip)) return true;
        }
        return false;
    }

    private static bool CidrContains(string cidr, string ip)
    {
        string[] parts = cidr.Split('/');
        if (parts.Length != 2) return false;
        IPAddress network;
        IPAddress address;
        int prefix;
        if (!IPAddress.TryParse(parts[0], out network) || !IPAddress.TryParse(ip, out address) ||
            network.AddressFamily != AddressFamily.InterNetwork || address.AddressFamily != AddressFamily.InterNetwork ||
            !Int32.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32)
        {
            return false;
        }
        byte[] n = network.GetAddressBytes();
        byte[] a = address.GetAddressBytes();
        int fullBytes = prefix / 8;
        int remaining = prefix % 8;
        for (int i = 0; i < fullBytes; i++) if (n[i] != a[i]) return false;
        if (remaining == 0) return true;
        int mask = (0xff << (8 - remaining)) & 0xff;
        return (n[fullBytes] & mask) == (a[fullBytes] & mask);
    }

    private string RequireTunnelId(Dictionary<string, object> request)
    {
        string id = GetString(request, "id").ToLowerInvariant();
        if (!TunnelIdPattern.IsMatch(id))
        {
            RespondJson(400, "invalid_tunnel_id");
        }
        return id;
    }

    private string RequireSequence(Dictionary<string, object> request)
    {
        string sequence = GetString(request, "seq");
        if (!SequencePattern.IsMatch(sequence))
        {
            RespondJson(400, "invalid_sequence");
        }
        return sequence;
    }

    private static string GetString(Dictionary<string, object> values, string key)
    {
        object value;
        if (!values.TryGetValue(key, out value) || value == null) return "";
        return value as string ?? Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture);
    }

    private static int GetInt(Dictionary<string, object> values, string key)
    {
        object value;
        if (!values.TryGetValue(key, out value) || value == null) return 0;
        int result;
        if (value is int) return (int)value;
        if (Int32.TryParse(Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture), out result)) return result;
        return 0;
    }

    private static TunnelMeta ReadMeta(string dir)
    {
        string path = Path.Combine(dir, "meta.json");
        if (!File.Exists(path)) return null;
        try { return new JavaScriptSerializer().Deserialize<TunnelMeta>(File.ReadAllText(path, Encoding.UTF8)); }
        catch { return null; }
    }

    private static void WriteMeta(string path, TunnelMeta meta)
    {
        AtomicWriteText(path, new JavaScriptSerializer().Serialize(meta));
    }

    private static string ReadState(string dir)
    {
        string path = Path.Combine(dir, "state.txt");
        try { return File.Exists(path) ? File.ReadAllText(path, Encoding.UTF8).Trim() : null; }
        catch { return null; }
    }

    private static void WriteState(string dir, string state)
    {
        if (!Directory.Exists(dir)) return;
        try { AtomicWriteText(Path.Combine(dir, "state.txt"), state); } catch { }
    }

    private static void AtomicWriteText(string path, string contents)
    {
        string temp = path + "." + RandomHex(4) + ".tmp";
        File.WriteAllText(temp, contents, Encoding.UTF8);
        try
        {
            if (File.Exists(path))
            {
                try { File.Replace(temp, path, null); }
                catch
                {
                    TryDelete(path);
                    File.Move(temp, path);
                }
            }
            else
            {
                File.Move(temp, path);
            }
        }
        finally
        {
            TryDelete(temp);
        }
    }

    private static void CleanupStaleTunnels()
    {
        if (!Directory.Exists(StateRoot)) return;
        long now = UnixNow();
        foreach (string dir in Directory.GetDirectories(StateRoot))
        {
            string name = Path.GetFileName(dir);
            if (name.StartsWith(".creating-", StringComparison.Ordinal))
            {
                try
                {
                    if ((DateTime.UtcNow - Directory.GetLastWriteTimeUtc(dir)).TotalSeconds > 60) RemoveTree(dir);
                }
                catch { }
                continue;
            }
            if (!TunnelIdPattern.IsMatch(name)) continue;
            TunnelMeta meta = ReadMeta(dir);
            string state = ReadState(dir);
            if (meta == null || state == "closed" || state == "connect_failed" || meta.expires_at + 60 < now)
            {
                RemoveTree(dir);
            }
        }
    }

    private static int CountActiveTunnels()
    {
        int count = 0;
        long now = UnixNow();
        if (!Directory.Exists(StateRoot)) return 0;
        foreach (string dir in Directory.GetDirectories(StateRoot))
        {
            string id = Path.GetFileName(dir);
            if (!TunnelIdPattern.IsMatch(id)) continue;
            TunnelMeta meta = ReadMeta(dir);
            string state = ReadState(dir);
            if (meta != null && meta.expires_at > now && (state == "opened" || state == "running")) count++;
        }
        return count;
    }

    private static string TunnelDir(string id)
    {
        return Path.Combine(StateRoot, id);
    }

    private static void EnsureDirectory(string path)
    {
        if (!Directory.Exists(path)) Directory.CreateDirectory(path);
    }

    private static void RemoveTree(string path)
    {
        try { if (Directory.Exists(path)) Directory.Delete(path, true); else TryDelete(path); } catch { }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    private void RespondJson(int status, string code)
    {
        WriteJson(status, new Dictionary<string, object> { { "error", code } });
        throw new StopProcessingException();
    }

    private void WriteJson(int status, object payload)
    {
        HttpResponse response = _context.Response;
        response.Clear();
        response.StatusCode = status;
        response.TrySkipIisCustomErrors = true;
        response.ContentType = "application/json; charset=utf-8";
        response.Cache.SetCacheability(HttpCacheability.NoCache);
        response.Cache.SetNoStore();
        response.Write(new JavaScriptSerializer().Serialize(payload));
    }

    private void NoContent()
    {
        HttpResponse response = _context.Response;
        response.Clear();
        response.StatusCode = 204;
        response.TrySkipIisCustomErrors = true;
        response.Cache.SetNoStore();
        throw new StopProcessingException();
    }

    private static byte[] ReadLimited(Stream input, int maxBytes)
    {
        using (MemoryStream output = new MemoryStream())
        {
            byte[] buffer = new byte[8192];
            while (output.Length < maxBytes)
            {
                int want = Math.Min(buffer.Length, maxBytes - (int)output.Length);
                int read = input.Read(buffer, 0, want);
                if (read <= 0) break;
                output.Write(buffer, 0, read);
            }
            return output.ToArray();
        }
    }

    private static int ReadInt32BigEndian(byte[] data, int offset)
    {
        return (data[offset] << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3];
    }

    private static bool FixedTimeEquals(string expected, string actual)
    {
        byte[] a = Encoding.UTF8.GetBytes(expected);
        byte[] b = Encoding.UTF8.GetBytes(actual);
        int diff = a.Length ^ b.Length;
        int max = Math.Max(a.Length, b.Length);
        for (int i = 0; i < max; i++)
        {
            byte av = i < a.Length ? a[i] : (byte)0;
            byte bv = i < b.Length ? b[i] : (byte)0;
            diff |= av ^ bv;
        }
        return diff == 0;
    }

    private static string RandomHex(int bytes)
    {
        byte[] raw = new byte[bytes];
        using (RandomNumberGenerator rng = RandomNumberGenerator.Create()) rng.GetBytes(raw);
        StringBuilder builder = new StringBuilder(bytes * 2);
        foreach (byte value in raw) builder.Append(value.ToString("x2"));
        return builder.ToString();
    }

    private static long UnixNow()
    {
        return (long)(DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
    }

    private sealed class Envelope
    {
        public Dictionary<string, object> Metadata;
        public byte[] Payload;
    }

    public sealed class TunnelMeta
    {
        public string id { get; set; }
        public string host { get; set; }
        public string ip { get; set; }
        public int port { get; set; }
        public long created_at { get; set; }
        public long expires_at { get; set; }
    }

    private sealed class StopProcessingException : Exception { }

}

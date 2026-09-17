<%@ page import="java.io.*,java.net.*,java.nio.*,java.nio.channels.*,java.nio.charset.StandardCharsets,java.security.SecureRandom,java.util.*,java.util.concurrent.*,java.util.concurrent.atomic.*,java.util.regex.Pattern,javax.servlet.*,javax.servlet.http.*" %>
<%!
    private static final int META_LIMIT = 8192;
    private static final String TOKEN = "CHANGE_ME_BEFORE_PUBLIC_USE";
    private static final boolean REQUIRE_HTTPS = true;
    private static final boolean TRUST_FORWARDED_PROTO = false;
    private static final int CONNECT_TIMEOUT = 8;
    private static final int IDLE_TIMEOUT = 300;
    private static final int MAX_LIFETIME = 3600;
    private static final int MAX_SEND = 262144;
    private static final int MAX_PENDING = 1048576;
    private static final int MAX_TUNNELS = 32;
    private static final int HEARTBEAT = 5;
    private static final String[] ALLOWED_CIDRS = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"};
    private static final String[] DENIED_CIDRS = {"0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"};
    private static final int[][] ALLOWED_PORTS = {{22,22},{80,80},{443,443},{445,445},{3389,3389},{8123,8123}};
    private static final Pattern ID_RE = Pattern.compile("^[a-f0-9]{32}$");
    private static final Pattern SEQ_RE = Pattern.compile("^(?:0|[1-9][0-9]{0,17})$");
    private static final Pattern HOST_RE = Pattern.compile("^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$");
    private static final SecureRandom RNG = new SecureRandom();
    private static final ConcurrentHashMap<String,Tunnel> TUNNELS = new ConcurrentHashMap<String,Tunnel>();

    private static final class Stop extends RuntimeException { private static final long serialVersionUID = 1L; }
    private static final class Envelope { Map<String,String> meta; byte[] payload; }
    private static final class Tunnel {
        String id, host, ip;
        int port;
        long createdAt, expiresAt;
        volatile String state = "opened";
        volatile boolean closing;
        final AtomicBoolean runnerActive = new AtomicBoolean(false);
        final AtomicLong pendingBytes = new AtomicLong(0);
        final ConcurrentSkipListMap<Long,byte[]> queue = new ConcurrentSkipListMap<Long,byte[]>();
    }

    private void dispatch(HttpServletRequest req, HttpServletResponse resp) throws Exception {
        if (TOKEN.length() == 0 || "CHANGE_ME_BEFORE_PUBLIC_USE".equals(TOKEN)) json(resp,503,"tunnel_token_not_configured");
        if (!"POST".equalsIgnoreCase(req.getMethod())) { resp.setHeader("Allow","POST"); json(resp,405,"method_not_allowed"); }
        if (REQUIRE_HTTPS && !isHttps(req)) json(resp,400,"https_required");

        Envelope env = readEnvelope(req,resp);
        if (!fixedEquals(TOKEN,val(env.meta,"token"))) json(resp,401,"unauthorized");
        String action = val(env.meta,"action");
        if ("open".equals(action)) open(resp,env.meta);
        else if ("run".equals(action)) run(resp,env.meta);
        else if ("send".equals(action)) send(resp,env.meta,env.payload);
        else if ("close".equals(action)) closeTunnel(resp,env.meta);
        else json(resp,404,"unknown_action");
    }

    private void open(HttpServletResponse resp, Map<String,String> m) throws Exception {
        cleanup();
        int active = 0;
        for (Tunnel t : TUNNELS.values()) if (("opened".equals(t.state)||"running".equals(t.state)) && t.expiresAt > now()) active++;
        if (active >= MAX_TUNNELS) json(resp,429,"too_many_tunnels");
        String host = val(m,"host").trim();
        int port = toInt(val(m,"port"));
        if (host.length()==0 || port<1 || port>65535) json(resp,400,"invalid_target");
        if (!portAllowed(port)) json(resp,403,"target_port_not_allowed");
        String ip = resolveAllowed(host);
        if (ip == null) json(resp,403,"target_not_allowed");

        Tunnel t = new Tunnel();
        t.id = randomHex(16); t.host = host; t.ip = ip; t.port = port;
        t.createdAt = now(); t.expiresAt = t.createdAt + MAX_LIFETIME;
        TUNNELS.put(t.id,t);
        resp.reset(); resp.setStatus(201); resp.setContentType("application/json; charset=utf-8"); resp.setHeader("Cache-Control","no-store");
        resp.getWriter().write("{\"id\":\""+t.id+"\",\"expires_at\":"+t.expiresAt+"}");
        throw new Stop();
    }

    private void run(HttpServletResponse resp, Map<String,String> m) throws Exception {
        Tunnel t = tunnel(resp,m);
        if (t.expiresAt <= now()) json(resp,410,"tunnel_expired");
        if (!t.runnerActive.compareAndSet(false,true)) json(resp,409,"runner_already_active");
        SocketChannel channel = null; Selector selector = null; boolean connected = false;
        try {
            try { channel = connect(t.ip,t.port); connected = true; }
            catch (Exception e) { t.state="connect_failed"; json(resp,502,"target_connect_failed"); }
            t.state="running";
            resp.reset(); resp.setStatus(200); resp.setContentType("application/octet-stream");
            resp.setHeader("Cache-Control","no-store, no-cache, must-revalidate, no-transform");
            resp.setHeader("Pragma","no-cache"); resp.setHeader("X-Accel-Buffering","no"); resp.setHeader("Content-Encoding","identity");
            ServletOutputStream out = resp.getOutputStream(); out.write(new byte[4096]); out.flush();

            selector = Selector.open(); channel.register(selector,SelectionKey.OP_READ);
            ByteBuffer pending = ByteBuffer.allocate(0), readBuf = ByteBuffer.allocate(65536);
            long lastActivity=System.nanoTime(), lastHeartbeat=lastActivity;
            while (!t.closing && now() < t.expiresAt && seconds(lastActivity,System.nanoTime()) < IDLE_TIMEOUT) {
                if (!pending.hasRemaining()) {
                    Map.Entry<Long,byte[]> e=t.queue.pollFirstEntry();
                    if (e!=null) { pending=ByteBuffer.wrap(e.getValue()); t.pendingBytes.addAndGet(-e.getValue().length); lastActivity=System.nanoTime(); }
                }
                SelectionKey key=channel.keyFor(selector); key.interestOps(SelectionKey.OP_READ | (pending.hasRemaining()?SelectionKey.OP_WRITE:0));
                selector.select(100);
                if (key.isValid() && key.isWritable() && pending.hasRemaining()) { int n=channel.write(pending); if(n>0) lastActivity=System.nanoTime(); }
                if (key.isValid() && key.isReadable()) {
                    readBuf.clear(); int n=channel.read(readBuf); if(n<0) break;
                    if(n>0){ frame(out,readBuf.array(),n); lastActivity=System.nanoTime(); }
                }
                selector.selectedKeys().clear();
                long n=System.nanoTime(); if(seconds(lastHeartbeat,n)>=HEARTBEAT){ frame(out,new byte[0],0); lastHeartbeat=n; }
            }
        } finally {
            if(selector!=null) try{selector.close();}catch(Exception ignored){}
            if(channel!=null) try{channel.close();}catch(Exception ignored){}
            if (connected) t.state="closed";
            t.runnerActive.set(false);
        }
    }

    private void send(HttpServletResponse resp, Map<String,String> m, byte[] payload) throws Exception {
        Tunnel t=tunnel(resp,m);
        if(t.expiresAt<=now()) json(resp,410,"tunnel_expired");
        if(t.closing) json(resp,409,"tunnel_closing");
        if(!"running".equals(t.state)) json(resp,409,"tunnel_not_running");
        String seqText=val(m,"seq"); if(!SEQ_RE.matcher(seqText).matches()) json(resp,400,"invalid_sequence");
        if(payload.length==0) noContent(resp);
        long seq; try{seq=Long.parseLong(seqText);}catch(Exception e){json(resp,400,"invalid_sequence");return;}
        if(t.pendingBytes.addAndGet(payload.length)>MAX_PENDING){t.pendingBytes.addAndGet(-payload.length);json(resp,429,"upstream_queue_full");}
        if(t.queue.putIfAbsent(seq,payload)!=null){t.pendingBytes.addAndGet(-payload.length);json(resp,409,"duplicate_sequence");}
        noContent(resp);
    }

    private void closeTunnel(HttpServletResponse resp, Map<String,String> m) throws Exception { Tunnel t=tunnel(resp,m); t.closing=true; noContent(resp); }
    private Tunnel tunnel(HttpServletResponse resp, Map<String,String> m) throws Exception {
        String id=val(m,"id").toLowerCase(Locale.ROOT); if(!ID_RE.matcher(id).matches()) json(resp,400,"invalid_tunnel_id");
        Tunnel t=TUNNELS.get(id); if(t==null) json(resp,404,"tunnel_not_found"); return t;
    }

    private Envelope readEnvelope(HttpServletRequest req,HttpServletResponse resp) throws Exception {
        String ct=req.getContentType(); if(ct==null || !"application/octet-stream".equalsIgnoreCase(ct.split(";",2)[0].trim())) json(resp,415,"unsupported_media_type");
        int limit=4+META_LIMIT+MAX_SEND; if(req.getContentLength()>limit) json(resp,413,"request_too_large");
        byte[] raw=limited(req.getInputStream(),limit+1); if(raw.length>limit) json(resp,413,"request_too_large"); if(raw.length<4) json(resp,400,"invalid_envelope");
        int ml=ByteBuffer.wrap(raw,0,4).order(ByteOrder.BIG_ENDIAN).getInt(); if(ml<2||ml>META_LIMIT||raw.length<4+ml) json(resp,400,"invalid_envelope");
        Map<String,String> meta; try{meta=parseJson(new String(raw,4,ml,StandardCharsets.UTF_8));}catch(Exception e){json(resp,400,"invalid_metadata");return null;}
        byte[] payload=Arrays.copyOfRange(raw,4+ml,raw.length); String action=val(meta,"action");
        if(!"send".equals(action)&&payload.length!=0) json(resp,400,"unexpected_payload"); if("send".equals(action)&&payload.length>MAX_SEND) json(resp,413,"request_too_large");
        Envelope e=new Envelope(); e.meta=meta;e.payload=payload;return e;
    }

    private static SocketChannel connect(String ip,int port)throws Exception{
        SocketChannel c=SocketChannel.open();c.configureBlocking(false);c.connect(new InetSocketAddress(InetAddress.getByName(ip),port));
        long d=System.nanoTime()+TimeUnit.SECONDS.toNanos(CONNECT_TIMEOUT); while(!c.finishConnect()){if(System.nanoTime()>=d){c.close();throw new SocketTimeoutException();}Thread.sleep(10);}return c;
    }
    private static void frame(OutputStream out,byte[] data,int n)throws IOException{out.write(ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(n).array());if(n>0)out.write(data,0,n);out.flush();}
    private static boolean isHttps(HttpServletRequest r){if(r.isSecure())return true;if(!TRUST_FORWARDED_PROTO)return false;String h=r.getHeader("X-Forwarded-Proto");return h!=null&&"https".equalsIgnoreCase(h.split(",",2)[0].trim());}
    private static boolean portAllowed(int p){for(int[] r:ALLOWED_PORTS)if(p>=r[0]&&p<=r[1])return true;return false;}
    private static String resolveAllowed(String host){
        try{
            List<Inet4Address> list=new ArrayList<Inet4Address>();
            if(host.matches("^[0-9.]+$")){InetAddress a=InetAddress.getByName(host);if(!(a instanceof Inet4Address))return null;list.add((Inet4Address)a);}
            else{if(!HOST_RE.matcher(host).matches())return null;for(InetAddress a:InetAddress.getAllByName(host))if(a instanceof Inet4Address)list.add((Inet4Address)a);}
            if(list.isEmpty())return null;for(Inet4Address a:list){String ip=a.getHostAddress();if(anyCidr(ip,DENIED_CIDRS)||!anyCidr(ip,ALLOWED_CIDRS))return null;}return list.get(0).getHostAddress();
        }catch(Exception e){return null;}
    }
    private static boolean anyCidr(String ip,String[] ranges){for(String c:ranges)if(cidr(c,ip))return true;return false;}
    private static boolean cidr(String c,String ip){try{String[] p=c.split("/",2);InetAddress n=InetAddress.getByName(p[0]),a=InetAddress.getByName(ip);if(!(n instanceof Inet4Address)||!(a instanceof Inet4Address))return false;int bits=Integer.parseInt(p[1]);if(bits<0||bits>32)return false;byte[] nb=n.getAddress(),ab=a.getAddress();int full=bits/8,rem=bits%8;for(int i=0;i<full;i++)if(nb[i]!=ab[i])return false;if(rem==0)return true;int mask=(0xff<<(8-rem))&0xff;return((nb[full]&0xff)&mask)==((ab[full]&0xff)&mask);}catch(Exception e){return false;}}
    private static void cleanup(){long n=now();for(Map.Entry<String,Tunnel> e:TUNNELS.entrySet()){Tunnel t=e.getValue();if(("closed".equals(t.state)||"connect_failed".equals(t.state)||t.expiresAt+60<n)&&!t.runnerActive.get())TUNNELS.remove(e.getKey(),t);}}
    private static void json(HttpServletResponse r,int s,String code)throws IOException{r.reset();r.setStatus(s);r.setContentType("application/json; charset=utf-8");r.setHeader("Cache-Control","no-store");r.getWriter().write("{\"error\":\""+code+"\"}");throw new Stop();}
    private static void noContent(HttpServletResponse r){r.reset();r.setStatus(204);r.setHeader("Cache-Control","no-store");throw new Stop();}
    private static byte[] limited(InputStream in,int max)throws IOException{ByteArrayOutputStream o=new ByteArrayOutputStream();byte[] b=new byte[8192];while(o.size()<max){int n=in.read(b,0,Math.min(b.length,max-o.size()));if(n<0)break;if(n>0)o.write(b,0,n);}return o.toByteArray();}
    private static String val(Map<String,String> m,String k){String v=m.get(k);return v==null?"":v;}
    private static int toInt(String s){try{return Integer.parseInt(s);}catch(Exception e){return 0;}}
    private static long now(){return System.currentTimeMillis()/1000L;} private static double seconds(long a,long b){return(b-a)/1e9;}
    private static String randomHex(int n){byte[] b=new byte[n];RNG.nextBytes(b);StringBuilder s=new StringBuilder(n*2);for(byte x:b)s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
    private static boolean fixedEquals(String a,String b){byte[] x=a.getBytes(StandardCharsets.UTF_8),y=b.getBytes(StandardCharsets.UTF_8);int d=x.length^y.length,m=Math.max(x.length,y.length);for(int i=0;i<m;i++)d|=(i<x.length?x[i]&255:0)^(i<y.length?y[i]&255:0);return d==0;}

    private static Map<String,String> parseJson(String text){
        Map<String,String> m=new HashMap<String,String>();int[] p={0};ws(text,p);need(text,p,'{');ws(text,p);if(peek(text,p,'}')){p[0]++;return m;}
        while(true){ws(text,p);String k=jstr(text,p);ws(text,p);need(text,p,':');ws(text,p);String v=peek(text,p,'\"')?jstr(text,p):prim(text,p);m.put(k,v);ws(text,p);if(peek(text,p,'}')){p[0]++;ws(text,p);if(p[0]!=text.length())throw new IllegalArgumentException();return m;}need(text,p,',');}
    }
    private static String jstr(String s,int[] p){need(s,p,'\"');StringBuilder o=new StringBuilder();while(p[0]<s.length()){char c=s.charAt(p[0]++);if(c=='\"')return o.toString();if(c=='\\'){if(p[0]>=s.length())throw new IllegalArgumentException();char e=s.charAt(p[0]++);if(e=='u'){if(p[0]+4>s.length())throw new IllegalArgumentException();o.append((char)Integer.parseInt(s.substring(p[0],p[0]+4),16));p[0]+=4;}else{String f="\"\\/bfnrt",t="\"\\/\b\f\n\r\t";int i=f.indexOf(e);if(i<0)throw new IllegalArgumentException();o.append(t.charAt(i));}}else{o.append(c);}}throw new IllegalArgumentException();}
    private static String prim(String s,int[] p){int a=p[0];while(p[0]<s.length()&&",}".indexOf(s.charAt(p[0]))<0&&!Character.isWhitespace(s.charAt(p[0])))p[0]++;if(a==p[0])throw new IllegalArgumentException();String v=s.substring(a,p[0]);if(!v.matches("-?(?:0|[1-9][0-9]*)|true|false|null"))throw new IllegalArgumentException();return"null".equals(v)?"":v;}
    private static void ws(String s,int[] p){while(p[0]<s.length()&&Character.isWhitespace(s.charAt(p[0])))p[0]++;}private static boolean peek(String s,int[] p,char c){return p[0]<s.length()&&s.charAt(p[0])==c;}private static void need(String s,int[] p,char c){if(!peek(s,p,c))throw new IllegalArgumentException();p[0]++;}
%>
<%
    try { dispatch(request,response); }
    catch (Stop ignored) { }
    catch (Exception ex) {
        application.log("[java-socks-tunnel] request failed",ex);
        if(!response.isCommitted()){
            try{response.reset();response.setStatus(500);response.setContentType("application/json; charset=utf-8");response.setHeader("Cache-Control","no-store");response.getWriter().write("{\"error\":\"internal_error\"}");}catch(Exception ignored){}
        }
    }
%>

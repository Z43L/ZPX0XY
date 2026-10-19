package io.zpx0xy;

import android.content.Context;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Standalone device-side HTTP/1 proxy and TLS inspector. */
final class ProxyEngine {
    private static final int FIRST_PORT = 8080;
    private static final int BODY_LIMIT = 32 * 1024 * 1024;
    private final Context context;
    private final WorkbenchStore store;
    private final CertificateAuthority ca;
    private final ExecutorService pool;
    private final AtomicBoolean enabled = new AtomicBoolean(true);
    private final AtomicBoolean stopping = new AtomicBoolean(false);
    private final ConcurrentHashMap<String, Pending> queue = new ConcurrentHashMap<>();
    private volatile ServerSocket listener;
    private volatile int listeningPort = FIRST_PORT;

    ProxyEngine(Context context, WorkbenchStore store, CertificateAuthority ca, ExecutorService pool) {
        this.context=context.getApplicationContext();this.store=store;this.ca=ca;this.pool=pool;
    }
    boolean isEnabled() { return enabled.get(); }
    int port() { return listeningPort; }
    void setEnabled(boolean value) { enabled.set(value); }
    void stop() { stopping.set(true); try { if(listener!=null)listener.close(); } catch(Exception ignored){}; for(Pending p:queue.values())p.ready.countDown(); }
    void start() throws Exception {
        ServerSocket bound=null;
        for(int port=FIRST_PORT;port<FIRST_PORT+21&&!stopping.get();port++) {
            ServerSocket candidate=new ServerSocket();
            try { candidate.setReuseAddress(true);candidate.bind(new InetSocketAddress("127.0.0.1",port));bound=candidate;listeningPort=port;break; }
            catch(Exception busy) { try{candidate.close();}catch(Exception ignored){};android.util.Log.i("ZPX0XY","Proxy port "+port+" unavailable; trying the next port"); }
        }
        if(bound==null)throw new java.io.IOException("No free local proxy port from "+FIRST_PORT+" through "+(FIRST_PORT+20));
        listener=bound;final ServerSocket server=bound;
        pool.execute(() -> {
            try(server) { while(!stopping.get()) { try { Socket socket=server.accept();pool.execute(() -> handleClient(socket)); } catch(java.net.SocketException closed) { if(!stopping.get())android.util.Log.e("ZPX0XY","Proxy listener failed",closed);break; } } }
            catch(Exception e) { if(!stopping.get())android.util.Log.e("ZPX0XY","Proxy listener failed on "+listeningPort,e); }
        });
    }

    private void handleClient(Socket socket) {
        try (Socket client=socket) {
            client.setSoTimeout(30_000);
            BufferedInputStream in=new BufferedInputStream(client.getInputStream());
            BufferedOutputStream out=new BufferedOutputStream(client.getOutputStream());
            String line=WorkbenchService.readLine(in);if(line==null)return;
            String[] parts=line.split(" ",3);if(parts.length<2)return;
            String method=parts[0].toUpperCase(Locale.ROOT), target=parts[1];
            JSONObject headers=WorkbenchService.readHeaders(in);
            if(method.equals("CONNECT")) { handleConnect(client,out,target);return; }
            if(!enabled.get()) { sendSimple(out,503,"Proxy paused");return; }
            byte[] body=readRequestBody(in,headers);
            String url=absoluteUrl(target,headers.optString("Host",""),false);
            Request request=new Request(method,url,headers,body,"proxy");
            Result result=perform(request,true);
            writeResponse(out,result);
        } catch(Exception e) { android.util.Log.d("ZPX0XY","Proxy connection ended: "+e.getMessage()); }
    }

    private void handleConnect(Socket client,OutputStream downstream,String authority) throws Exception {
        if(!enabled.get()) { sendSimple(downstream,503,"Proxy paused");return; }
        String host=authority;int port=443;int colon=authority.lastIndexOf(':');
        if(colon>0){host=authority.substring(0,colon).replace("[","").replace("]","");try{port=Integer.parseInt(authority.substring(colon+1));}catch(Exception ignored){}}
        if(!"true".equals(store.setting("tls_intercept","false"))) { tunnel(client,downstream,host,port);return; }
        downstream.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ZPX0XY\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));downstream.flush();
        SSLContext context=ca.contextFor(host);
        SSLSocket tls=(SSLSocket)context.getSocketFactory().createSocket(client,host,port,false);
        tls.setUseClientMode(false);tls.setSoTimeout(30_000);tls.startHandshake();
        try (SSLSocket secure=tls) {
            BufferedInputStream in=new BufferedInputStream(secure.getInputStream());BufferedOutputStream out=new BufferedOutputStream(secure.getOutputStream());
            String line=WorkbenchService.readLine(in);if(line==null)return;String[] parts=line.split(" ",3);if(parts.length<2)return;
            JSONObject headers=WorkbenchService.readHeaders(in);byte[] body=readRequestBody(in,headers);
            Request request=new Request(parts[0].toUpperCase(Locale.ROOT),absoluteUrl(parts[1],headers.optString("Host",host),true),headers,body,"proxy");
            writeResponse(out,perform(request,true));
        }
    }

    private void tunnel(Socket client,OutputStream downstream,String host,int port) throws Exception {
        Socket upstream=new Socket();upstream.connect(new InetSocketAddress(host,port),10_000);upstream.setSoTimeout(30_000);
        downstream.write("HTTP/1.1 200 Connection Established\r\nProxy-Agent: ZPX0XY\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));downstream.flush();
        CountDownLatch done=new CountDownLatch(2);Socket origin=upstream;
        pool.execute(() -> { copy(client,origin);done.countDown(); });
        copy(origin,client);done.countDown();done.await(35,TimeUnit.SECONDS);
        JSONObject empty=new JSONObject();store.saveRequest(WorkbenchService.now(),"CONNECT",host,":"+port,"https://"+host+":"+port+"/",200,empty,"",empty,"TLS tunnel passed through · encrypted contents not inspected",0,"proxy","");
    }
    private void copy(Socket from,Socket to) { try { byte[] b=new byte[32768];int n;while((n=from.getInputStream().read(b))!=-1){to.getOutputStream().write(b,0,n);to.getOutputStream().flush();} } catch(Exception ignored) { } finally { try{to.shutdownOutput();}catch(Exception ignored){} } }

    private Result perform(Request request,boolean allowIntercept) {
        long started=System.nanoTime();Integer status=null;JSONObject responseHeaders=new JSONObject();byte[] responseBody=new byte[0];String error="";URI uri=null;
        try {
            if(allowIntercept&&"true".equals(store.setting("intercept_enabled","false"))) request=hold(request);
            if(!request.error.isEmpty()) { status=403;error=request.error;responseBody=error.getBytes(StandardCharsets.UTF_8);throw new DroppedRequest(); }
            if(!request.source.equals("automation"))request=applyRules(request,"request");uri=URI.create(request.url);
            if(!Arrays.asList("http","https").contains(uri.getScheme())||uri.getHost()==null)throw new IllegalArgumentException("URL must be an absolute HTTP or HTTPS URL");
            int port=uri.getPort()>0?uri.getPort():(uri.getScheme().equals("https")?443:80);
            Socket origin;
            if(uri.getScheme().equals("https")) {
                SSLSocket secure=(SSLSocket)SSLSocketFactory.getDefault().createSocket();secure.connect(new InetSocketAddress(uri.getHost(),port),10_000);
                javax.net.ssl.SSLParameters params=secure.getSSLParameters();params.setEndpointIdentificationAlgorithm("HTTPS");
                try{params.setServerNames(java.util.Collections.singletonList(new javax.net.ssl.SNIHostName(uri.getHost())));}catch(Exception ignored){}
                secure.setSSLParameters(params);secure.setSoTimeout(30_000);secure.startHandshake();origin=secure;
            } else { origin=new Socket();origin.connect(new InetSocketAddress(uri.getHost(),port),10_000);origin.setSoTimeout(30_000); }
            try(Socket upstream=origin) {
                BufferedOutputStream out=new BufferedOutputStream(upstream.getOutputStream());
                String path=uri.getRawPath();if(path==null||path.isEmpty())path="/";if(uri.getRawQuery()!=null)path+="?"+uri.getRawQuery();
                out.write((request.method+" "+path+" HTTP/1.1\r\n").getBytes(StandardCharsets.ISO_8859_1));
                boolean hasHost=false;
                for(String key:jsonKeys(request.headers)){if(key.equalsIgnoreCase("host"))hasHost=true;if(key.equalsIgnoreCase("connection")||key.equalsIgnoreCase("proxy-connection")||key.equalsIgnoreCase("transfer-encoding")||key.equalsIgnoreCase("content-length"))continue;out.write((safe(key)+": "+safe(request.headers.optString(key))+"\r\n").getBytes(StandardCharsets.ISO_8859_1));}
                if(!hasHost)out.write(("Host: "+uri.getRawAuthority()+"\r\n").getBytes(StandardCharsets.ISO_8859_1));
                out.write(("Content-Length: "+request.body.length+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));out.write(request.body);out.flush();
                BufferedInputStream in=new BufferedInputStream(upstream.getInputStream());String statusLine=WorkbenchService.readLine(in);if(statusLine==null)throw new java.io.IOException("Empty upstream response");
                if (statusLine.startsWith("HTTP/")) {
                    String[] statusParts=statusLine.split(" ",3);
                    if(statusParts.length<2)throw new java.io.IOException("Malformed upstream status line: "+statusLine);
                    status=Integer.parseInt(statusParts[1]);
                    responseHeaders=WorkbenchService.readHeaders(in);responseBody=readResponseBody(in,responseHeaders,request.method,status);
                } else {
                    // Some captive portals and legacy HTTP/0.9 endpoints return the body
                    // without an HTTP status line. Preserve that page instead of failing
                    // with NumberFormatException (for example, on an initial <html> line).
                    android.util.Log.i("ZPX0XY","Received a body-only upstream response from "+uri.getHost());
                    status=200;
                    responseHeaders.put("Content-Type",statusLine.trim().toLowerCase(Locale.ROOT).startsWith("<")?"text/html; charset=utf-8":"text/plain; charset=utf-8");
                    ByteArrayOutputStream legacy=new ByteArrayOutputStream();
                    legacy.write(statusLine.getBytes(StandardCharsets.ISO_8859_1));legacy.write('\n');
                    byte[] buffer=new byte[16384];int n;
                    while((n=in.read(buffer))!=-1){if(legacy.size()+n>BODY_LIMIT)throw new java.io.IOException("Legacy upstream response exceeds 32 MiB limit");legacy.write(buffer,0,n);}
                    responseBody=legacy.toByteArray();
                }
            }
            if(isText(responseHeaders))responseBody=replaceBody(responseBody,"response");
        } catch(DroppedRequest ignored) { } catch(Exception e){error=e.getMessage()==null?e.toString():e.getMessage();}
        long duration=(System.nanoTime()-started)/1_000_000L;
        String host=uri!=null&&uri.getHost()!=null?uri.getHost():"";String path=uri!=null?(uri.getRawPath()==null?"/":uri.getRawPath())+(uri.getRawQuery()==null?"":"?"+uri.getRawQuery()):request.url;
        try { long id=store.saveRequest(WorkbenchService.now(),request.method,host,path,request.url,status,request.headers,WorkbenchStore.text(request.body),responseHeaders,WorkbenchStore.text(responseBody),duration,request.source,error);return new Result(id,status,responseHeaders,responseBody,duration,error); }
        catch(Exception e){return new Result(-1,status,responseHeaders,responseBody,duration,error.isEmpty()?e.getMessage():error);}
    }

    private Request hold(Request request) {
        String id=UUID.randomUUID().toString().substring(0,12);Pending p=new Pending(id,request);queue.put(id,p);
        try { if(!p.ready.await(180,TimeUnit.SECONDS))return request; } catch(InterruptedException e){Thread.currentThread().interrupt();return request;}
        if(p.dropped)return request.withErrorDrop();
        return p.request==null?request:p.request;
    }
    JSONArray pendingJson() throws Exception { JSONArray a=new JSONArray();for(Pending p:queue.values())a.put(p.json());return a; }
    boolean decide(String id,JSONObject decision) {
        Pending p=queue.get(id);if(p==null)return false;
        if(decision.optString("action").equals("drop")){p.dropped=true;p.ready.countDown();queue.remove(id);return true;}
        try {p.request=new Request(decision.optString("method",p.request.method),decision.optString("url",p.request.url),decision.optJSONObject("headers")==null?p.request.headers:decision.getJSONObject("headers"),WorkbenchStore.body(decision.optString("body",WorkbenchStore.text(p.request.body))),p.request.source);}catch(Exception ignored){}
        p.ready.countDown();queue.remove(id);return true;
    }
    void interceptEnabled(boolean enabled) { if(!enabled)for(Pending p:queue.values()){p.ready.countDown();queue.remove(p.id);} }

    JSONObject perform(String method,String url,JSONObject headers,String body,String source,boolean intercept) {
        JSONObject h=headers==null?new JSONObject():headers;Result r=perform(new Request(method,url,h,WorkbenchStore.body(body),source),intercept);
        try{return new JSONObject().put("id",r.id).put("status",r.status==null?JSONObject.NULL:r.status).put("headers",r.headers).put("body",WorkbenchStore.text(r.body)).put("duration",r.duration).put("error",r.error);}catch(Exception e){return new JSONObject();}
    }
    JSONObject automate(JSONObject input) throws Exception {
        JSONArray payloads=input.optJSONArray("payloads");if(payloads==null||payloads.length()==0||payloads.length()>25)return new JSONObject().put("error","Provide between 1 and 25 values");
        JSONArray results=new JSONArray();String method=input.optString("method","GET"),url=input.optString("url","");if(!java.util.Arrays.asList("GET","HEAD","OPTIONS").contains(method))return new JSONObject().put("error","Only GET, HEAD, or OPTIONS are allowed for bounded automation");JSONObject base=input.optJSONObject("headers");String body="";int delay=Math.max(250,Math.min(5000,input.optInt("delayMs",500)));
        for(int i=0;i<payloads.length();i++){String payload=payloads.optString(i);JSONObject headers=new JSONObject();if(base!=null){Iterator<String> keys=base.keys();while(keys.hasNext()){String k=keys.next();headers.put(k,base.optString(k).replace("{{payload}}",payload));}}
            Result result=perform(new Request(method,url.replace("{{payload}}",payload),headers,body.replace("{{payload}}",payload).getBytes(StandardCharsets.UTF_8),"intruder"),false);
            results.put(new JSONObject().put("index",i).put("payload",payload).put("id",result.id).put("status",result.status==null?JSONObject.NULL:result.status).put("duration",result.duration).put("error",result.error));
            if(delay>0&&i+1<payloads.length())Thread.sleep(delay);
        }
        return new JSONObject().put("results",results);
    }

    JSONObject scanFindings() throws Exception {
        JSONArray scopes=store.scopes();if(scopes.length()==0)return new JSONObject().put("error","Add authorized hosts to Target > Scope before running a passive scan");
        JSONArray requests=store.requests("",true,2000);int found=0;
        for(int i=0;i<requests.length();i++){JSONObject request=requests.getJSONObject(i);String host=request.optString("host"),url=request.optString("url");if(!inScope(host,scopes))continue;JSONObject response=request.optJSONObject("response_headers");if(response==null)continue;
            if(!response.has("Content-Security-Policy"))found+=addFinding("Content Security Policy missing","low",host,url,"Response did not include a Content-Security-Policy header. Review whether this page serves browser-rendered content.",request.optLong("id"));
            if(!response.has("X-Content-Type-Options"))found+=addFinding("MIME sniffing protection missing","info",host,url,"Response did not include X-Content-Type-Options: nosniff.",request.optLong("id"));
            if(url.startsWith("https://")&&!response.has("Strict-Transport-Security"))found+=addFinding("HSTS header missing","info",host,url,"HTTPS response did not include Strict-Transport-Security.",request.optLong("id"));
            String origin=response.optString("Access-Control-Allow-Origin","");String credentials=response.optString("Access-Control-Allow-Credentials","");if(origin.equals("*")&&credentials.equalsIgnoreCase("true"))found+=addFinding("CORS wildcard with credentials","medium",host,url,"Wildcard origin combined with credentials is an unsafe CORS configuration; validate with an authenticated browser request.",request.optLong("id"));
        }
        return new JSONObject().put("created",found).put("checked",requests.length());
    }
    private int addFinding(String title,String severity,String host,String url,String description,long requestId) {
        try{return store.addFinding(title,severity,host,url,description,"open",requestId,WorkbenchService.now())>0?1:0;}catch(Exception e){return 0;}
    }
    private boolean inScope(String host,JSONArray scopes){for(int i=0;i<scopes.length();i++){String s=scopes.optJSONObject(i).optString("host");if(s.startsWith("*.")?host.endsWith(s.substring(1)):host.equalsIgnoreCase(s))return true;}return false;}

    private Request applyRules(Request request,String target) throws Exception {
        JSONArray rules=store.rules();String url=request.url;JSONObject headers=new JSONObject(request.headers.toString());byte[] body=request.body;
        for(int i=0;i<rules.length();i++){JSONObject rule=rules.getJSONObject(i);if(rule.optInt("enabled",1)==0)continue;String direction=rule.optString("target","request");if(!direction.equals(target)&&!direction.equals("both"))continue;Pattern p=Pattern.compile(rule.optString("pattern"));String replacement=rule.optString("replacement","");url=p.matcher(url).replaceAll(replacement);Iterator<String> keys=headers.keys();while(keys.hasNext()){String key=keys.next();headers.put(key,p.matcher(headers.optString(key)).replaceAll(replacement));}String b=WorkbenchStore.text(body);if(!b.startsWith("__BASE64__:"))body=p.matcher(b).replaceAll(replacement).getBytes(StandardCharsets.UTF_8);}
        return new Request(request.method,url,headers,body,request.source);
    }
    private byte[] replaceBody(byte[] bytes,String target) throws Exception {
        String text=WorkbenchStore.text(bytes);if(text.startsWith("__BASE64__:"))return bytes;JSONArray rules=store.rules();for(int i=0;i<rules.length();i++){JSONObject r=rules.getJSONObject(i);String direction=r.optString("target");if(r.optInt("enabled",1)==1&&(direction.equals(target)||direction.equals("both")))text=Pattern.compile(r.optString("pattern")).matcher(text).replaceAll(r.optString("replacement",""));}return text.getBytes(StandardCharsets.UTF_8);
    }
    private boolean isText(JSONObject headers){String type=headers.optString("Content-Type",headers.optString("content-type","")).toLowerCase(Locale.ROOT);String encoding=headers.optString("Content-Encoding",headers.optString("content-encoding","")).toLowerCase(Locale.ROOT);return (type.startsWith("text/")||type.contains("json")||type.contains("xml")||type.contains("javascript"))&&encoding.isEmpty();}

    private byte[] readRequestBody(InputStream in,JSONObject headers) throws Exception {
        String transfer=headers.optString("Transfer-Encoding",headers.optString("transfer-encoding", ""));
        if(transfer.toLowerCase(Locale.ROOT).contains("chunked"))return readChunked(in);
        return WorkbenchService.readBody(in,headers,BODY_LIMIT);
    }
    private byte[] readResponseBody(InputStream in,JSONObject headers,String method,int status) throws Exception {
        if(method.equals("HEAD")||status==204||status==304||(status>=100&&status<200))return new byte[0];
        String transfer=headers.optString("Transfer-Encoding",headers.optString("transfer-encoding", ""));
        if(transfer.toLowerCase(Locale.ROOT).contains("chunked"))return readChunked(in);
        int length=headers.optInt("Content-Length",headers.optInt("content-length",-1));if(length>=0){if(length>BODY_LIMIT)throw new java.io.IOException("Response exceeds 32 MiB forwarding limit");return WorkbenchService.readBody(in,new JSONObject().put("Content-Length",length),BODY_LIMIT);}
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[16384];int n;while((n=in.read(buffer))!=-1){if(out.size()+n>BODY_LIMIT)throw new java.io.IOException("Response exceeds 32 MiB forwarding limit");out.write(buffer,0,n);}return out.toByteArray();
    }
    private byte[] readChunked(InputStream in) throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();String line;
        while((line=WorkbenchService.readLine(in))!=null){String size=line.split(";",2)[0].trim();int n=Integer.parseInt(size,16);if(n==0){while((line=WorkbenchService.readLine(in))!=null&&!line.isEmpty()){}break;}if(out.size()+n>BODY_LIMIT)throw new java.io.IOException("Chunked body exceeds 32 MiB forwarding limit");byte[] chunk=new byte[n];int pos=0;while(pos<n){int r=in.read(chunk,pos,n-pos);if(r<0)throw new java.io.EOFException();pos+=r;}out.write(chunk);WorkbenchService.readLine(in);}
        return out.toByteArray();
    }
    private void writeResponse(OutputStream out,Result result) throws Exception {
        int status=result.status==null?502:result.status;String reason=status==200?"OK":status==301?"Moved Permanently":status==302?"Found":status==403?"Forbidden":status==404?"Not Found":status>=500?"Bad Gateway":"Response";
        byte[] body=result.body;if(result.error!=null&&!result.error.isEmpty()&&result.status==null)body=("ZPX0XY upstream error: "+result.error).getBytes(StandardCharsets.UTF_8);
        out.write(("HTTP/1.1 "+status+" "+reason+"\r\n").getBytes(StandardCharsets.ISO_8859_1));
        Iterator<String> keys=result.headers.keys();while(keys.hasNext()){String key=keys.next();if(key.equalsIgnoreCase("connection")||key.equalsIgnoreCase("transfer-encoding")||key.equalsIgnoreCase("content-length"))continue;out.write((safe(key)+": "+safe(result.headers.optString(key))+"\r\n").getBytes(StandardCharsets.ISO_8859_1));}
        out.write(("Content-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));out.write(body);out.flush();
    }
    private void sendSimple(OutputStream out,int code,String message) throws Exception {byte[] body=message.getBytes(StandardCharsets.UTF_8);out.write(("HTTP/1.1 "+code+" Error\r\nContent-Type: text/plain\r\nContent-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));out.write(body);out.flush();}
    private String absoluteUrl(String target,String host,boolean tls){if(target.startsWith("http://")||target.startsWith("https://"))return target;return (tls?"https://":"http://")+host+target;}
    private String safe(String value){return value.replace("\r","").replace("\n","");}
    private ArrayList<String> jsonKeys(JSONObject o){ArrayList<String> keys=new ArrayList<>();Iterator<String> it=o.keys();while(it.hasNext())keys.add(it.next());return keys;}

    private static final class Request {
        final String method,url,source;final JSONObject headers;final byte[] body;final String error;
        Request(String method,String url,JSONObject headers,byte[] body,String source){this(method,url,headers,body,source,"");}
        Request(String method,String url,JSONObject headers,byte[] body,String source,String error){this.method=method;this.url=url;this.headers=headers;this.body=body;this.source=source;this.error=error;}
        Request withErrorDrop(){return new Request(method,url,headers,body,source,"Request dropped by interception queue");}
    }
    private static final class DroppedRequest extends Exception { }
    private static final class Pending {
        final String id;final CountDownLatch ready=new CountDownLatch(1);volatile Request request;volatile boolean dropped;
        Pending(String id,Request request){this.id=id;this.request=request;}
        JSONObject json() throws Exception{return new JSONObject().put("id",id).put("method",request.method).put("url",request.url).put("headers",request.headers).put("body",WorkbenchStore.text(request.body));}
    }
    private static final class Result {
        final long id,duration;final Integer status;final JSONObject headers;final byte[] body;final String error;
        Result(long id,Integer status,JSONObject headers,byte[] body,long duration,String error){this.id=id;this.status=status;this.headers=headers;this.body=body;this.duration=duration;this.error=error;}
    }
}

package io.zpx0xy;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/** Device-local store. Android never needs the desktop database or its process. */
final class WorkbenchStore extends SQLiteOpenHelper {
    WorkbenchStore(Context context) { super(context, "zpx0xy.db", null, 2); }

    @Override public void onCreate(SQLiteDatabase db) {
        db.execSQL("CREATE TABLE requests(id INTEGER PRIMARY KEY AUTOINCREMENT, created TEXT NOT NULL, method TEXT NOT NULL, host TEXT NOT NULL, path TEXT NOT NULL, url TEXT NOT NULL, status INTEGER, request_headers TEXT NOT NULL, request_body TEXT NOT NULL, response_headers TEXT NOT NULL, response_body TEXT NOT NULL, duration REAL NOT NULL, source TEXT NOT NULL, error TEXT NOT NULL)");
        db.execSQL("CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT NOT NULL)");
        db.execSQL("CREATE TABLE scopes(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL UNIQUE)");
        db.execSQL("CREATE TABLE match_replace(id INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT NOT NULL, replacement TEXT NOT NULL, target TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1)");
        db.execSQL("CREATE TABLE notes(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL)");
        db.execSQL("CREATE TABLE findings(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, severity TEXT NOT NULL, host TEXT NOT NULL, url TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL, request_id INTEGER, created TEXT NOT NULL, UNIQUE(request_id,title))");
        db.execSQL("CREATE TABLE automations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,method TEXT NOT NULL,url TEXT NOT NULL,headers TEXT NOT NULL,body TEXT NOT NULL,payloads TEXT NOT NULL,delay_ms INTEGER NOT NULL,updated TEXT NOT NULL)");
        db.execSQL("INSERT INTO settings(key,value) VALUES('tls_intercept','false')");
        db.execSQL("INSERT INTO settings(key,value) VALUES('proxy_enabled','true')");
        db.execSQL("INSERT INTO settings(key,value) VALUES('intercept_enabled','false')");
    }
    @Override public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) { if(oldVersion<2)db.execSQL("CREATE TABLE IF NOT EXISTS automations(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,method TEXT NOT NULL,url TEXT NOT NULL,headers TEXT NOT NULL,body TEXT NOT NULL,payloads TEXT NOT NULL,delay_ms INTEGER NOT NULL,updated TEXT NOT NULL)"); }

    static String text(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        try { return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(bytes)).toString(); }
        catch (Exception ignored) { return "__BASE64__:" + Base64.getEncoder().encodeToString(bytes); }
    }
    static byte[] body(String value) {
        if (value == null || value.isEmpty()) return new byte[0];
        if (value.startsWith("__BASE64__:")) return Base64.getDecoder().decode(value.substring(11));
        return value.getBytes(StandardCharsets.UTF_8);
    }
    long saveRequest(String created, String method, String host, String path, String url, Integer status,
                     JSONObject requestHeaders, String requestBody, JSONObject responseHeaders,
                     String responseBody, long duration, String source, String error) {
        ContentValues v = new ContentValues(); v.put("created", created); v.put("method", method);
        v.put("host", host); v.put("path", path); v.put("url", url); if (status != null) v.put("status", status);
        v.put("request_headers", requestHeaders.toString()); v.put("request_body", cap(requestBody));
        v.put("response_headers", responseHeaders.toString()); v.put("response_body", cap(responseBody));
        v.put("duration", duration); v.put("source", source); v.put("error", error);
        return getWritableDatabase().insert("requests", null, v);
    }
    private String cap(String s) { return s == null ? "" : s.substring(0, Math.min(1_000_000, s.length())); }

    JSONArray requests(String search, boolean detail, int limit) throws JSONException {
        JSONArray out = new JSONArray(); String like = "%" + (search == null ? "" : search) + "%";
        try (Cursor c = getReadableDatabase().rawQuery("SELECT * FROM requests WHERE host LIKE ? OR url LIKE ? OR method LIKE ? ORDER BY id DESC LIMIT ?", new String[]{like, like, like, String.valueOf(limit)})) {
            while (c.moveToNext()) out.put(request(c, detail));
        }
        return out;
    }
    JSONObject request(long id) throws JSONException {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT * FROM requests WHERE id=?", new String[]{String.valueOf(id)})) {
            return c.moveToFirst() ? request(c, true) : null;
        }
    }
    private JSONObject request(Cursor c, boolean detail) throws JSONException {
        JSONObject o = new JSONObject().put("id", c.getLong(c.getColumnIndexOrThrow("id")))
            .put("created", c.getString(c.getColumnIndexOrThrow("created")))
            .put("method", c.getString(c.getColumnIndexOrThrow("method")))
            .put("host", c.getString(c.getColumnIndexOrThrow("host")))
            .put("path", c.getString(c.getColumnIndexOrThrow("path")))
            .put("url", c.getString(c.getColumnIndexOrThrow("url")))
            .put("status", c.isNull(c.getColumnIndexOrThrow("status")) ? JSONObject.NULL : c.getInt(c.getColumnIndexOrThrow("status")))
            .put("duration", c.getLong(c.getColumnIndexOrThrow("duration")))
            .put("source", c.getString(c.getColumnIndexOrThrow("source")))
            .put("error", c.getString(c.getColumnIndexOrThrow("error")));
        if (detail) o.put("request_headers", new JSONObject(c.getString(c.getColumnIndexOrThrow("request_headers"))))
            .put("request_body", c.getString(c.getColumnIndexOrThrow("request_body")))
            .put("response_headers", new JSONObject(c.getString(c.getColumnIndexOrThrow("response_headers"))))
            .put("response_body", c.getString(c.getColumnIndexOrThrow("response_body")));
        return o;
    }

    JSONArray scopes() throws JSONException { return rows("SELECT id,host FROM scopes ORDER BY host", null); }
    JSONArray rules() throws JSONException { return rows("SELECT * FROM match_replace ORDER BY id DESC", null); }
    JSONArray notes() throws JSONException { return rows("SELECT * FROM notes ORDER BY id DESC", null); }
    JSONArray findings() throws JSONException { return rows("SELECT * FROM findings ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, id DESC", null); }
    JSONArray automations() throws JSONException { JSONArray out=new JSONArray();try(Cursor c=getReadableDatabase().rawQuery("SELECT * FROM automations ORDER BY id DESC",null)){while(c.moveToNext()){JSONObject o=new JSONObject();o.put("id",c.getLong(0)).put("name",c.getString(1)).put("method",c.getString(2)).put("url",c.getString(3)).put("headers",new JSONObject(c.getString(4))).put("body",c.getString(5)).put("payloads",new JSONArray(c.getString(6))).put("delay_ms",c.getInt(7)).put("delayMs",c.getInt(7)).put("updated",c.getString(8));out.put(o);}}return out; }
    JSONObject automation(long id) throws JSONException { try(Cursor c=getReadableDatabase().rawQuery("SELECT * FROM automations WHERE id=?",new String[]{String.valueOf(id)})){if(!c.moveToFirst())return null;return new JSONObject().put("id",c.getLong(0)).put("name",c.getString(1)).put("method",c.getString(2)).put("url",c.getString(3)).put("headers",new JSONObject(c.getString(4))).put("body",c.getString(5)).put("payloads",new JSONArray(c.getString(6))).put("delay_ms",c.getInt(7)).put("delayMs",c.getInt(7)).put("updated",c.getString(8));} }
    private JSONArray rows(String sql, String[] args) throws JSONException {
        JSONArray out = new JSONArray();
        try (Cursor c = getReadableDatabase().rawQuery(sql, args)) {
            String[] columns = c.getColumnNames();
            while (c.moveToNext()) { JSONObject o = new JSONObject(); for (int i=0;i<columns.length;i++) o.put(columns[i], c.isNull(i) ? JSONObject.NULL : c.getString(i)); out.put(o); }
        }
        return out;
    }
    String setting(String key, String fallback) {
        try (Cursor c = getReadableDatabase().rawQuery("SELECT value FROM settings WHERE key=?", new String[]{key})) { return c.moveToFirst() ? c.getString(0) : fallback; }
    }
    void setSetting(String key, String value) { ContentValues v=new ContentValues(); v.put("key",key); v.put("value",value); getWritableDatabase().insertWithOnConflict("settings",null,v,SQLiteDatabase.CONFLICT_REPLACE); }
    long addScope(String host) { ContentValues v=new ContentValues();v.put("host",host);return getWritableDatabase().insertWithOnConflict("scopes",null,v,SQLiteDatabase.CONFLICT_IGNORE); }
    long addRule(String pattern,String replacement,String target) { ContentValues v=new ContentValues();v.put("pattern",pattern);v.put("replacement",replacement);v.put("target",target);return getWritableDatabase().insert("match_replace",null,v); }
    long addAutomation(JSONObject a,String updated) { ContentValues v=new ContentValues();v.put("name",a.optString("name"));v.put("method",a.optString("method"));v.put("url",a.optString("url"));v.put("headers",a.optJSONObject("headers")==null?"{}":a.optJSONObject("headers").toString());v.put("body",a.optString("body",""));v.put("payloads",a.optJSONArray("payloads")==null?"[]":a.optJSONArray("payloads").toString());v.put("delay_ms",a.optInt("delayMs",500));v.put("updated",updated);return getWritableDatabase().insert("automations",null,v); }
    long addNote(String title,String body,String created) { ContentValues v=new ContentValues();v.put("title",title);v.put("body",body);v.put("created",created);return getWritableDatabase().insert("notes",null,v); }
    long addFinding(String title,String severity,String host,String url,String description,String status,long requestId,String created) {
        ContentValues v=new ContentValues();v.put("title",title);v.put("severity",severity);v.put("host",host);v.put("url",url);v.put("description",description);v.put("status",status);if(requestId>0)v.put("request_id",requestId);v.put("created",created);
        return getWritableDatabase().insertWithOnConflict("findings",null,v,SQLiteDatabase.CONFLICT_IGNORE);
    }
}

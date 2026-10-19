package io.zpx0xy;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.DownloadListener;
import android.webkit.ConsoleMessage;
import android.webkit.WebChromeClient;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.JavascriptInterface;
import android.content.ContentValues;
import android.provider.MediaStore;
import android.os.Environment;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import org.json.JSONObject;

import android.net.Uri;

/** Android runs the proxy and dashboard on this device; no desktop companion is required. */
public final class MainActivity extends Activity {
    private WebView web;
    private LinearLayout root;
    private TextView startupMessage;
    private Handler main;
    private long startupStarted;
    private boolean loadingDashboard;
    private volatile int dashboardPort = 4173;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(233, 237, 240));
        getWindow().setNavigationBarColor(Color.rgb(233, 237, 240));
        int systemBars = android.view.View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) systemBars |= android.view.View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR;
        getWindow().getDecorView().setSystemUiVisibility(systemBars);
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED)
            requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 44);
        main = new Handler(Looper.getMainLooper());
        showStartup("Iniciando el proxy y la interfaz local…", false);
        Intent service = new Intent(this, WorkbenchService.class);
        try {
            if (Build.VERSION.SDK_INT >= 26) startForegroundService(service); else startService(service);
        } catch (Exception error) {
            android.util.Log.e("ZPX0XY", "Could not launch workbench service", error);
            showStartup("Android no pudo iniciar el servicio: " + error.getMessage(), true);
            return;
        }
        openDashboard();
    }

    private void showStartup(String message, boolean retry) {
        if (root == null) {
            root = new LinearLayout(this);
            root.setOrientation(LinearLayout.VERTICAL);
            root.setGravity(Gravity.CENTER);
            root.setPadding(28, 28, 28, 28);
            root.setBackgroundColor(Color.rgb(233, 237, 240));
            TextView title = new TextView(this);
            title.setText("ZPX0XY"); title.setTextSize(24); title.setTextColor(Color.rgb(37,39,43));
            title.setGravity(Gravity.CENTER); root.addView(title);
            ProgressBar progress = new ProgressBar(this);
            LinearLayout.LayoutParams pp = new LinearLayout.LayoutParams(64, 64); pp.topMargin=24; pp.bottomMargin=18;
            root.addView(progress, pp);
            startupMessage = new TextView(this);
            startupMessage.setTextColor(Color.rgb(90,95,102)); startupMessage.setTextSize(15);
            startupMessage.setGravity(Gravity.CENTER); root.addView(startupMessage);
        }
        startupMessage.setText(message);
        View old = root.findViewWithTag("retry");
        if (old != null) root.removeView(old);
        if (retry) {
            Button button = new Button(this); button.setTag("retry"); button.setText("Reintentar");
            button.setOnClickListener(v -> { startupStarted=System.currentTimeMillis(); loadingDashboard=true; showStartup("Comprobando el servicio local…", false); waitForDashboard(); });
            LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(-2, -2); bp.topMargin=16; root.addView(button,bp);
        }
        setContentView(root);
    }

    private void openDashboard() {
        web = new WebView(this);
        web.setBackgroundColor(Color.rgb(233, 237, 240));
        web.getSettings().setJavaScriptEnabled(true);
        web.getSettings().setDomStorageEnabled(true);
        web.getSettings().setLoadsImagesAutomatically(true);
        web.addJavascriptInterface(new AndroidBridge(), "ZPX0XYAndroid");
        web.setWebViewClient(new WebViewClient() {
            @Override public void onPageFinished(WebView view, String url) {
                android.util.Log.i("ZPX0XY", "Dashboard loaded: " + url);
                if (view == web) setContentView(web);
            }
            @Override public void onReceivedError(WebView view, android.webkit.WebResourceRequest request, android.webkit.WebResourceError error) {
                if (request.isForMainFrame()) {
                    String description = error.getDescription() == null ? "Error de carga" : error.getDescription().toString();
                    android.util.Log.e("ZPX0XY", "Dashboard load error: " + description + " " + request.getUrl());
                    showStartup("No se pudo cargar la interfaz: " + description, true);
                }
            }
            @Override public void onReceivedHttpError(WebView view, android.webkit.WebResourceRequest request, android.webkit.WebResourceResponse response) {
                if (request.isForMainFrame() && response.getStatusCode() >= 400) {
                    android.util.Log.e("ZPX0XY", "Dashboard HTTP error " + response.getStatusCode() + " " + request.getUrl());
                    showStartup("El servicio respondió con error HTTP " + response.getStatusCode(), true);
                }
            }
        });
        web.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onConsoleMessage(ConsoleMessage message) {
                if (message.messageLevel() == ConsoleMessage.MessageLevel.ERROR)
                    android.util.Log.e("ZPX0XY", "JavaScript " + message.sourceId() + ":" + message.lineNumber() + " " + message.message());
                return true;
            }
        });
        web.setDownloadListener((url, userAgent, contentDisposition, mimetype, contentLength) -> installCa(url));
        showStartup("Esperando al servicio local…", false);
        startupStarted=System.currentTimeMillis(); loadingDashboard=true;
        waitForDashboard();
    }

    private void waitForDashboard() {
        Runnable[] attempt = new Runnable[1];
        attempt[0] = () -> new Thread(() -> {
            int foundPort = 0;
            for (int port = 4173; port <= 4193 && foundPort == 0; port++) {
                HttpURLConnection c = null;
                try {
                    c = (HttpURLConnection) new URL("http://127.0.0.1:"+port+"/api/status").openConnection();
                    c.setConnectTimeout(150); c.setReadTimeout(150);
                    if (c.getResponseCode() == 200) {
                        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
                        byte[] buffer = new byte[1024]; int count;
                        try (InputStream input = c.getInputStream()) { while ((count=input.read(buffer))!=-1) bytes.write(buffer,0,count); }
                        JSONObject status = new JSONObject(bytes.toString("UTF-8"));
                        if ("ZPX0XY".equals(status.optString("service")) && status.optInt("dashboardPort") == port) foundPort=port;
                    }
                } catch (Exception ignored) { }
                finally { if(c!=null)c.disconnect(); }
            }
            final int readyPort = foundPort;
            main.post(() -> {
                if (!loadingDashboard || isFinishing()) return;
                if (readyPort > 0) { loadingDashboard=false; dashboardPort=readyPort; web.loadUrl("http://127.0.0.1:"+dashboardPort+"/"); }
                else if (System.currentTimeMillis()-startupStarted > 20_000) {
                    loadingDashboard=false;
                    showStartup("El servicio local no responde. Revisa los registros de ZPX0XY o vuelve a intentarlo.", true);
                } else { showStartup("Iniciando el servicio local… " + ((System.currentTimeMillis()-startupStarted)/1000) + " s", false); main.postDelayed(attempt[0], 300); }
            });
        }).start();
        attempt[0].run();
    }

    private void installCa(String url) {
        new Thread(() -> {
            try {
                HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
                connection.setConnectTimeout(3000); connection.setReadTimeout(5000);
                try (InputStream in = connection.getInputStream(); ByteArrayOutputStream out = new ByteArrayOutputStream()) {
                    byte[] buffer = new byte[8192]; int read;
                    while ((read = in.read(buffer)) != -1) out.write(buffer, 0, read);
                    byte[] certificate = out.toByteArray();
                    if (connection.getResponseCode() != 200 || certificate.length < 256)
                        throw new java.io.IOException("El servidor devolvió un certificado vacío o inválido");
                    java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(new java.io.ByteArrayInputStream(certificate));
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        saveCaToDownloads(certificate);
                        runOnUiThread(() -> {
                            Toast.makeText(this, "Certificado guardado en Descargas/ZPX0XY. En Ajustes, abre Seguridad y privacidad > Otros ajustes de seguridad > Instalar desde almacenamiento.", Toast.LENGTH_LONG).show();
                            try { startActivity(new Intent(Settings.ACTION_SECURITY_SETTINGS)); }
                            catch (Exception error) { android.util.Log.e("ZPX0XY", "Could not open Android security settings", error); startActivity(new Intent(Settings.ACTION_SETTINGS)); }
                        });
                    } else {
                        Intent intent = android.security.KeyChain.createInstallIntent();
                        intent.putExtra(android.security.KeyChain.EXTRA_CERTIFICATE, certificate);
                        intent.putExtra(android.security.KeyChain.EXTRA_NAME, "ZPX0XY Inspection CA");
                        runOnUiThread(() -> {
                            try { startActivity(intent); }
                            catch (Exception error) { android.util.Log.e("ZPX0XY", "Could not open Android credential installer", error); Toast.makeText(this, "Android no pudo abrir el instalador del certificado: " + error.getMessage(), Toast.LENGTH_LONG).show(); }
                        });
                    }
                } finally { connection.disconnect(); }
            } catch (Exception e) {
                android.util.Log.e("ZPX0XY", "Could not prepare CA certificate for installation", e);
                runOnUiThread(() -> Toast.makeText(this, "No se pudo abrir el instalador de CA: " + e.getMessage(), Toast.LENGTH_LONG).show());
            }
        }).start();
    }

    private void saveCaToDownloads(byte[] certificate) throws Exception {
        String filename = "ZPX0XY-ca.crt";
        String folder = Environment.DIRECTORY_DOWNLOADS + "/ZPX0XY";
        android.content.ContentResolver resolver = getContentResolver();
        Uri collection = MediaStore.Downloads.EXTERNAL_CONTENT_URI;
        resolver.delete(collection, MediaStore.Downloads.DISPLAY_NAME + "=? AND " + MediaStore.Downloads.RELATIVE_PATH + "=?", new String[]{filename, folder + "/"});
        ContentValues values = new ContentValues();
        values.put(MediaStore.Downloads.DISPLAY_NAME, filename);
        values.put(MediaStore.Downloads.MIME_TYPE, "application/x-x509-ca-cert");
        values.put(MediaStore.Downloads.RELATIVE_PATH, folder);
        values.put(MediaStore.Downloads.IS_PENDING, 1);
        Uri saved = resolver.insert(collection, values);
        if (saved == null) throw new java.io.IOException("No se pudo guardar el certificado en Descargas");
        try (java.io.OutputStream output = resolver.openOutputStream(saved, "w")) {
            if (output == null) throw new java.io.IOException("No se pudo escribir el certificado en Descargas");
            output.write(certificate);
        } catch (Exception error) { resolver.delete(saved, null, null); throw error; }
        ContentValues ready = new ContentValues(); ready.put(MediaStore.Downloads.IS_PENDING, 0);
        resolver.update(saved, ready, null, null);
        android.util.Log.i("ZPX0XY", "CA certificate saved to Downloads/ZPX0XY/" + filename);
    }

    public final class AndroidBridge {
        @JavascriptInterface public void installCa() {
            runOnUiThread(() -> Toast.makeText(MainActivity.this, "Preparando el certificado para Android…", Toast.LENGTH_SHORT).show());
            MainActivity.this.installCa("http://127.0.0.1:" + dashboardPort + "/api/ca");
        }
    }

    @Override public void onBackPressed() {
        if (web != null && web.canGoBack()) web.goBack(); else super.onBackPressed();
    }
}

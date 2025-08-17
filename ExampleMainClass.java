package lol.alez.wboot;

import org.bukkit.Bukkit;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;

public final class WBoot extends JavaPlugin {

    private static final String SERVER_URL = "https://example.com/plugins/";
    private static final String PLUGIN_NAME = "Example";
    private static final String VERSION_ENDPOINT = "version.txt";
    private static final String DOWNLOAD_ENDPOINT = "download.jar";
    private static final String AUTH_TOKEN = "your-secure-auth-token-here";

    private File pluginFile;
    private ClassLoader pluginClassLoader;
    private Object actualPlugin;

    @Override
    public void onEnable() {
        getLogger().info("Initializing plugin bootstrapper...");
        new BukkitRunnable() {
            @Override
            public void run() {
                try {
                    downloadAndLoadPlugin();
                } catch (Exception e) {
                    getLogger().severe("Failed to load plugin: " + e.getMessage());
                    getServer().getPluginManager().disablePlugin(WBoot.this);
                }
            }
        }.runTaskAsynchronously(this);
    }

    @Override
    public void onDisable() {
        if (actualPlugin != null) {
            try {
                actualPlugin.getClass().getMethod("onDisable").invoke(actualPlugin);
            } catch (Exception e) {
                getLogger().log(Level.WARNING, "Error 8; Report to Alez.", e);
            }
        }

        if (pluginFile != null && pluginFile.exists()) {
            try {
                Files.delete(pluginFile.toPath());
            } catch (IOException e) {
                getLogger().log(Level.WARNING, "Error 9; Report to Alez.", e);
            }
        }
    }

    private void downloadAndLoadPlugin() throws Exception {
        String remoteVersion = fetchRemoteVersion();
        String localVersion = getLocalVersion();

        if (!remoteVersion.equals(localVersion) || !getPluginFile().exists()) {
            getLogger().info("Downloading plugin update...");
            downloadPlugin();
            saveLocalVersion(remoteVersion);
        }
        loadActualPlugin();
    }

    private String fetchRemoteVersion() throws Exception {
        URL url = new URL(SERVER_URL + VERSION_ENDPOINT);
        HttpURLConnection conn = createSecureConnection(url);

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
            return reader.readLine().trim();
        } finally {
            conn.disconnect();
        }
    }

    private void downloadPlugin() throws Exception {
        URL url = new URL(SERVER_URL + DOWNLOAD_ENDPOINT);
        HttpURLConnection conn = createSecureConnection(url);

        File tempFile = File.createTempFile("W_", ".jar");

        try (InputStream in = conn.getInputStream();
             FileOutputStream out = new FileOutputStream(tempFile)) {

            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        } finally {
            conn.disconnect();
        }

        if (verifyDownload(tempFile)) {
            File finalFile = getPluginFile();
            if (finalFile.exists()) {
                finalFile.delete();
            }
            tempFile.renameTo(finalFile);
            this.pluginFile = finalFile;
        } else {
            tempFile.delete();
            throw new Exception("Downloaded file verification failed");
        }
    }

    private HttpURLConnection createSecureConnection(URL url) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestProperty("Authorization", "Bearer " + AUTH_TOKEN);
        conn.setRequestProperty("User-Agent", "WBoot/1.0");
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(30000);

        if (conn instanceof HttpsURLConnection) {
            disableSSLVerification((HttpsURLConnection) conn);
        }

        return conn;
    }

    private void disableSSLVerification(HttpsURLConnection conn) throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        conn.setSSLSocketFactory(sc.getSocketFactory());
        conn.setHostnameVerifier((hostname, session) -> true);
    }

    private boolean verifyDownload(File file) {
        try {
            return file.length() > 1000 && file.getName().endsWith(".jar");
        } catch (Exception e) {
            return false;
        }
    }

    private void loadActualPlugin() throws Exception {
        URL[] urls = { pluginFile.toURI().toURL() };
        this.pluginClassLoader = new PluginClassLoader(urls, getClass().getClassLoader());
        Class<?> pluginClass = pluginClassLoader.loadClass(getMainClassFromJar());
        actualPlugin = pluginClass.getDeclaredConstructor().newInstance();
        initializeActualPlugin(actualPlugin);
        actualPlugin.getClass().getMethod("onEnable").invoke(actualPlugin);

        getLogger().info("Successfully loaded and enabled actual plugin");
    }

    private String getMainClassFromJar() throws Exception {
        return "com.example.plugin.MainClass";
    }

    private void initializeActualPlugin(Object plugin) throws Exception {
        // Example of setting common JavaPlugin fields
        /*
        Field dataFolderField = JavaPlugin.class.getDeclaredField("dataFolder");
        dataFolderField.setAccessible(true);
        dataFolderField.set(plugin, getDataFolder());

        Field loggerField = JavaPlugin.class.getDeclaredField("logger");
        loggerField.setAccessible(true);
        loggerField.set(plugin, getLogger());
        */
    }

    private File getPluginFile() {
        return new File(getDataFolder(), PLUGIN_NAME + ".jar");
    }

    private String getLocalVersion() {
        File versionFile = new File(getDataFolder(), "version.txt");
        if (!versionFile.exists()) return "";
        try {
            return new String(Files.readAllBytes(versionFile.toPath())).trim();
        } catch (IOException e) {
            return "";
        }
    }

    private void saveLocalVersion(String version) {
        File versionFile = new File(getDataFolder(), "version.txt");
        try {
            getDataFolder().mkdirs();
            Files.write(versionFile.toPath(), version.getBytes());
        } catch (IOException e) {
            getLogger().log(Level.WARNING, "Could not save version info", e);
        }
    }

    private static class PluginClassLoader extends java.net.URLClassLoader {
        public PluginClassLoader(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }
        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            try {
                return super.loadClass(name, resolve);
            } catch (ClassNotFoundException e) {
                throw e;
            }
        }
    }
}

package example;

import org.jetbrains.annotations.NotNull;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.commons.Version;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class KeyFetcher {
    private final Map<String, PublicKey> keyCache = new ConcurrentHashMap<>();

    public PublicKey get(String kid) throws Exception {
        return keyCache.computeIfAbsent(kid, k -> {
            try {
                return loadPubKey(fetchPubKey(kid));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        });
    }

    protected String fetchPubKey(String kid) throws Exception {
        final URL url = URI.create("https://sip-keys.authenticvision.com/v4/" + URLEncoder.encode(kid, StandardCharsets.UTF_8)).toURL();
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);

        final int status = conn.getResponseCode();
        if (status != 200) {
            throw new IllegalStateException("Failed to fetch public key for kid: " + kid + ", status: " + status);
        }

        final String paserk;
        try (InputStream is = conn.getInputStream()) {
            paserk = new String(is.readAllBytes(), StandardCharsets.UTF_8).trim();
        }

        return paserk;
    }

    @NotNull
    protected static PublicKey loadPubKey(String paserk) throws Exception {
        final String prefix = "k4.public.";
        if (!paserk.startsWith(prefix)) {
            throw new IllegalArgumentException("Invalid key format sip-keys.authenticvision.com, must start with 'k4.public.'");
        }
        byte[] keyBytes = Base64.getUrlDecoder().decode(paserk.substring(prefix.length()));
        return new PublicKey(Ed25519KeyConversion.toPublicKey(keyBytes), Version.V4);
    }
}

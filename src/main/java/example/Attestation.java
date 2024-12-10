package example;

import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import org.paseto4j.commons.PublicKey;
import org.paseto4j.version4.PasetoPublic;

import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

public class Attestation {
    private final KeyFetcher keyFetcher;
    private final static Attestation instance = new Attestation(new KeyFetcher());

    static {
        // required for paseto4j, no-op if BouncyCastle is already registered
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    public static void main(@NotNull String[] args) {
        if (args.length != 1) {
            System.err.println("usage: Attestation <token>");
            System.exit(1);
        }
        try {
            Attestation decoder = Attestation.getInstance();
            JSONObject payload = decoder.decodeToken(args[0]);
            System.out.println(payload.toString(2));
            System.exit(0);
        } catch (Exception e) {
            System.err.print("Error: ");
            e.printStackTrace();
            System.exit(1);
        }
    }

    public static Attestation getInstance() {
        return instance;
    }

    public Attestation(KeyFetcher keyFetcher) {
        this.keyFetcher = keyFetcher;
    }

    public JSONObject decodeToken(String token) throws Exception {
        final String prefix = "v4.public.";
        if (!token.startsWith(prefix)) {
            throw new IllegalArgumentException("Invalid token format");
        }

        final String footerRaw = new String(Base64.getUrlDecoder().decode(token.substring(token.lastIndexOf('.') + 1)), StandardCharsets.UTF_8);
        final JSONObject footer = new JSONObject(footerRaw);

        final String kid = footer.getString("kid");
        if (!kid.startsWith("k4.pid.")) {
            throw new IllegalArgumentException("Invalid key id in footer");
        }

        PublicKey publicKey = keyFetcher.get(kid);
        final String verified = PasetoPublic.parse(publicKey, token, footerRaw, "");
        return new JSONObject(verified);
    }
}

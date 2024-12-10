package example;

import org.jetbrains.annotations.NotNull;
import org.json.JSONObject;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.Security;

public class AttestationTest {

    private static final String PUBKEY =
        "k4.public.f2AxH__c3AQy_abwIYAZvwzLYrLPAUNH5o6cFzPj1_0";
    private static final String KID =
        "k4.pid.2uab3h18sgaYX1PKFW3OIMvGIfAMnuwWBJ6TuCbuwQii";
    private static final String TOKEN =
        "v4.public.eyJhdWQiOiJleGFtcGxlLmNvbSIsImV4cCI6IjIwMzAtMDEtMDFUMDA6MDA6MDBaIiwiaWF0IjoiMjAyMy0wNC0yMFQxNjo1NDowMVoiLCJqdGkiOiJmOGIxZDdmNzNiNzEzYWY0M2FkNTllMzNiN2MwMmRmNSIsInJlc3VsdCI6IkFVVEhFTlRJQyIsInNsaWQiOiJaNDVKQkpSNlM5IiwibG9jYXRpb24iOnsibGF0Ijo0Ny43OTQ2LCJsb24iOjEyLjk4NjR9LCJleHRyZWZzIjpbImZvbyIseyJiYXIiOiJiYXoifSwxMjNdffeoKRK7wfueWl9ti4h9JTYM2ZOXOPgHMOq-6eRxFEKFUYz1LLcNxUp9JtHHY-FD5pHxP9OQ9nOg_izxMwK3GgU.eyJraWQiOiAiazQucGlkLjJ1YWIzaDE4c2dhWVgxUEtGVzNPSU12R0lmQU1udXdXQko2VHVDYnV3UWlpIn0";

    @Test
    public void testDecodeToken() throws Exception {
        Attestation decoder = new Attestation(new KeyFetcher() {
            @NotNull
            protected String fetchPubKey(String kid) {
                if (!KID.equals(kid)) {
                    throw new IllegalArgumentException("Unexpected key id: " + kid);
                }
                return PUBKEY;
            }
        });
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        JSONObject payload = decoder.decodeToken(TOKEN);

        Assertions.assertNotNull(payload);
        Assertions.assertEquals("AUTHENTIC", payload.getString("result"));
        Assertions.assertEquals("example.com", payload.getString("aud"));
        Assertions.assertEquals("f8b1d7f73b713af43ad59e33b7c02df5", payload.getString("jti"));
        Assertions.assertEquals("Z45JBJR6S9", payload.getString("slid"));
        Assertions.assertEquals("foo", payload.getJSONArray("extrefs").toList().stream().filter("foo"::equals).findFirst().orElse(null));
    }
}


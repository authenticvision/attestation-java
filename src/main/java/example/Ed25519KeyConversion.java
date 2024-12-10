package example;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.internal.asn1.edec.EdECObjectIdentifiers;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class Ed25519KeyConversion {
    public static PublicKey toPublicKey(byte[] pubKeyData) throws Exception {
        AlgorithmIdentifier algId = new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519);
        SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(algId, pubKeyData);
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(spki.getEncoded());
        return KeyFactory.getInstance("Ed25519").generatePublic(pubSpec);
    }
}

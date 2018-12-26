package co.krypt.krypton;

import android.support.test.InstrumentationRegistry;
import android.support.test.runner.AndroidJUnit4;

import junit.framework.Assert;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.util.Collections;

import co.krypt.krypton.crypto.KeyManager;
import co.krypt.krypton.crypto.KeyType;
import co.krypt.krypton.crypto.SSHKeyPairI;
import co.krypt.krypton.pgp.PGPPublicKey;
import co.krypt.krypton.pgp.UserID;
import co.krypt.krypton.pgp.codesign.UnsignedBinaryDocument;
import co.krypt.krypton.pgp.packet.HashAlgorithm;
import co.krypt.krypton.pgp.packet.SignableUtils;
import co.krypt.krypton.pgp.packet.SignatureType;
import co.krypt.krypton.pgp.packet.SignedSignatureAttributes;
import co.krypt.krypton.pgp.publickey.PublicKeyAlgorithm;

/**
 * Instrumentation test, which will execute on an Android device.
 *
 * @see <a href="http://d.android.com/tools/testing">Testing documentation</a>
 */
@RunWith(AndroidJUnit4.class)
public class PGPCodesignTest {
    @Test
    public void dataSigning_succeeds() throws Exception {
        final byte[] data = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
        SSHKeyPairI kp1 = KeyManager.loadOrGenerateKeyPair(InstrumentationRegistry.getTargetContext(), KeyType.RSA, "test");
        PGPPublicKey pubkey = new PGPPublicKey(kp1, Collections.singletonList(new UserID("Kevin King", "kevin@krypt.co")));

        UnsignedBinaryDocument unsigned = new UnsignedBinaryDocument(
                data,
                kp1,
                HashAlgorithm.SHA512
        );
        SignedSignatureAttributes sig = unsigned.sign(
                kp1.pgpSign(HashAlgorithm.SHA512, SignableUtils.signableBytes(unsigned))
        );

        byte[] serializedSig = sig.serializedBytes();
        SignedSignatureAttributes parsedSig = SignedSignatureAttributes.parse(new DataInputStream(new ByteArrayInputStream(serializedSig)));

        Assert.assertTrue(parsedSig.attributes.attributes.hashAlgorithm == HashAlgorithm.SHA512);
        Assert.assertTrue(parsedSig.attributes.attributes.pkAlgorithm == PublicKeyAlgorithm.RSA_ENCRYPT_OR_SIGN);
        Assert.assertTrue(parsedSig.attributes.attributes.type == SignatureType.BINARY);
        Assert.assertFalse(parsedSig.attributes.attributes.unhashedSubpackets.issuer.header.type.critical);
    }
}

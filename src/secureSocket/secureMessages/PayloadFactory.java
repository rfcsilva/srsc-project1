package secureSocket.secureMessages;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class PayloadFactory {

	protected static final byte TYPE1 = 0x01;

	public static Payload buildPayload(byte payloadType, byte[] rawPayload) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {

		switch(payloadType) {

		case TYPE1:
			return DefaultPayload.deserialize(rawPayload);		
		default: 
			return null; // TODO: Deveria fazer um throw
		}
	}



}

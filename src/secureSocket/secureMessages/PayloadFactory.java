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

import secureSocket.Cryptography2;

public class PayloadFactory {

	public static Payload buildPayload(byte payloadType, byte[] rawPayload, Cryptography2 cryptoManager) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {

		switch(payloadType) {

		case DefaultPayload.TYPE:
			return DefaultPayload.deserialize(rawPayload, cryptoManager);	
		default: 
			return null; // TODO: Deveria fazer um throw
		}
	}



}

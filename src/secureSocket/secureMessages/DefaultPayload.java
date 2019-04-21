package secureSocket.secureMessages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import Utils.ArrayUtils;
import secureSocket.Cryptography;

// TODO : find better name for the class
public class DefaultPayload implements Payload {
		
	//Encryption support
	private static Cryptography criptoService; 
	
	
	//Payload data
	private long id;
	private long nonce;
	private byte[] message;
	private byte[] innerMac;
	private byte[] cipherText;
	private byte[] outterMac;
	
	public DefaultPayload(long id, long nonce, byte[] message) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		this.message = message;
		this.id = id;
		this.nonce = nonce;
		byte[] Mp = buildMp();
		
		// cipherText
		criptoService = new Cryptography(Cipher.ENCRYPT_MODE); // TODO: Isto assim naõ parece bom, tem de se arranjar melhor maneira de interajir com esta class
				
		//Append MacDoS
		this.innerMac = criptoService.computeMac(Mp);	
		this.cipherText = criptoService.encrypt( ArrayUtils.concat(Mp, innerMac));
		this.outterMac = criptoService.computeMacDoS(this.cipherText);
	}
	
	private byte[] buildMp() throws IOException {
		
		ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
		DataOutputStream dataOut = new DataOutputStream(byteOut);
		
		dataOut.writeLong(id);
		dataOut.writeLong(nonce);
		dataOut.write(message, 0, message.length);
		dataOut.flush();
		byteOut.flush();
		
		byte[] mp = byteOut.toByteArray();
		
		dataOut.close();
		byteOut.close();
		
		
		return mp;
	}

	public byte getPayloadType() {
		return 0x01;
	}
	
	public byte[] serialize() {
		return ArrayUtils.concat(this.cipherText, this.outterMac);
	}
	
	public short size() {
		return (short) (cipherText.length + outterMac.length);
	}

	//TODO handle bad macs
	public static Payload deserialize(byte[] rawPayload ) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		
	    byte[][] messageParts = criptoService.splitHeader(rawPayload);
	    if(criptoService.validateMacDos(messageParts[0], messageParts[1])) {
	    	byte[] plainText = criptoService.decrypt(messageParts[0]); //TODO: better name
	    	byte[][] payloadParts = criptoService.splitPayload(plainText);
	    	if(criptoService.validadeInnerMac(payloadParts[0], payloadParts[1])) {
	    		return deconstructMp(payloadParts[0]);    		
	    	}		
	    }
		return null;
	}

	private static Payload deconstructMp(byte[] mp) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		
		ByteArrayInputStream byteIn = new ByteArrayInputStream(mp);
		DataInputStream dataIn = new DataInputStream(byteIn);
		
		long id = dataIn.readLong();
		long nonce = dataIn.readLong();
		int  messageSize = mp.length - 2* Long.BYTES;
		byte[] message = new byte[ messageSize ];
		dataIn.read(message, 0, messageSize);
		Payload payload = new DefaultPayload(id, nonce, message);
		
		dataIn.close();
		byteIn.close();
		
		
		return payload;
	}

	@Override
	public byte[] getMessage() {
		
		return message;
	}
}

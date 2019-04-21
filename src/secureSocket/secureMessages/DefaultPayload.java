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
import secureSocket.Cryptography2;

// TODO : find better name for the class
public class DefaultPayload implements Payload {
	
	protected static final byte TYPE = 0x01;
		
	//Encryption support
	//private static Cryptography2 criptoService; 
	
	
	//Payload data
	private long id;
	private long nonce;
	private byte[] message;
	private byte[] innerMac;
	private byte[] cipherText;
	private byte[] outterMac;
	
	public DefaultPayload(long id, long nonce, byte[] message, Cryptography2 criptoService) throws IOException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		
		this.message = message;
		this.id = id;
		this.nonce = nonce;
		byte[] Mp = buildMp();
		
		// cipherText
		//this.criptoService = criptoService;
				
		//Append MacDoS
		this.innerMac = criptoService.computeMac(Mp);	
		this.cipherText = criptoService.encrypt( ArrayUtils.concat(Mp, innerMac));
		this.outterMac = criptoService.computeMacDoS(this.cipherText);
	}
	
	private DefaultPayload(long id, long nonce, byte[] message, byte[] ciphertext,
			byte[] innerMac, byte[] outterMac) {
		
		this.id = id;
			this.nonce = nonce;
		this.message = message;
		this.cipherText = ciphertext;
		this.innerMac = innerMac;
		this.outterMac = outterMac;
		
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
	// TODO : retornar Payload ou DEfaultPayload?
	public static Payload deserialize(byte[] rawPayload, Cryptography2 criptoService ) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		
	    byte[][] messageParts = criptoService.splitHeader(rawPayload);
	    if(criptoService.validateMacDos(messageParts[0], messageParts[1])) {
	    	byte[] plainText = criptoService.decrypt(messageParts[0]); //TODO: better name
	    	byte[][] payloadParts = criptoService.splitPayload(plainText);
	    	if(criptoService.validadeInnerMac(payloadParts[0], payloadParts[1])) {
	    		
	    		ByteArrayInputStream byteIn = new ByteArrayInputStream(payloadParts[0]);
	    		DataInputStream dataIn = new DataInputStream(byteIn);
	    		
	    		long id = dataIn.readLong();
	    		long nonce = dataIn.readLong();
	    		int  messageSize = payloadParts[0].length - 2* Long.BYTES;
	    		byte[] message = new byte[ messageSize ];
	    		dataIn.read(message, 0, messageSize);
	    	
	    		Payload payload = new DefaultPayload(id, nonce, message,
	    				messageParts[0], payloadParts[1], messageParts[1]);
	    		
	    		dataIn.close();
	    		byteIn.close();
	    		
	    		return payload;		
	    	}		
	    }
		return null;
	}

	@Override
	public byte[] getMessage() {
		return message;
	}
}

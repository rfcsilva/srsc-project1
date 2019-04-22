package kdc.needhamSchroeder;

import java.security.Key;

import javax.crypto.SecretKey;

import cryptography.Cryptography;
import secureSocket.secureMessages.Payload;

public class NS2 implements Payload { //{Na+1, Nc, Ks , B, {Nc, A, B, Ks}KB }KA 

	public static final byte TYPE = 0x12;
	
	private long Na; // EU acho que é NA' ou seja NA-1 ou NA+1 ou outra transformação
	private long Nc;
	private SecretKey Ks;
	private byte[] b;
	private byte[] cipherText;
	private byte[] ticket;
	private byte[] outerMac;
	
	// TODO passar o ticket ou criá-lo cá dentro?
	public NS2(long Na, long Nc, SecretKey Ks, byte[] b, byte[] ticket, Cryptography cryptoManager) {
		this.Na = Na;
		this.Nc = Nc;
		this.Ks = Ks;
		this.b = b;

		this.cipherText = null; // TODO

	}

	@Override
	public byte getPayloadType() {
		return TYPE;
	}

	@Override
	public byte[] serialize() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public short size() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public byte[] getMessage() {
		// TODO Auto-generated method stub
		return null;
	}

}

package kdc.needhamSchroeder;

import java.security.Key;

import secureSocket.secureMessages.Payload;

public class NS2 implements Payload {

	private long na;
	private long nc;
	private Key sessionKey;
	private byte[] b;
	
	
	public NS2() {
		// TODO Auto-generated constructor stub
	}

	@Override
	public byte getPayloadType() {
		// TODO Auto-generated method stub
		return 0;
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
package kdc;

import java.io.IOException;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;

import cryptography.Cryptography;

public interface KDCClient {

	public Cryptography getSessionParameters() throws NoSuchAlgorithmException, IOException;
	
}

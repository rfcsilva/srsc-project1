package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import cryptography.CryptographyNS;
import cryptography.CryptographyUtils;
import cryptography.nonce.CounterNonceManager;
import cryptography.nonce.NonceManager;
import kdc.KDC;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederKDC implements KDC {

	private SecureDatagramSocket socket;
	private NonceManager nonceManager;
	private String configPath;
	
	public NeedhamSchroederKDC(InetSocketAddress addr, CryptographyNS cryptoManager, String configPath) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(addr, cryptoManager);
		this.nonceManager = new CounterNonceManager(0, 3);
		this.configPath = configPath;
	}
	
	@Override
	public void start() throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, NoSuchProviderException, IOException, InvalidPayloadTypeException, BrokenBarrierException {
		while(true) {
			SecureMessage sm = new SecureMessageImplementation();
			InetSocketAddress client_addr = receiveRequest(sm);
			processRequest(sm, client_addr, configPath);
		}
	}
	
	private void processRequest(SecureMessage request, InetSocketAddress client_addr, String configPath) {
		long Nc = this.getNonce();
		new Thread(() -> {
			try {
				NS1 req = (NS1)request.getPayload();
				String a = req.getA();
				String b = req.getB();
				
				System.out.println("Received request from " + a + "(" + client_addr.toString() + ")" + " to " + b + " with nonce " + req.getNa());

				SecureDatagramSocket new_socket = new SecureDatagramSocket(req.getCryptoManagerA());

				// Generate Session Parameters
				//String path = "./configs/kdc/session-ciphersuite.conf"; // TODO: ISto deveria ser args
				byte[] securityParams = CryptoFactory.serialize(configPath); //buildSessionParameters(configPath);

				// TODO: FALTA FAZER DINHEIRO

				// envia replys
				long Na_1 = req.getNa() + 1;
				
				Payload payload = new NS2(Na_1, Nc, securityParams, req.getA(), req.getB(), req.getCryptoManagerB(), req.getCryptoManagerA());
				SecureMessage sm = new SecureMessageImplementation(payload);
				
				new_socket.send(sm, client_addr);
			} catch(Exception e) {
				e.printStackTrace(); // TODO: tratar as excepções
			}
		}).start();
	}

	public InetSocketAddress receiveRequest( SecureMessage sm ) throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {
		InetSocketAddress addr = null;
		
		boolean replay = false;
		do {
			addr = socket.receive(sm);
			
			// Verify if is replay
			long Na = ((NS1)sm.getPayload()).getNa();
			replay = this.verifyReplay(Na);
			if(replay)
				System.err.println("Replayed request " + Na);
		} while(replay);
		
		return addr;	
	}
	
	private synchronized long getNonce() {
		return nonceManager.getNonce();
	}
	
	private synchronized boolean verifyReplay(long nonce) {
		return nonceManager.verifyReplay(nonce);
	}
	
}

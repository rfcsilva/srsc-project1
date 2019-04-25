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
import java.util.concurrent.BrokenBarrierException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import cryptography.CryptographyNS;
import cryptography.nonce.NonceManager;
import cryptography.nonce.WindowNonceManager;
import kdc.KDCService;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.Payload;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederKDC implements KDCService {

	private SecureDatagramSocket socket;
	private NonceManager nonceManager;
	private String configPath;

	public NeedhamSchroederKDC(InetSocketAddress addr, CryptographyNS cryptoManager, String configPath) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, IOException {
		socket = new SecureDatagramSocket(addr, cryptoManager);
		this.nonceManager = new WindowNonceManager(100, cryptoManager.getSecureRandom());
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

		new Thread(() -> {
			try {
				NS1 req = (NS1)request.getPayload();
				String a = req.getA();
				String b = req.getB();
				long Na = req.getNa();

				if(this.verifyReplay(Na)) {
					System.err.println("Receveid replay " + Na);
				} else {
					System.out.println("Received request from " + a + "(" + client_addr.toString() + ")" + " to " + b + " with nonce " + Na);

					SecureDatagramSocket new_socket = new SecureDatagramSocket(req.getCryptoManagerA());

					// Generate Session Parameters for A and B
					byte[] securityParams = CryptoFactory.serialize(configPath); // TODO: renomear para buildSessionParameters(configPath);

					// TODO: FALTA FAZER DINHEIRO

					// Send reply to A
					long Na_1 = req.getNa() + 1;
					long Nc = this.getNonce();

					Payload payload = new NS2(Na_1, Nc, securityParams, a, b, req.getCryptoManagerB(), req.getCryptoManagerA());
					SecureMessage sm = new SecureMessageImplementation(payload);
					new_socket.send(sm, client_addr);
				}

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
		return nonceManager.generateNonce();
	}

	private synchronized boolean verifyReplay(long nonce) {
		return nonceManager.verifyReplay(nonce);
	}

}

package kdc.needhamSchroeder;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.CryptoFactory;
import cryptography.Cryptography;
import cryptography.nonce.WindowNonceManager;
import kdc.KDCServer;
import secureSocket.SecureDatagramSocket;
import secureSocket.exceptions.InvalidPayloadTypeException;
import secureSocket.secureMessages.SecureMessage;
import secureSocket.secureMessages.SecureMessageImplementation;

public class NeedhamSchroederServer implements KDCServer {

	private static final int WINDOW_SIZE = 100;

	private InetSocketAddress b_addr;
	private Cryptography master_cryptoManager;
	private WindowNonceManager nonceManager;

	public NeedhamSchroederServer(InetSocketAddress b_addr, Cryptography master_cryptoManager)
			throws InvalidKeyException, NoSuchAlgorithmException, UnrecoverableEntryException, KeyStoreException,
			CertificateException, NoSuchPaddingException, InvalidAlgorithmParameterException, IOException,
			ShortBufferException, IllegalBlockSizeException, BadPaddingException {

		this.b_addr = b_addr;
		this.master_cryptoManager = master_cryptoManager;
		this.nonceManager = new WindowNonceManager(WINDOW_SIZE, master_cryptoManager.getSecureRandom());
	}

	@Override
	public Cryptography getSessionParameters()
			throws InvalidKeyException, ShortBufferException, IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException,
			UnrecoverableEntryException, KeyStoreException, CertificateException, IOException, NoSuchProviderException,
			InvalidPayloadTypeException, BrokenBarrierException { // TODO: isto precisa de outo nome

		AtomicReference<Cryptography> cryptoManager = new AtomicReference<>(null);
		AtomicBoolean finished = new AtomicBoolean(false);

		// Listen for incoming requests
		listenRequests(finished, cryptoManager, master_cryptoManager);

		while (!finished.get()) {
			try {
				Thread.sleep(100); // TODO : quanto tempo?
			} catch (Exception e) {}
		}

		return cryptoManager.get();
	}

	private void listenRequests(AtomicBoolean finished, AtomicReference<Cryptography> cryptoManager, Cryptography master_cryptoManager) 
			throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, 
			UnrecoverableEntryException, KeyStoreException,	CertificateException, IOException, ShortBufferException, 
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException {

		/*new Thread(() -> {
			try {*/
				SecureDatagramSocket inSocket = new SecureDatagramSocket(b_addr, master_cryptoManager);
				inSocket.setTimeout(5 * 1000); // TODO: Isto parece pouco não?

				System.out.println("Waitting for Ticket...");

				while (!finished.get()) {
					try {
						// Receive Ticket
						SecureMessage sm = new SecureMessageImplementation();
						InetSocketAddress addr = inSocket.receive(sm);

						System.out.println("Received Ticket.");

						NS3 ns3 = (NS3) sm.getPayload();

						// If not replay
						if (!verifyReplay(ns3.getNc()))
							processRequest(ns3, addr, cryptoManager, finished);
						else
							System.err.println("Replay of: " + ns3.getNc());

					} catch (SocketTimeoutException e) {}
				}

				inSocket.close();

			/*}  catch(Exception e) {
				e.printStackTrace();
			}

		}).start();*/
	}

	private void processRequest(NS3 ns3, InetSocketAddress addr, AtomicReference<Cryptography> cryptoManager, AtomicBoolean finished) {
		new Thread(() -> {
			try {
				Cryptography session_cryptoManager = CryptoFactory.deserialize( ns3.getKs() ); //UDP_KDC_Server.deserializeSessionParameters(ns3.getKs());

				SecureDatagramSocket new_socket = new SecureDatagramSocket(session_cryptoManager);
				new_socket.setTimeout(30 * 1000); // TODO : quanto timeout?

				long Nb = getNonce();

				NS4 ns4 = new NS4(Nb, session_cryptoManager);
				SecureMessage sm = new SecureMessageImplementation(ns4);
				new_socket.send(sm, addr);
				System.out.println("Sending Challenge... " + Nb);

				SecureMessage sm2 = new SecureMessageImplementation();
				new_socket.receive(sm2);
				// System.out.println("Received Challenge answer.");

				NS4 ns5 = (NS4) sm2.getPayload();

				if (ns5.getNb() == (Nb + 1)) {
					System.out.println("Valid Challenge Answer: " + ns5.getNb());
					cryptoManager.set(session_cryptoManager);
					finished.set(true);
				} else {
					System.err.println("Invalid Challenge Answer: " + ns5.getNb() + " != " + (Nb + 1));
				}

				new_socket.close();

			} catch (Exception e) {
				//e.printStackTrace();
			}
		}).start();
	}

	private synchronized long getNonce() {
		return this.nonceManager.generateNonce();
	}

	private synchronized boolean verifyReplay(long nonce) {
		return this.nonceManager.verifyReplay(nonce);
	}

}

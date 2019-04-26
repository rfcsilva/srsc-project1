package keyEstablishmentProtocol;

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

import javax.crypto.NoSuchPaddingException;

import cryptography.Cryptography;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.InvalidChallangeReplyException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.TooManyTriesException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnServerException;
import secureSocket.exceptions.InvalidPayloadTypeException;

public interface KeyEstablishmentProtocolClient {

	public Cryptography getSessionParameters(String b, String[] arguments) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidChallangeReplyException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, TooManyTriesException, UnkonwnIdException, UnkonwnServerException;
	
	public InetSocketAddress getMyAddr() ; // TODO: isto deveria de desaparecer, não? ou entaõ devolver a socket no método de cima?
	
}

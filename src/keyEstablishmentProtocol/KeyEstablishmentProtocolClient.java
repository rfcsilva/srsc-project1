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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

import cryptography.Cryptography;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.InvalidChallangeReplyException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.TooManyTriesException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnIdException;
import keyEstablishmentProtocol.needhamSchroeder.exceptions.UnkonwnServerException;
import secureSocket.exceptions.InvalidPayloadTypeException;

public interface KeyEstablishmentProtocolClient {

	public Cryptography getSessionParameters(String b, String[] arguments) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, UnrecoverableEntryException, KeyStoreException, CertificateException, InvalidChallangeReplyException, NoSuchProviderException, InvalidPayloadTypeException, BrokenBarrierException, TooManyTriesException, UnkonwnIdException, UnkonwnServerException, IllegalBlockSizeException, BadPaddingException, ShortBufferException;
	
	public InetSocketAddress getMyAddr() ;
	
}

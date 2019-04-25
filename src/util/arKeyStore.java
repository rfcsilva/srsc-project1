package util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.List;

import javax.crypto.SecretKey;

public class arKeyStore {

	private KeyStore keystore;
	private String password;
	private String path;

	public arKeyStore(String path, String password, String type) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		this.keystore = loadKeyStore(path, password, type);
		this.password = password;
		this.path = path;
	}

	public KeyStore.Entry getEntry(String alias) {
		try {
			KeyStore.PasswordProtection ks_pp = new KeyStore.PasswordProtection(password.toCharArray());
			return keystore.getEntry(alias, ks_pp);
		} catch( KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e ) {
			return null;
		}
	}

	public boolean setEntry(String alias, KeyStore.Entry entry) {
		try {
			KeyStore.PasswordProtection ks_pp = new KeyStore.PasswordProtection(password.toCharArray());
			keystore.setEntry(alias, entry, ks_pp);
			return true;
		} catch( KeyStoreException e ) {
			return false;
		}
	}

	public SecretKey getKey(String alias) {
		try {
			SecretKeyEntry entry = (KeyStore.SecretKeyEntry) this.getEntry(alias);
			return entry.getSecretKey();
		} catch( NullPointerException e) {
			return null;
		}
	}

	public boolean setKey(String alias, SecretKey key) {
		try {
			keystore.setKeyEntry(alias, key, this.password.toCharArray(), null);
			return true;
		} catch( KeyStoreException e ) {
			return false;
		}
	}
	
	public boolean removeEntry(String alias) {
		try {
			keystore.deleteEntry(alias);
			return true;
		} catch (KeyStoreException e) {
			return false;
		}
	}
	
	public boolean removeKey(String alias) {
		return this.removeEntry(alias);
	}
	
	public List<String> aliases() {
		List<String> list = null;
		try {
			list = Collections.list(keystore.aliases());
		} catch (KeyStoreException e) {}
		return list;
	}
	
	public boolean contains(String alias) {
		try {
			return keystore.containsAlias(alias);
		} catch (KeyStoreException e) {
			return false;
		}
	}
	
	public void store() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		OutputStream os = new FileOutputStream(this.path, false);
		keystore.store(os, this.password.toCharArray());
	}
	
	public static KeyStore loadKeyStore(String path, String password, String keyStore_type) throws KeyStoreException,
	NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException {
		KeyStore key_store = KeyStore.getInstance(keyStore_type);
		key_store.load(new FileInputStream(path), password.toCharArray());
		return key_store;
	}

	/*private static SecretKey getKey(KeyStore ks, String password, String alias) throws NoSuchAlgorithmException,
	UnrecoverableEntryException, KeyStoreException, CertificateException, FileNotFoundException, IOException {

		KeyStore.PasswordProtection ks_pp = new KeyStore.PasswordProtection(password.toCharArray());
		SecretKeyEntry entry = (KeyStore.SecretKeyEntry) ks.getEntry(alias, ks_pp);
		return entry.getSecretKey();
	}*/

}

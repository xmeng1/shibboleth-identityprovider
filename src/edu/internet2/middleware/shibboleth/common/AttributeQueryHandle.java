package edu.internet2.middleware.shibboleth.common;

import java.util.StringTokenizer;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.doomdark.uuid.UUID;
import org.doomdark.uuid.UUIDGenerator;

/**
 * A Shibboleth Attribute Query Handle.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 *
 */

public class AttributeQueryHandle {

	private String principal;
	private long creationTime;
	private long expirationTime;
	private byte[] cipherTextHandle;
	private String handleID;

	/**
	 * Unmarshalls an <code>AttributeQueryHandle</code> based on the results of the serialize() method
	 * of an existing <code>AttributeQueryHandle</code>.  Requires a key identical to the one used
	 * in the creation of the original <code>AttributeQueryHandle</code>.
	 * 
	 */

	public AttributeQueryHandle(String handle, SecretKey key)
		throws HandleException {

		try {
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key);
			StringTokenizer tokenizer =
				new StringTokenizer(
					new String(cipher.doFinal(Base64.decode(handle))),
					"||",
					false);
			principal = tokenizer.nextToken();
			expirationTime = new Long(tokenizer.nextToken()).longValue();
			handleID = tokenizer.nextToken();
		} catch (Exception e) {
			throw new HandleException("Error unmarshalling handle: " + e);
		}

	}

	/**
	 * Creates a new <code>AttributeQueryHandle</code>
	 * @param principal <code>String</code> representation of user that the handle should reference
	 * @param validityPeriod Time in milliseconds for which the handle should be valid
	 * @param hsLocation URL of the Handle Service used to generate the AQH
	 * @param key Symmetric key used to encrypt the AQH upon serialization
	 * 
	 */

	public AttributeQueryHandle(
		String principal,
		SecretKey key,
		long validityPeriod,
		String hsLocation)
		throws HandleException {

		this.principal = principal;
		this.creationTime = System.currentTimeMillis();
		this.expirationTime = creationTime + validityPeriod;

		try {
			//create a unique id based on the url of the HS and the current time
			UUIDGenerator uuidGen = UUIDGenerator.getInstance();
			UUID nameSpaceUUID = new UUID(UUID.NAMESPACE_URL);
			handleID =
			uuidGen.generateNameBasedUUID(nameSpaceUUID, hsLocation)+ ":" + uuidGen.generateTimeBasedUUID();
			
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipherTextHandle =
				cipher.doFinal(
					(principal + "||" + expirationTime + "||" + handleID)
						.getBytes());

		} catch (Exception e) {
			throw new HandleException("Error creating handle: " + e);

		}

	}

	/**
	 * Returns a <code>String</code> representation of the user that the handle references.
	 */

	public String getPrincipal() {
		return principal;
	}

	/**
	 * Returns a <code>String</code> of ciphertext representing the <code>AttributeQueryHandle</code> instance.
	 */

	public String serialize() {

		return new String(Base64.encode(cipherTextHandle));
	}

	/**
	 * Boolean result indicates whether the validity of this <code>AttributeQueryHandle</code> 
	 * has lapsed.
	 */

	public boolean isExpired() {

		if (System.currentTimeMillis() > expirationTime) {
			return true;
		} else {
			return false;
		}

	}

	/**
	 * Returns a <code>String</code> representation of the unique identifier for this handle.
	 */
	
	public String getHandleID() {
		return handleID;
	}

}
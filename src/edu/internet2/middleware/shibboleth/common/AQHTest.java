package edu.internet2.middleware.shibboleth.common;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
/**
 * Exercises the <code>AttributeQueryHandle</code>
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 *
 */
public class AQHTest extends TestCase {
	protected SecretKey goodKey;
	protected String testHs;
	public AQHTest(String name) {
		super(name);
	}

	public static void main(String args[]) {
		junit.textui.TestRunner.run(AQHTest.class);
	}

	/**
	 * @see TestCase#setUp()
	 */

	protected void setUp() {
		try {
			Security.addProvider(new BouncyCastleProvider());
			KeyGenerator gen = KeyGenerator.getInstance("DESede");
			gen.init(new SecureRandom());
			goodKey = gen.generateKey();
		} catch (NoSuchAlgorithmException e) {
			fail("Could not generate fixture (secret key)");
		}
		testHs = "http://www.test.com/HS";
	}
	/**
	 * Tests the basic, creation, serialization, and unmarshalling of the <code>AttributeQueryHandle</code>
	 */

	public void testAQH() {
		try {
			//Create an AQH
			AttributeQueryHandle originalAQH =
				new AttributeQueryHandle("Walter", goodKey, 300000l, testHs);
			//Ensure that a unique id was generated 
			assertNotNull("No unique id generated for handle", originalAQH.getHandleID());
			String cacheHandleID = originalAQH.getHandleID();
			//Ensure that the principal was set correctly
			assertEquals("Principal incorrect", "Walter", originalAQH.getPrincipal());
			//Test to see that the handle has not expired	
			//Hopefull this doesn't take more than 5 mintues to run :-)
			assertTrue("AttributeQueryHandle unexpectedly expired.", (!originalAQH.isExpired()));
			//Create a new AQH from the serialized first AQH
			AttributeQueryHandle secondAQH =
				new AttributeQueryHandle(originalAQH.serialize(), goodKey);
			//Ensure that the principal was set correctly
			assertEquals("Principal incorrect", "Walter", secondAQH.getPrincipal());
			//Test to see that the handle has not expired	
			//Hopefull this doesn't take more than 5 mintues to run :-)
			assertTrue("AttributeQueryHandle unexpectedly expired.", (!secondAQH.isExpired()));
			//Make sure that the handle id matches that of the first object
			assertEquals(
				"Improper unmarshalling of unique handle id",
				cacheHandleID,
				secondAQH.getHandleID());
		} catch (HandleException e) {
			fail("Failed to create AttributeQueryHandle" + e);
		}
	}
	/**
	 * Ensure that <code>AttributeQueryHandle</code> objects expire correctly
	 */
	public void testExpiration() {
		try {
			AttributeQueryHandle aqh = new AttributeQueryHandle("Walter", goodKey, 1l, testHs);
			Thread.sleep(2);
			assertTrue("AttributeQueryHandle failed to expire appropriately", aqh.isExpired());
		} catch (InterruptedException e) {
		} catch (HandleException e) {
			fail("Failed to create AttributeQueryHandle" + e);
		}
	}
	/**
	 * Ensue that all of our UUIDs are not identical
	 */
	public void testDups() {
		try {
			AttributeQueryHandle aqh1 = new AttributeQueryHandle("Walter", goodKey, 1l, testHs);
			AttributeQueryHandle aqh2 = new AttributeQueryHandle("Walter", goodKey, 1l, testHs);
			assertTrue(
				"Reusing a UUID when creating new AQH",
				!aqh1.getHandleID().equals(aqh2.getHandleID()));
		} catch (HandleException e) {
			fail("Failed to create AttributeQueryHandle" + e);
		}
	}
}
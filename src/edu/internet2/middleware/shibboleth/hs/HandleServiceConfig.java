package edu.internet2.middleware.shibboleth.hs;

/**
 * Class used by the  WAYF service to determine runtime options.  
 * Most of the fields of this class should have reasonable defaults.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class HandleServiceConfig {

	private static String logoLocation = "images/internet2.gif";
	private static String supportContact = "mailto:shib-support@internet2.org";
	private static String location = "http://shib2.internet2.edu/shibboleth/HS";
	private static String helpText =
		"In order to fulfill the request for the web"
			+ " resource you have just chosen, information must be sent from your home institution to the "
			+ "provider of the resource.  The web resource should load automatically.  If it does not load within "
			+ "five seconds, click on the Transmit button.";
	private static String detailedHelpURL = "http://blah";
	private static String handleRepositoryImplementation =
		"edu.internet2.middleware.shibboleth.common.provider.MemoryHandleRepository";
	private static String validityPeriod = "1400000";
	private static String domain = "internet2.edu";
	private static String issuer = "shib2.internet2.edu";
	private static String aaURL = "https://shib2.internet2.edu/shibb/servlet/AAServlet";
	private static String secretKey;

	/**
	 * Constructor for HandleServiceConfig.
	 */
	public HandleServiceConfig() {
		super();
	}

	/**
	 * Gets the logoLocation.
	 * @return Returns a String
	 */
	public static String getLogoLocation() {
		return logoLocation;
	}

	/**
	 * Sets the logoLocation.
	 * @param logoLocation The logoLocation to set
	 */
	public static void setLogoLocation(String logoLocation) {
		HandleServiceConfig.logoLocation = logoLocation;
	}

	/**
	 * Gets the supportContact.
	 * @return Returns a String
	 */
	public static String getSupportContact() {
		return supportContact;
	}

	/**
	 * Sets the supportContact.
	 * @param supportContact The supportContact to set
	 */
	public static void setSupportContact(String supportContact) {
		HandleServiceConfig.supportContact = supportContact;
	}

	/**
	 * Gets the helpText.
	 * @return Returns a String
	 */
	public static String getHelpText() {
		return helpText;
	}

	/**
	 * Sets the helpText.
	 * @param helpText The helpText to set
	 */
	public static void setHelpText(String hs_helpText) {
		HandleServiceConfig.helpText = hs_helpText;
	}

	/**
	 * Gets the handleRepositoryImplementation.
	 * @return Returns a String
	 */
	public static String getHandleRepositoryImplementation() {
		return handleRepositoryImplementation;
	}

	/**
	 * Sets the handleRepositoryImplementation.
	 * @param handleRepositoryImplementation The handleRepositoryImplementation to set
	 */
	public static void setHandleRepositoryImplementation(String handleRepositoryImplementation) {
		HandleServiceConfig.handleRepositoryImplementation = handleRepositoryImplementation;
	}

	/**
	 * Gets the detailedHelpURL.
	 * @return Returns a String
	 */
	public static String getDetailedHelpURL() {
		return detailedHelpURL;
	}

	/**
	 * Sets the detailedHelpURL.
	 * @param detailedHelpURL The detailedHelpURL to set
	 */
	public static void setDetailedHelpURL(String hs_detailedHelpURL) {
		HandleServiceConfig.detailedHelpURL = hs_detailedHelpURL;
	}

	/**
	 * Gets the location.
	 * @return Returns a String
	 */
	public static String getLocation() {
		return location;
	}

	/**
	 * Sets the location.
	 * @param location The location to set
	 */
	public static void setLocation(String hs_location) {
		HandleServiceConfig.location = hs_location;
	}

	/**
	 * Gets the ticket.
	 * @return Returns a String
	 */
	public static String getValidityPeriod() {
		return validityPeriod;
	}

	/**
	 * Sets the ticket.
	 * @param ticket The ticket to set
	 */
	public static void setValidityPeriod(String validityPeriod) {
		HandleServiceConfig.validityPeriod = validityPeriod;
	}

	/**
	 * Gets the domain.
	 * @return Returns a String
	 */
	public static String getDomain() {
		return domain;
	}

	/**
	 * Sets the domain.
	 * @param domain The domain to set
	 */
	public static void setDomain(String domain) {
		HandleServiceConfig.domain = domain;
	}

	/**
	 * Gets the issuer.
	 * @return Returns a String
	 */
	public static String getIssuer() {
		return issuer;
	}

	/**
	 * Sets the issuer.
	 * @param issuer The issuer to set
	 */
	public static void setIssuer(String issuer) {
		HandleServiceConfig.issuer = issuer;
	}

	/**
	 * Gets the aaURL.
	 * @return Returns a String
	 */
	public static String getAaURL() {
		return aaURL;
	}

	/**
	 * Sets the aaURL.
	 * @param aaURL The aaURL to set
	 */
	public static void setAaURL(String aaURL) {
		HandleServiceConfig.aaURL = aaURL;
	}

	/**
	 * Gets the secretKey.  Can only be retrieved one time.
	 * @return Returns a String
	 */
	public static String getSecretKey() {
		String cacheKey = secretKey;
		secretKey = null;
		return cacheKey;
	}

	/**
	 * Sets the secretKey.
	 * @param secretKey The secretKey to set
	 */
	public static void setSecretKey(String secretKey) {
		HandleServiceConfig.secretKey = secretKey;
	}

}
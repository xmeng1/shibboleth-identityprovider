package edu.internet2.middleware.shibboleth.hs;

import java.io.IOException;
import java.io.InputStream;
import java.security.Security;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.xml.sax.SAXException;

import edu.internet2.middleware.shibboleth.AABindingInfo;
import edu.internet2.middleware.shibboleth.Policies;
import edu.internet2.middleware.shibboleth.SAMLAuthenticationAssertionFactory;
import edu.internet2.middleware.shibboleth.SAMLException;
import edu.internet2.middleware.shibboleth.common.AttributeQueryHandle;
import edu.internet2.middleware.shibboleth.common.Base64;
import edu.internet2.middleware.shibboleth.common.HandleException;

/**
 * 
 * A servlet implementation of the Shibboleth Handle Service.  Accepts 
 * Shibboleth Attribute Query Handle Requests via HTTP GET and generates 
 * SAML authN assertions containing an opaque user handle.  These assertions are 
 * embedded in an HTML that auto-POSTs to the referring SHIRE.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 * @author Barbara Jenson blk&#064;cmu.edu
 *
 */

public class HandleService extends HttpServlet {

	private static Logger log = Logger.getLogger(HandleService.class.getName());
	private SAMLAuthenticationAssertionFactory assertionFactory;
	private String hsConfigFileLocation;
	private String log4jConfigFileLocation;
	private SecretKey key;

	/**
	 * @see GenericServlet#init()
	 */

	public void init() throws ServletException {

		super.init();
		loadInitParams();
		initLogger();
		initConfig();
		initViewConfig();
		initSecretKey();
		initAuthNFactory();
	}

	/**
	 * Initializes symmetric key for use in AQH creation
	 */

	private void initSecretKey() throws ServletException {

		try {

			//Currently hardcoded to use Bouncy Castle
			//Decide to change this or not based on overall shibboleth policy
			Security.addProvider(new BouncyCastleProvider());
			SecretKeyFactory keyFactory =
				SecretKeyFactory.getInstance("DESede");
			DESedeKeySpec keySpec =
				new DESedeKeySpec(
					Base64.decode(HandleServiceConfig.getSecretKey()));
			key = keyFactory.generateSecret(keySpec);
		} catch (Exception t) {
			log.fatal("Error reading Secret Key from configuration.", t);
			throw new ServletException("Error reading Key from configuration.");
		}

	}

	/**
	 * Retrieves location of HS configuration files from the servlet configuration.
	 */

	private void loadInitParams() {

		hsConfigFileLocation =
			getServletConfig().getInitParameter("HSConfigFileLocation");
		if (hsConfigFileLocation == null) {
			hsConfigFileLocation = "/WEB-INF/conf/shibboleth.xml";
		}
		log4jConfigFileLocation =
			getServletConfig().getInitParameter("log4jConfigFileLocation");
		if (log4jConfigFileLocation == null) {
			log4jConfigFileLocation = "/WEB-INF/conf/log4j.properties";
		}

	}

	/**
	 * Loads HS configuration.  Populates a <code>HandleServiceConfig</code> object based
	 * on administrator supplied configuration.
	 */

	private void initConfig() throws ServletException {

		InputStream is =
			getServletContext().getResourceAsStream(hsConfigFileLocation);
		HsConfigDigester digester = new HsConfigDigester();
		try {
			digester.parse(is);
		} catch (SAXException se) {
			log.fatal("Error parsing HS configuration file.", se);
			throw new ServletException(
				"Error parsing HS configuration file.",
				se);
		} catch (IOException ioe) {
			log.fatal("Error reading HS configuration file.", ioe);
			throw new ServletException(
				"Error reading HS configuration file.",
				ioe);
		}

	}

	/**
	 * Starts up Log4J.
	 */

	private void initLogger() {

		PropertyConfigurator.configure(
			getServletContext().getRealPath("/") + log4jConfigFileLocation);

	}

	/**
	 * Places configuration parameters in the <code>ServletContext</code> so that they may 
	 * be retreived by view components.
	 */

	private void initViewConfig() {
		getServletContext().setAttribute(
			"hs_supportContact",
			HandleServiceConfig.getSupportContact());
		getServletContext().setAttribute(
			"hs_logoLocation",
			HandleServiceConfig.getLogoLocation());
		getServletContext().setAttribute(
			"hs_helpText",
			HandleServiceConfig.getHelpText());
		getServletContext().setAttribute(
			"hs_detailedHelpURL",
			HandleServiceConfig.getDetailedHelpURL());
		getServletContext().setAttribute(
			"hs_location",
			HandleServiceConfig.getHsURL());
	}

	/**
	 * Initializes SAML AuthN Factory
	 */

	private void initAuthNFactory() throws ServletException {
		try {
			AABindingInfo[] binfo = new AABindingInfo[1];
			binfo[0] =
				new AABindingInfo(
					AABindingInfo.SAML_SOAP_HTTPS,
					HandleServiceConfig.getAaURL());
			String[] policies = { Policies.POLICY_URI_CLUBSHIB };
			assertionFactory =
				SAMLAuthenticationAssertionFactory.getInstance(
					policies,
					HandleServiceConfig.getIssuer(),
					HandleServiceConfig.getDomain(),
					binfo,
					null,
					null);

		} catch (SAMLException se) {
			log.fatal("Error initializing SAML library: ", se);
			throw new ServletException("Error initializing SAML library: ", se);
		}
	}

	/**
	 * @see HttpServlet#doGet(HttpServletRequest, HttpServletResponse)
	 */

	public void doGet(HttpServletRequest req, HttpServletResponse resp)
		throws ServletException, IOException {

		try {
			validateRequestParameters(req);
			req.setAttribute("shire", req.getParameter("shire"));
			req.setAttribute("target", req.getParameter("target"));
			log.info("Generating assertion...");
			long startTime = System.currentTimeMillis();
			byte[] assertion =
				generateAssertion(
					req.getParameter("shire"),
					req.getRemoteAddr(),
					req.getRemoteUser(),
					req.getAuthType());
			log.info(
				"Assertion Generated: "
					+ "elapsed time "
					+ (System.currentTimeMillis() - startTime)
					+ " milliseconds.");
			log.debug("Assertion: " + new String(Base64.decode(assertion)));
			handleForm(req, resp, assertion);
		} catch (HandleServiceException e) {
			handleError(req, resp, e);
		}

	}

	/**
	 * Deals with HS runtime exceptions.  Logs errors locally and then 
	 * formats them for output to user.
	 * 
	 * @param e The Exception to be handled
	 */

	private void handleError(
		HttpServletRequest req,
		HttpServletResponse res,
		Exception e) throws ServletException {

		log.warn("Handle Service Failure: " + e);

		req.setAttribute("errorText", e.toString());
		RequestDispatcher rd = req.getRequestDispatcher("/hserror.jsp");

		try {
			rd.forward(req, res);
		} catch (IOException ioe) {
			log.info(
				"IO operation interrupted when displaying Handle Service error page: "
					+ ioe);
		} catch (ServletException se) {
			log.error(
				"Problem trying to display Handle Service error page: " + se);
				throw se;
		}
	}

	/**
	 * Method for auto-POSTing a Base64 encoded SAML assertion.
	 * 
	 * @param assertion Base64 encoded SAML authN assertion
	 */

	private void handleForm(
		HttpServletRequest req,
		HttpServletResponse res,
		byte[] assertion)
		throws HandleServiceException {

		try {
			//Hardcoded to ASCII to ensure Base64 encoding compatibility
			req.setAttribute("assertion", new String(assertion, "ASCII"));
			RequestDispatcher rd = req.getRequestDispatcher("/hs.jsp");
			log.info("POSTing assertion to SHIRE.");
			rd.forward(req, res);
		} catch (IOException ioe) {
			throw new HandleServiceException(
				"IO interruption while displaying Handle Service UI." + ioe);
		} catch (ServletException se) {
			throw new HandleServiceException(
				"Problem displaying Handle Service UI." + se);
		}
	}

	/**
	 * Generates a new <code>AttributeQueryHandle</code> and includes it in a 
	 * <code>SAMLAuthenticationAssertion</code>.
	 */

	private byte[] generateAssertion(
		String shireURL,
		String clientAddress,
		String remoteUser,
		String authType)
		throws HandleServiceException {
		try {

			AttributeQueryHandle aqh =
				new AttributeQueryHandle(
					remoteUser,
					key,
					Long.parseLong(HandleServiceConfig.getValidityPeriod()),
					HandleServiceConfig.getHsURL());

			log.info("Acquired Handle: " + aqh.getHandleID());

			return assertionFactory
				.getAssertion(
					new String(aqh.serialize(), "ASCII"),
					shireURL,
					clientAddress,
					authType,
					new Date(),
					null)
				.toBase64();

		} catch (SAMLException se) {
			throw new HandleServiceException(
				"Error creating SAML assertion: " + se);
		} catch (IOException ioe) {
			throw new HandleServiceException(
				"Error creating SAML assertion: " + ioe);
		} catch (HandleException he) {
			throw new HandleServiceException(
				"Error creating User Handle: " + he);
		}
	}

	/**
	 * Ensures that <code>HttpServletRequest</code> contains all of the parameters necessary
	 * for generation of an <code>AttributeQueryHandle</code>.
	 */

	private void validateRequestParameters(HttpServletRequest req)
		throws HandleServiceException {

		if ((req.getParameter("shire") == null)
			|| (req.getParameter("shire").equals(""))) {
			throw new HandleServiceException("Invalid data from SHIRE: No acceptance URL received.");
		}
		if ((req.getParameter("target") == null)
			|| (req.getParameter("target").equals(""))) {
			throw new HandleServiceException("Invalid data from SHIRE: No target URL received.");
		}
		if ((req.getRemoteUser() == null)
			|| (req.getRemoteUser().equals(""))) {
			throw new HandleServiceException("No authentication received from webserver.");
		}
		if ((req.getAuthType() == null) || (req.getAuthType().equals(""))) {
			throw new HandleServiceException("Unable to ascertain authentication type.");
		}
		if ((req.getRemoteAddr() == null)
			|| (req.getRemoteAddr().equals(""))) {
			throw new HandleServiceException("Unable to ascertain client address.");
		}
	}

}
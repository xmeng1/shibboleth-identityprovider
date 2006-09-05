
package edu.internet2.middleware.shibboleth.idp.provider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.opensaml.NoSuchProviderException;
import org.opensaml.SAMLBinding;
import org.opensaml.SAMLBindingFactory;
import org.opensaml.SAMLException;
import org.opensaml.SAMLRequest;
import org.opensaml.SAMLResponse;
import org.w3c.dom.Element;

import edu.internet2.middleware.shibboleth.common.ShibbolethConfigurationException;
import edu.internet2.middleware.shibboleth.idp.RequestHandlingException;

public abstract class SAMLv1_Base_QueryHandler extends BaseServiceHandler {

	private static Logger log = Logger.getLogger(SAMLv1_Base_QueryHandler.class.getName());
	protected SAMLBinding binding;

	protected SAMLv1_Base_QueryHandler(Element config) throws ShibbolethConfigurationException {

		super(config);

		try {
			binding = SAMLBindingFactory.getInstance(SAMLBinding.SOAP);
		} catch (NoSuchProviderException e) {
			log.error("Unable to initialize SAML SOAP binding:" + e);
			throw new ShibbolethConfigurationException("Couldn't initialize " + getHandlerName() + " handler.");
		}
	}

	protected SAMLRequest parseSAMLRequest(HttpServletRequest request) throws RequestHandlingException {

		// Parse SOAP request and marshall SAML request object
		SAMLRequest samlRequest = null;
		try {
			samlRequest = binding.receive(request, 1);
		} catch (SAMLException e) {
			log.error("Unable to parse request: " + e);
			throw new RequestHandlingException("Invalid request data.");
		}

		// If we have DEBUG logging turned on, dump out the request to the log
		// This takes some processing, so only do it if we need to
		if (log.isDebugEnabled()) {
			log
					.debug("Dumping generated SAML Request:" + System.getProperty("line.separator")
							+ samlRequest.toString());
		}
		return samlRequest;
	}

	protected void respondWithError(HttpServletResponse response, SAMLRequest samlRequest, SAMLException e)
			throws RequestHandlingException {

		log.error("Error while processing request: " + e);
		try {
			SAMLResponse samlResponse = new SAMLResponse((samlRequest != null) ? samlRequest.getId() : null, null,
					null, e);
			if (log.isDebugEnabled()) {
				log.debug("Dumping generated SAML Error Response:" + System.getProperty("line.separator")
						+ samlResponse.toString());
			}
			binding.respond(response, samlResponse, null);
			log.debug("Returning SAML Error Response.");
		} catch (SAMLException se) {
			try {
				binding.respond(response, null, e);
			} catch (SAMLException e1) {
				log.error("Caught exception while responding to requester: " + e.getMessage());
				throw new RequestHandlingException(e1.getMessage());
			}
		}
	}

}
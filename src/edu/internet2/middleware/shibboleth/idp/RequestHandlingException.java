
package edu.internet2.middleware.shibboleth.idp;

/**
 * Signals that an IdPProtocolHandler was unable to respond appropriately to a request.
 */
public class RequestHandlingException extends Exception {

	RequestHandlingException(String message) {

		super(message);
	}

}

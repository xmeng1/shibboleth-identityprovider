package edu.internet2.middleware.shibboleth.hs;

/**
 * 
 * Signals that an error has occurred while processing a 
 * Shibboleth AQHR (Attribute Query Handle Request)
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 *
 */

public class HandleServiceException extends Exception {

	/**
	 * Constructs a <code>HandleServiceException</code> with the specified detail
	 * message. The error message string <code>s</code> can later be
	 * retrieved by the <code>{@link java.lang.Throwable#getMessage}</code>
	 * method of class <code>java.lang.Throwable</code>.
	 *
	 * @param   s   the detail message.
	 */

	public HandleServiceException(String message) {

		super(message);
	}

}
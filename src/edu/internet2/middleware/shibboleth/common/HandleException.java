package edu.internet2.middleware.shibboleth.common;

/**
 * 
 * Signals that an error has occurred while creating
 * a shibboleth AQH (Attribute Query Handle)
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 *
 */

public class HandleException extends Exception {

	/**
	 * Constructs a <code>HandleException</code> with the specified detail
	 * message. The error message string <code>s</code> can later be
	 * retrieved by the <code>{@link java.lang.Throwable#getMessage}</code>
	 * method of class <code>java.lang.Throwable</code>.
	 *
	 * @param s The detailed message.
	 */

	public HandleException(String message) {

		super(message);
	}

}
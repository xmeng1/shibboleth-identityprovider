package edu.internet2.middleware.shibboleth.wayf;

/**
 * Signals that an error has occurred while processing a 
 * Shibboleth WAYF request.
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfException extends Exception {

	public WayfException(String message) {

		super(message);
	}
}
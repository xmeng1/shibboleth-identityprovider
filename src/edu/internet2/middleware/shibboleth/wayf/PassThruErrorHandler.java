package edu.internet2.middleware.shibboleth.wayf;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Sax <code>ErrorHandler</code> that simply passes all errors up as new 
 * exceptions.
 */

public class PassThruErrorHandler implements ErrorHandler {

	/**
	 * @see org.xml.sax.ErrorHandler#error(SAXParseException)
	 */
	public void error(SAXParseException arg0) throws SAXException {
		throw new SAXException("Error parsing xml file: " + arg0);
	}

	/**
	 * @see org.xml.sax.ErrorHandler#fatalError(SAXParseException)
	 */
	public void fatalError(SAXParseException arg0) throws SAXException {
		throw new SAXException("Error parsing xml file: " + arg0);
	}

	/**
	 * @see org.xml.sax.ErrorHandler#warning(SAXParseException)
	 */
	public void warning(SAXParseException arg0) throws SAXException {
		throw new SAXException("Error parsing xml file: " + arg0);
	}

}


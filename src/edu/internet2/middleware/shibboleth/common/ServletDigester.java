package edu.internet2.middleware.shibboleth.common;

import java.io.InputStream;
import java.util.StringTokenizer;

import javax.servlet.ServletContext;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.apache.commons.digester.Digester;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;
import org.xml.sax.XMLReader;

/**
 * This class is a jakarta Digester style parser that will pull schemas from /WEB-INF/schemas, if they 
 * exist.
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class ServletDigester extends Digester {

	private ServletContext context;

	public ServletDigester() {
		super();
		configure();
	}

	public ServletDigester(ServletContext context) {
		super();
		super.setErrorHandler(new PassThruErrorHandler());
		this.context = context;

	}

	public ServletDigester(SAXParser parser) {
		super(parser);
		super.setErrorHandler(new PassThruErrorHandler());
		configure();
	}

	public ServletDigester(XMLReader reader) {
		super(reader);
		super.setErrorHandler(new PassThruErrorHandler());
		configure();
	}

	/**
	 * @see org.xml.sax.EntityResolver#resolveEntity(String, String)
	 */
	public InputSource resolveEntity(String publicId, String systemId) throws SAXException {

		if (context != null && systemId != null) {
			StringTokenizer tokenString = new StringTokenizer(systemId, "/");
			String xsdFile = "";
			while (tokenString.hasMoreTokens()) {
				xsdFile = tokenString.nextToken();
			}
			if (xsdFile.endsWith(".xsd")) {
				InputStream stream = context.getResourceAsStream("/WEB-INF/classes/schemas/" + xsdFile);
				if (stream != null) {
					return new InputSource(stream);
				}
			}
		}
		return null;

	}

	/**
	* Return the SAXParser we will use to parse the input stream.  If there
	* is a problem creating the parser, return <code>null</code>.
	*/
	public SAXParser getParser() {

		// Return the parser we already created (if any)
		if (parser != null) {
			return (parser);
		}

		// Create and return a new parser
		synchronized (this) {
			try {
				if (factory == null) {
					factory = SAXParserFactory.newInstance();
				}
				factory.setNamespaceAware(namespaceAware);
				factory.setValidating(validating);
				if (validating) {
					factory.setFeature("http://xml.org/sax/features/namespaces", true);
					factory.setFeature("http://xml.org/sax/features/validation", true);
					factory.setFeature("http://apache.org/xml/features/validation/schema", true);
					factory.setFeature(
						"http://apache.org/xml/features/validation/schema-full-checking",
						true);
				}
				parser = factory.newSAXParser();
				return (parser);
			} catch (Exception e) {
				return (null);
			}
		}

	}

	/**
	* Sax <code>ErrorHandler</code> that passes all errors up as new 
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
}

package edu.internet2.middleware.shibboleth.hs;

import javax.servlet.ServletContext;
import javax.xml.parsers.SAXParser;

import org.xml.sax.XMLReader;

import edu.internet2.middleware.shibboleth.common.ServletDigester;

/**
 * This class is a jakarta Digester style parser for the HS configuration file.  
 * It should populate the HandleServiceConfig object during HS initilization. NOTE: It is
 * assumed that the mutators of this class will only be called by a single thread during
 * servlet initilization only (NOT thread safe)
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class HsConfigDigester extends ServletDigester {

	protected String hsConfigClass =
		"edu.internet2.middleware.shibboleth.hs.HandleServiceConfig";
	private boolean configured = false;

	public HsConfigDigester() {
		super();
		configure();
	}

	public HsConfigDigester(SAXParser parser) {
		super(parser);
		configure();
	}

	public HsConfigDigester(ServletContext context) {
		super(context);
		configure();
	}

	public HsConfigDigester(XMLReader reader) {
		super(reader);
		configure();
	}

	protected void configure() {

		if (configured == true) {
			return;
		}
		addObjectCreate("HandleServiceConfig", hsConfigClass);
		addSetProperties("HandleServiceConfig");
		addCallMethod("HandleServiceConfig/HelpText", "setHelpText", 0);
		addCallMethod("HandleServiceConfig/SecretKey", "setSecretKey", 0);

		configured = true;

	}

	/**
	 * Gets the wayfDataClass.
	 * @return Returns a String
	 */
	public String getHsConfigClass() {
		return hsConfigClass;
	}

	/**
	 * Sets the wayfDataClass.
	 * @param wayfDataClass The wayfDataClass to set
	 */
	public void setHsConfigClass(String wayfDataClass) {
		this.hsConfigClass = wayfDataClass;
	}

}
package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.ServletContext;
import javax.xml.parsers.SAXParser;

import org.xml.sax.XMLReader;

import edu.internet2.middleware.shibboleth.common.ServletDigester;

/**
 * This class is a jakarta Digester style parser for the WAYF configuration file.  
 * It should populate the WayfConfig object during WAYF initilization. NOTE: It is
 * assumed that the mutators of this class will only be called by a single thread during
 * servlet initilization only (NOT thread safe)
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfConfigDigester extends ServletDigester {

	protected String wayfConfigClass = "edu.internet2.middleware.shibboleth.wayf.WayfConfig";
	private boolean configured = false;

	public WayfConfigDigester() {
		super();
		configure();
	}

	public WayfConfigDigester(SAXParser parser) {
		super(parser);
		configure();
	}

	public WayfConfigDigester(ServletContext context) {
		super(context);
	}

	public WayfConfigDigester(XMLReader reader) {
		super(reader);
		configure();
	}

	/**
	 * @see Digester#configure()
	 */
	protected void configure() {

		if (configured == true) {
			return;
		}
		addObjectCreate("WayfConfig", wayfConfigClass);
		addSetProperties("WayfConfig");
		addCallMethod("WayfConfig/HelpText", "setHelpText", 0);
		addCallMethod("WayfConfig/SearchResultEmptyText", "setSearchResultEmptyText", 0);
		addCallMethod("WayfConfig/SearchIgnore/IgnoreText", "addIgnoredForMatch", 0);

		configured = true;

	}

}
package edu.internet2.middleware.shibboleth.wayf;

import javax.servlet.ServletContext;
import javax.xml.parsers.SAXParser;

import org.xml.sax.XMLReader;

import edu.internet2.middleware.shibboleth.common.ServletDigester;

/**
 * @author Administrator
 *
 * To change this generated comment edit the template variable "typecomment":
 * Window>Preferences>Java>Templates.
 * To enable and disable the creation of type comments go to
 * Window>Preferences>Java>Code Generation.
 */
public class OriginSitesDigester extends ServletDigester {

	protected String originClass = "edu.internet2.middleware.shibboleth.wayf.Origin";
	protected String wayfDataClass = "edu.internet2.middleware.shibboleth.wayf.WayfOrigins";
	protected String originSetClass = "edu.internet2.middleware.shibboleth.wayf.OriginSet";

	private boolean configured = false;

	/**
	 * Constructor for OriginSitesDigester.
	 */
	public OriginSitesDigester() {
		super();
	}

	/**
	 * Constructor for OriginSitesDigester.
	 * @param context
	 */
	public OriginSitesDigester(ServletContext context) {
		super(context);
	}

	/**
	 * Constructor for OriginSitesDigester.
	 * @param parser
	 */
	public OriginSitesDigester(SAXParser parser) {
		super(parser);
	}

	/**
	 * Constructor for OriginSitesDigester.
	 * @param reader
	 */
	public OriginSitesDigester(XMLReader reader) {
		super(reader);
	}

	/**
	* @see Digester#configure()
	*/
	protected void configure() {

		if (configured == true) {
			return;
		}
		//Create data container
		addObjectCreate("Sites", wayfDataClass);

		//Digest sites that are nested in a group
		addObjectCreate("Sites/SiteGroup", originSetClass);
		addSetNext("Sites/SiteGroup", "addOriginSet", originSetClass);
		addCallMethod("Sites/SiteGroup", "setName", 1);
		addCallParam("Sites/SiteGroup", 0, "Name");

		addObjectCreate("Sites/SiteGroup/OriginSite", originClass);
		addSetNext("Sites/SiteGroup/OriginSite", "addOrigin", originClass);
		addCallMethod("Sites/SiteGroup/OriginSite", "setName", 1);
		addCallParam("Sites/SiteGroup/OriginSite", 0, "Name");
		addSetProperties("Sites/SiteGroup/OriginSite");
		addCallMethod("Sites/SiteGroup/OriginSite/Alias", "addAlias", 0);
		addCallMethod("Sites/SiteGroup/OriginSite", "setHandleService", 1);
		addCallParam("Sites/SiteGroup/OriginSite/HandleService", 0, "Location");

		//Digest sites without nesting and add them to the default group
		addObjectCreate("Sites/OriginSite", originSetClass);
		addSetNext("Sites/OriginSite", "addOriginSet", originSetClass);
		addObjectCreate("Sites/OriginSite", originClass);
		addSetNext("Sites/OriginSite", "addOrigin", originClass);
		addCallMethod("Sites/OriginSite", "setName", 1);
		addCallParam("Sites/OriginSite", 0, "Name");
		addSetProperties("Sites/OriginSite");
		addCallMethod("Sites/OriginSite/Alias", "addAlias", 0);
		addCallMethod("Sites/OriginSite", "setHandleService", 1);
		addCallParam("Sites/OriginSite/HandleService", 0, "Location");

		configured = true;

	}

}

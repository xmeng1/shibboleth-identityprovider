package edu.internet2.middleware.shibboleth.wayf;

import javax.xml.parsers.SAXParser;
import org.apache.commons.digester.Digester;
import org.xml.sax.XMLReader;

/**
 * This class is a jakarta Digester style parser for the WAYF configuration file.  
 * It should populate the WayfConfig object during WAYF initilization. NOTE: It is
 * assumed that the mutators of this class will only be called by a single thread during
 * servlet initilization only (NOT thread safe)
 * 
 * @author Walter Hoehn wassa&#064;columbia.edu
 */

public class WayfConfigDigester extends Digester {

	protected String originClass =
		"edu.internet2.middleware.shibboleth.wayf.Origin";
	protected String wayfDataClass =
		"edu.internet2.middleware.shibboleth.wayf.WayfOrigins";
	protected String originSetClass =
		"edu.internet2.middleware.shibboleth.wayf.OriginSet";
	protected String wayfConfigClass =
		"edu.internet2.middleware.shibboleth.wayf.WayfConfig";
	private boolean configured = false;

	public WayfConfigDigester() {
		super();
		configure();
	}

	public WayfConfigDigester(SAXParser parser) {
		super(parser);
		configure();
	}

	public WayfConfigDigester(XMLReader reader) {
		super(reader);
		configure();
	}

	public String getOriginClass() {
		return originClass;
	}

	public void setOriginClass(String originClass) {
		this.originClass = originClass;
	}

	/**
	 * @see Digester#configure()
	 */
	protected void configure() {

		if (configured == true) {
			return;
		}
		addObjectCreate("ShibbolethConfig", wayfConfigClass);
		addSetProperties("ShibbolethConfig/WayfConfig");
		addCallMethod("ShibbolethConfig/WayfConfig/HelpText", "setHelpText", 0);
		addCallMethod(
			"ShibbolethConfig/WayfConfig/SearchResultEmptyText",
			"setSearchResultEmptyText",
			0);
		addCallMethod(
			"ShibbolethConfig/WayfConfig/SearchIgnore/String",
			"addIgnoredForMatch",
			0);

		addObjectCreate("ShibbolethConfig/CommonConfig", wayfDataClass);
		addSetNext(
			"ShibbolethConfig/CommonConfig",
			"setWAYFData",
			wayfDataClass);

		addObjectCreate(
			"ShibbolethConfig/CommonConfig/OriginSet",
			originSetClass);
		addSetNext(
			"ShibbolethConfig/CommonConfig/OriginSet",
			"addOriginSet",
			originSetClass);
		addSetProperties("ShibbolethConfig/CommonConfig/OriginSet");

		addObjectCreate(
			"ShibbolethConfig/CommonConfig/OriginSet/Origin",
			originClass);
		addSetNext(
			"ShibbolethConfig/CommonConfig/OriginSet/Origin",
			"addOrigin",
			originClass);
		addSetProperties("ShibbolethConfig/CommonConfig/OriginSet/Origin");

		addCallMethod(
			"ShibbolethConfig/CommonConfig/OriginSet/Origin/Alias",
			"addAlias",
			1);
		addCallParam(
			"ShibbolethConfig/CommonConfig/OriginSet/Origin/Alias",
			0,
			"name");

		configured = true;

	}

	public String getOriginSetClass() {
		return originSetClass;
	}

	public void setOriginSetClass(String originSetClass) {
		this.originSetClass = originSetClass;
	}

	public String getWayfDataClass() {
		return wayfDataClass;
	}

	public void setWayfDataClass(String wayfDataClass) {
		this.wayfDataClass = wayfDataClass;
	}

}
/*
 * Copyright [2005] [University Corporation for Advanced Internet Development, Inc.]
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.shibboleth.wayf;

import javax.xml.parsers.SAXParser;

import org.xml.sax.XMLReader;

import edu.internet2.middleware.shibboleth.common.ServletDigester;

/**
 * This class is a jakarta Digester style parser for the WAYF configuration file. It should populate the WayfConfig
 * object during WAYF initilization. NOTE: It is assumed that the mutators of this class will only be called by a single
 * thread during servlet initilization only (NOT thread safe)
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

	public WayfConfigDigester(XMLReader reader) {

		super(reader);
		configure();
	}

	/**
	 * @see Digester#configure()
	 */
	protected void configure() {

		if (configured == true) { return; }
		addObjectCreate("WayfConfig", wayfConfigClass);
		addSetProperties("WayfConfig");
		addCallMethod("WayfConfig/HelpText", "setHelpText", 0);
		addCallMethod("WayfConfig/SearchResultEmptyText", "setSearchResultEmptyText", 0);
		addCallMethod("WayfConfig/SearchIgnore/IgnoreText", "addIgnoredForMatch", 0);

		configured = true;

	}

}
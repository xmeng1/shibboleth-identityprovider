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

package edu.internet2.middleware.shibboleth.aa.attrresolv.provider;

import java.security.Principal;

import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import bsh.EvalError;
import bsh.Interpreter;
import bsh.ParseException;
import bsh.TargetError;
import edu.internet2.middleware.shibboleth.aa.attrresolv.AttributeDefinitionPlugIn;
import edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException;
import edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute;

/**
 * <code>AttributeDefinitionPlugIn</code> implementation that determines resolved values by evaluating a section of
 * java code specified in the resolver configuration. The java code be placed inside of a <Scriptlet/> child element.
 * 
 * @author Walter Hoehn
 */

public class ScriptletAttributeDefinition extends BaseAttributeDefinition implements AttributeDefinitionPlugIn {

	private String script;
	private static Logger log = Logger.getLogger(ScriptletAttributeDefinition.class.getName());

	public ScriptletAttributeDefinition(Element e) throws ResolutionPlugInException {

		super(e);

		NodeList scriptlets = e.getElementsByTagName("Scriptlet");

		if (scriptlets.getLength() < 1) {
			log.error("The Scriptlet Attribute Definition requires a <Scriptlet/> element.");
			throw new ResolutionPlugInException("Unable to load Attribute Definition.");
		}
		if (scriptlets.getLength() > 1) {
			log.warn("Scriptlet Attribute Definition contained more than one scriptlet.  Ignoring all but the first.");
		}

		Node tnode = ((Element) scriptlets.item(0)).getFirstChild();
		if (tnode != null && tnode.getNodeType() == Node.TEXT_NODE) {
			script = tnode.getNodeValue();
		}

		// Sanity check
		if (script == null || script.equals("")) {
			log.error("The Scriptlet Attribute Definition requires a <Scriptlet/> element that "
					+ "contains java code.");
			throw new ResolutionPlugInException("Unable to load Attribute Definition.");
		}
		try {
			loadBshInterpreter().eval(script);

			// FUTURE It would be really nice if we could do a better job of checking for errors here
		} catch (ParseException pe) {
			log.error("The code supplied in the <Scriptlet/> element cannot " + "be parsed by the interpreter: "
					+ pe.getMessage());
			throw new ResolutionPlugInException("Unable to load Attribute Definition.");

		} catch (Exception ge) {
			// this is expected... probably a NullPointer. We just want to ensure that the script will parse
		}

	}

	public void resolve(ResolverAttribute attribute, Principal principal, String requester, String responder,
			Dependencies depends) throws ResolutionPlugInException {

		try {

			standardProcessing(attribute);

			Interpreter beanShellInterpreter = loadBshInterpreter();

			// Export accessible variables to the scriptlet
			beanShellInterpreter.set("resolverAttribute", attribute);
			beanShellInterpreter.set("principal", principal);
			beanShellInterpreter.set("requester", requester);
			beanShellInterpreter.set("responder", responder);
			beanShellInterpreter.set("dependencies", depends);
			beanShellInterpreter.set("log", log);

			// Run the scriptlet
			beanShellInterpreter.eval(script);

			attribute.setResolved();

		} catch (EvalError e) {
			if (e instanceof TargetError) {
				if (((TargetError) e).getTarget() instanceof ResolutionPlugInException) { throw (ResolutionPlugInException) ((TargetError) e)
						.getTarget(); }
			}
			log.error("Encountered an error while evaluating the Attribute Definition scriptlet: " + e.getMessage());
			throw new ResolutionPlugInException("Unable to determine attribute's values.");
		}
	}

	private Interpreter loadBshInterpreter() {

		Interpreter beanShellInterpreter = new Interpreter();

		// Be friendy and import classes that will be needed in the scriptlet
		beanShellInterpreter.getNameSpace().importClass(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.ResolverAttribute");
		beanShellInterpreter.getNameSpace().importClass(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.Dependencies");
		beanShellInterpreter.getNameSpace().importClass("org.apache.log4j.Logger");
		beanShellInterpreter.getNameSpace().importClass(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.ResolutionPlugInException");
		beanShellInterpreter.getNameSpace().importClass("javax.naming.directory.Attributes");
		beanShellInterpreter.getNameSpace().importClass("javax.naming.directory.Attribute");
		beanShellInterpreter.getNameSpace().importClass(
				"edu.memphis.idmanagement.provisioning.ProvisioningEngineException");

		// Import any pre-defined scriptlet commands
		beanShellInterpreter.getNameSpace().importCommands(
				"edu.internet2.middleware.shibboleth.aa.attrresolv.provider.scriptlet");

		return beanShellInterpreter;
	}

}

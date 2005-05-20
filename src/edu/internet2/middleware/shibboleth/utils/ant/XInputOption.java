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

package edu.internet2.middleware.shibboleth.utils.ant;

import java.util.Iterator;
import java.util.Vector;

import org.apache.tools.ant.ProjectComponent;
import org.apache.tools.ant.util.StringUtils;

/**
 * @author Will Norris (wnorris@memphis.edu)
 */
public class XInputOption extends ProjectComponent {

	private Boolean caseSensitive = null;
	private String value = "";
	private Vector validArgs = null;
	private String displayName = null;
	private boolean isDefault = false;

	public XInputOption() {

		super();
	}

	public XInputOption(String value, String validargs, String displayName) {

		setValue(value);
		setValidArgs(validargs);
		addText(displayName);
	}

	public void setCasesensitive(boolean b) {

		setCaseSensitive(new Boolean(b));
	}

	public void setCaseSensitive(Boolean b) {

		this.caseSensitive = b;
	}

	public Boolean getCaseSensitive() {

		return this.caseSensitive;
	}

	public void setValue(String value) {

		this.value = value;
	}

	public String getValue() {

		if (value == null || value.equals("")) { return displayName(); }

		return this.value;
	}

	public void setValidArgs(String validargs) {

		this.validArgs = StringUtils.split(validargs, ',');
	}

	public Vector getValidArgs() {

		if (validArgs != null) {
			return this.validArgs;
		} else {
			Vector v = new Vector();
			v.add(getValue());
			return v;
		}
	}

	public void addText(String text) {

		this.displayName = text;
	}

	public String displayName() {

		return displayName;
	}

	public void setIsDefault(boolean b) {

		this.isDefault = b;
	}

	public boolean isDefault() {

		return this.isDefault;
	}

	public boolean acceptsInput(String input) {

		if (input.equals("") && isDefault()) { return true; }

		Iterator i = getValidArgs().iterator();
		while (i.hasNext()) {
			String arg = (String) i.next();
			if (getCaseSensitive().booleanValue()) {
				if (arg.equals(input)) { return true; }
			} else {
				if (arg.equalsIgnoreCase(input)) { return true; }
			}
		}
		return false;
	}
}

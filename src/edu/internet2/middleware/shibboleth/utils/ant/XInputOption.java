/*
 * The Shibboleth License, Version 1. Copyright (c) 2002 University Corporation for Advanced Internet Development, Inc.
 * All rights reserved Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met: Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials
 * provided with the distribution, if any, must include the following acknowledgment: "This product includes software
 * developed by the University Corporation for Advanced Internet Development <http://www.ucaid.edu>Internet2 Project.
 * Alternately, this acknowledegement may appear in the software itself, if and wherever such third-party
 * acknowledgments normally appear. Neither the name of Shibboleth nor the names of its contributors, nor Internet2, nor
 * the University Corporation for Advanced Internet Development, Inc., nor UCAID may be used to endorse or promote
 * products derived from this software without specific prior written permission. For written permission, please contact
 * shibboleth@shibboleth.org Products derived from this software may not be called Shibboleth, Internet2, UCAID, or the
 * University Corporation for Advanced Internet Development, nor may Shibboleth appear in their name, without prior
 * written permission of the University Corporation for Advanced Internet Development. THIS SOFTWARE IS PROVIDED BY THE
 * COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND WITH ALL FAULTS. ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT ARE
 * DISCLAIMED AND THE ENTIRE RISK OF SATISFACTORY QUALITY, PERFORMANCE, ACCURACY, AND EFFORT IS WITH LICENSEE. IN NO
 * EVENT SHALL THE COPYRIGHT OWNER, CONTRIBUTORS OR THE UNIVERSITY CORPORATION FOR ADVANCED INTERNET DEVELOPMENT, INC.
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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

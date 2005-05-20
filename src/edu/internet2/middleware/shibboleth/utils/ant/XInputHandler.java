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

import org.apache.tools.ant.input.DefaultInputHandler;
import org.apache.tools.ant.input.InputRequest;

/**
 * Extended version of <code>org.apache.tools.ant.input.DefaultInputHandler</code>.
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class XInputHandler extends DefaultInputHandler {

	public XInputHandler() {

		super();

	}

	protected String getPrompt(InputRequest request) {

		String prompt = request.getPrompt();
		if (request instanceof XMultipleChoiceInputRequest) {
			StringBuffer sb = new StringBuffer("\n" + prompt);
			sb.append(" [");
			Iterator i = ((XMultipleChoiceInputRequest) request).getOptions().iterator();
			boolean first = true;
			while (i.hasNext()) {
				if (!first) {
					sb.append(",");
				}
				XInputOption o = (XInputOption) i.next();
				sb.append(o.isDefault() ? o.displayName().toUpperCase() : o.displayName());
				first = false;
			}
			sb.append("]");
			prompt = sb.toString();
		}
		return prompt;
	}

}

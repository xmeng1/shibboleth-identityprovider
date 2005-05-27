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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

/**
 * @author Walter Hoehn
 */
public class URLConvert extends Task {

	private String addProperty;
	private String path;

	public void execute() throws BuildException {

		if (addProperty != null && getProject().getProperty(addProperty) != null) {
			log("Skipping " + getTaskName() + " as property " + addProperty + " has already been set.");
			return;
		}

		if (path == null) {
			log("Skipping " + getTaskName() + " because path was not specified.");
			return;
		}

		File file = new File(path);
		try {
			URL url = file.getAbsoluteFile().toURI().toURL();

			if (addProperty != null && url != null) {
				getProject().setNewProperty(addProperty, url.toString());
			}
		} catch (MalformedURLException e) {
			log("Skipping " + getTaskName() + " because path (" + path + ") could not be converted to a URL.");
			return;
		}

	}

	public void setAddProperty(String addproperty) {

		this.addProperty = addproperty;
	}

	public void setPath(String path) {

		this.path = path;
	}

}

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

package edu.internet2.middleware.shibboleth.utils;

import java.io.File;
import java.io.IOException;

/**
 * File manipulation utilities, extended from Jakarta's commons-io
 * 
 * @author Will Norris (wnorris@memphis.edu)
 */
public class FileUtils extends org.apache.commons.io.FileUtils {

	/**
	 * Replace all instances of <i>token</i> with <i>value</i> in the given
	 * File
	 * 
	 * @param file
	 * @param token
	 *            regular expression to match and replace
	 * @param value
	 *            string to replace token with
	 * @throws IOException
	 */
	public static void replaceString(File file, String token, String value)
			throws IOException {
		String contents = FileUtils.readFileToString(file, "utf-8");
		contents = contents.replaceAll(token, value);
		FileUtils.writeStringToFile(file, contents, "utf-8");
	}

}
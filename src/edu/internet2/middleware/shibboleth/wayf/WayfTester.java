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

import java.io.IOException;
import java.net.URLEncoder;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This class is simply redirects to hardcoded URL for the WAYF. Created for testing during development. Should probably
 * delete later and replace with a proper testing environment.
 */

public class WayfTester extends HttpServlet {

	private String acceptanceURL = "http://localhost/wayf/SHIRE";
	private String targetURL = "http://localhost/wayf/success.html";

	public void doGet(HttpServletRequest req, HttpServletResponse res) {

		try {
			res.sendRedirect("WAYF" + "?target=" + URLEncoder.encode(targetURL, "UTF-8") + "&shire="
					+ URLEncoder.encode(acceptanceURL, "UTF-8"));
		} catch (IOException ioe) {
			System.out.println("WAYF Tester Error");
		}

	}

}

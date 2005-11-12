<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" 
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>

<%@ taglib uri="/WEB-INF/tlds/struts-logic.tld" prefix="logic" %>
<%@ taglib uri="/WEB-INF/tlds/struts-bean.tld" prefix="bean" %>

<logic:present name="showComments" scope="Request">

<!-- TO CONFIGURE THIS FOR A SPECIFIC SITE
     =====================================

     Before you deploy this jsp you need to look for CONFIG below.
     These mark places where you should make changes. 

     If you want to make more profound changes but only to the jsp,
     you should read the sections marked PROGRAMMING NOTE below.-->

<!-- PROGRAMMING NOTE

     "requestURL" contains the URL that was specified to get the
     WAYF going.  The jsp uses it mostly for submitting result back to
     the WAYF and error reporting -->

</logic:present>

    <jsp:useBean id="requestURL" scope="request" class="java.lang.String"/>

<logic:present name="showComments" scope="Request">

<!-- PROGRAMMING NOTE

     shire, target, provider and time are all part of the Shibboleth
     protocol and need to be specified as parameters to the WAYF. -->

</logic:present>


    <jsp:useBean id="shire" scope="request" class="java.lang.String"/>
    <jsp:useBean id="target" scope="request" class="java.lang.String"/>
    <jsp:useBean id="providerId" scope="request" class="java.lang.String"/>
    <jsp:useBean id="time" scope="request" class="java.lang.String"/>

<logic:present name="showComments" scope="Request">
<!-- PROGRAMMING NOTE

     In addition to the above.  The WAYF also supplies the following to
     the jsp.

     "cookieList" If this exists it represents the contents of the
         _saml_idp cookie (possibly filtered to remove IdPs which
         cannot serve the SP).  It is a Collection of IdPSite objects,
         which themselves have the following properties:

       "name" The uri for the IdP, which needs to be returned to the
              WAYF in the "origin" parameter.

       "displayName" User friendly name (taken from its alias)

       "addressFor" The (ungarnished) URL for the IdP. This could be
              used to create a direct hyperlink to the IdP

     "sites" If this exists it contains all the possible IdPs for for
         the SP (possibly filtered).  It is a Collection of IdPSite
         Objects which are described above.  This is only present if
         provideList was defined true in the configuration.

     "siteLists" If this exists it contains all the possible metadata
         files which can service for the SP (possibly filtered).  It
         is a collection of IdPSiteSetEntry Objects which have two
         properties:

         "name" This is the displayName from the Metadata element in
            the WAYF configuration file

         "sites" This represents the IdPs.  Again it is a collection
            of IdPSite Objects

         It is only present if provideListOfList was defined true in
         the configuration.

     "singleSiteList" if this is present, then there is only one
         IdPSiteSetEntry Object in "siteLists".

     "searchresultempty" If this is present then it means that a
         search was performed, but no suitable IdPs were returned.

     "searchresults" If this is present it represents the list of IdPs
         which matched a previous search.  It is a Collection of
         IdPSite Objects. -->

<!-- PROGRAMMING NOTE

     The jsp communicates back to the WAYF via the parameters listed
     above, and:

        "action" what the WAYF has to do.  Possible contents are:

            "lookup" - refresh the screen.
            "search" - perform a search on the contents parameter "string"
            "selection" - redirect to the IdP with the uri "origin"

        "cache" preserve any selection in the _saml_idp cookie. A
            value of "session" makes the cookie last for the browser
            session, "perm" gives it the lifetime specified in the
            configuration file.  -->

</logic:present>

<head>
    <link rel="stylesheet" title="normal" type="text/css"
    href="wayf.css" /> <title>Identity Provider Selection</title>
    </head>

<body>
    <div class="head">
        <h1>

Select an identity provider

        </h1>
    </div>

    <div class="selector">
    <p class="text">

<!--CONFIG-->

The Service you are trying to reach requires that you
authenticate with your home institution, please select it from the
list below.

    </p>
    <logic:present name="cookieList" scope="request">

        <h2>

Recently used institutions:

        </h2>   

<logic:present name="showComments" scope="Request">

<!-- PROGRAMMING NOTE
 
     Generate a hyperlink back to the WAYF.  Note that we are
     simulating the user having specified a permanent cookie -->

</logic:present>

        <logic:iterate id="site" name="cookieList">
            <p  class="text">
                <a href="<bean:write name="requestURL" />?target=<bean:write name="target" />&shire=<bean:write name="shire" />&providerId=<bean:write name="providerId" />&time=value=<bean:write name="time" />&cache=perm&action=selection&origin=<jsp:getProperty name="site" property="name" />">
                    <jsp:getProperty name="site"
                    property="displayName" />
                </a>
            </p>
        </logic:iterate>

<logic:present name="showComments" scope="Request">

<!-- PROGRAMMING NOTE

     We defined the ClearCache.Wayf service in wayfconfig.  So we know
     it is here.  This will empty the cookie and loop -->

</logic:present>

        <form method="get" action="ClearCache.wayf" />
            <input type="hidden" name="shire" value="<bean:write name="shire" />" />
            <input type="hidden" name="target" value="<bean:write name="target" />" />
            <logic:present name="providerId" scope="request">
               <input type="hidden" name="providerId" value="<bean:write name="providerId" />" />
            </logic:present>
            <logic:present name="time" scope="request">
                <input type="hidden" name="time" value="<bean:write name="time" />" />
            </logic:present>
            <input type="submit" value="Clear" />
        </form>

    </logic:present>

    <div class="list">

        <h2>

Choose from a list:

        </h2>

        <logic:present name="sites" scope="request">
        <logic:notPresent name="siteLists" scope="request">

            <form method="get" action="<bean:write name="requestURL" />">
                    <input type="hidden" name="shire" value="<bean:write name="shire" />" />
                    <input type="hidden" name="target" value="<bean:write name="target" />" />
                    <logic:present name="providerId" scope="request">
                        <input type="hidden" name="providerId" value="<bean:write name="providerId" />" />
                    </logic:present>
                    <logic:present name="time" scope="request">
                        <input type="hidden" name="time" value="<bean:write name="time" />" />
                    </logic:present>
                    <input type="hidden" name="action" value="selection" />
                    <select name="origin">      
                        <logic:iterate id="site" name="sites">
                            <option value="<jsp:getProperty name="site" property="name" />">
                                <jsp:getProperty name="site" property="displayName" />
                            </option>
                        </logic:iterate>
                    </select>
                    <input type="submit" value="Select" />
                    <select name="cache">
                        <option value="false"> Do not remember
                        <option value="session" selected> Remember for session
                        <option value="perm"> Remember for a week
                    </select>
            </form>
        </logic:notPresent>
        </logic:present>

<logic:present name="showComments" scope="Request">

<!-- PROGRAMMING NOTE
     Build two tables side by side, one with the Federation names and 'ALL' (if apposite)
     and the other will be dynamically populated with the members of that federation.

     This needs to work in the face of no javascript, so we initially populate the 
     Right hand list with all the IdPs.  The first Selection in the Left hand Table will
     shrink this list

     The 'lists of all IdPs' is derived from the one which java gives us (if it did)
     otherwise it is derived by a double iteration through the List of Lists.  This
     makes for complicated looking code, but it's dead simple really.

 -->

</logic:present>

        <logic:present name="siteLists" scope="request">
          <form method="get" action="<bean:write name="requestURL" />">
            <input type="hidden" name="shire" value="<bean:write name="shire" />" />
            <input type="hidden" name="target" value="<bean:write name="target" />" />

            <logic:present name="providerId" scope="request">
              <input type="hidden" name="providerId" value="<bean:write name="providerId" />" />
            </logic:present>

            <logic:present name="time" scope="request">
              <input type="hidden" name="time" value="<bean:write name="time" />" />
            </logic:present>

            <table name="tab">
               <th>Federation </th>
               <th>Institution</th>
               <tr>
                 <td><select name="FedSelector" size="10" id="FedSelect" 
                             onChange="changedFed(this.form.origin,
                                                  this.form.FedSelector[this.form.FedSelector.selectedIndex].value);">
                   <logic:iterate id="siteset" name="siteLists">
                     <logic:present name="singleSiteList" scope="request">

                       <!-- Only One site so select it -->

                       <option value="<jsp:getProperty name="siteset" property="name"/>" SELECTED>
                         <jsp:getProperty name="siteset" property="name"/>
                       </option>
                     </logic:present>
                     <logic:notPresent name="singleSiteList" scope="request">
                       <option value="<jsp:getProperty name="siteset" property="name"/>">
                         <jsp:getProperty name="siteset" property="name"/>
                       </option>
                     </logic:notPresent>
                   </logic:iterate>

                   <logic:notPresent name="singleSiteList" scope="request">

                     <!-- More than one site so select the 'All' -->

                     <option value="ALL" selected>
                         All Sites
                     </option>
                   </logic:notPresent>
                </select></td>

                 <td>
                   <input type="hidden" name="action" value="selection" />
                   <select name="origin" size="10" id="originIdp"> 
                     <logic:present name="sites" scope="request">
                       <logic:iterate id="site" name="sites">
                         <option value="<jsp:getProperty name="site" property="name" />">
                           <jsp:getProperty name="site" property="displayName" />
                         </option>
                       </logic:iterate>
                     </logic:present>

                     <logic:notPresent name="sites" scope="request">
                       <logic:iterate id="siteset" name="siteLists">
                         <logic:iterate id="site" name="siteset" property="sites">
                           <option value="<jsp:getProperty name="site" property="name" />">
                             <jsp:getProperty name="site" property="displayName" />
                           </option>
                         </logic:iterate>
                       </logic:iterate>        
                     </logic:notPresent>
                   </select>
                   
                 </td>
               </tr>
             </table>
             <p>
               <input type="submit" value="Select" />
               <select name="cache">
                 <option value="false"> Do not remember
                 <option value="session" selected> Remember for session
                 <option value="perm"> Remember for a week
               </select>
             </p>
           </form>
        </logic:present>
        </div>
        <div class="search">
            <span class="option">or</span>

            <h2>

Search by keyword:

            </h2>

            <form method="get" action="<bean:write name="requestURL" />">
                <p>
                    <input type="hidden" name="shire" value="<bean:write name="shire" />" />
                    <input type="hidden" name="target" value="<bean:write name="target" />" />
                    <logic:present name="providerId" scope="request">
                        <input type="hidden" name="providerId" value="<bean:write name="providerId" />" />
                    </logic:present>
                    <logic:present name="time" scope="request">
                        <input type="hidden" name="time" value="<bean:write name="time" />" />
                    </logic:present>
                    <input type="hidden" name="action" value="search" />
                    <input type="text" name="string" />
                    <input type="submit" value="Search" />
                </p>
            </form>

            <logic:present name="searchResultsEmpty" scope="request">
                <p class="error">

No provider was found that matches your search criteria, please try again.

                </p>
            </logic:present>

            <logic:present name="searchresults" scope="request">
                <h3>

Search results:

                </h3>
                <form method="get" action="<bean:write name="requestURL" />">
                    <ul>
                        <logic:iterate id="currResult" name="searchresults">
                            <li>
                                <input type="radio" name="origin" value="<jsp:getProperty name="currResult" property="name" />" />
                                <jsp:getProperty name="currResult" property="displayName" />
                            </li>
                        </logic:iterate>
                    </ul>
                    <p>
                        <input type="hidden" name="shire" value="<bean:write name="shire" />" />
                        <input type="hidden" name="target" value="<bean:write name="target" />" />
                        <logic:present name="providerId" scope="request">
                            <input type="hidden" name="providerId" value="<bean:write name="providerId" />" />
                        </logic:present>
                        <logic:present name="time" scope="request">
                            <input type="hidden" name="time" value="<bean:write name="time" />" />
                        </logic:present>
                        <input type="hidden" name="action" value="selection" />
                        <input type="submit" value="Select" />
                        <select name="cache">
                            <option value="false"> Do not remember
                            <option value="session" selected> Remember for session
                            <option value="perm"> Remember for a week
                        </select>
                    </p>
                </form>     
            </logic:present>
        </div>
    </div>

    <div class="footer">
        <p class="text">
<!--CONFIG-->
Need assistance? Send mail to <a href="mailto:user@domain"> administrator's name</a> with description.
        </p>
        <div class="logo"><img src="images/internet2.gif" alt="InQueue" /></div>
    </div>

<logic:present name="showComments" scope="Request">

<!--PROGRAMMING NOTE
  
  We need to program the on changed selector.  Note that option.InnterText only
  works on IE, options.remove doesn't work on Firefox, and that
  options.add doesn't work on Safari.  Hence the somewhat strange manipulations
  to delete & populate the list of options.

  X        is the select object for the right hand table
  Selected is the name selected in the left hand table

-->

</logic:present>

<logic:present name="siteLists" scope="request">
<script language="javascript" type="text/javascript">
<!--

function changedFed(X, Selected) {

  <logic:notPresent name="singleSiteList" scope="request">

     while (X.length > 0) {
        X.options[(X.length-1)] = null;
     }
  
  
    <logic:iterate id="siteset" name="siteLists">
      if (Selected == "<jsp:getProperty name="siteset" property="name"/>") {
        var opt;
        <logic:iterate id="site" name="siteset" property="sites">
          opt = new Option ("<jsp:getProperty name="site" property="displayName" />");
          X.options[X.length] = opt;
          opt.value = "<jsp:getProperty name="site" property="name" />";
        </logic:iterate>
      }
    </logic:iterate>
  
      if (Selected == "ALL") {
        var opt;
  
      <logic:present name="sites" scope="request">
          <logic:iterate id="site" name="sites">
            opt = new Option("<jsp:getProperty name="site" property="displayName" />");
            X.options[X.length] = opt;
            opt.value = "<jsp:getProperty name="site" property="name" />";
          </logic:iterate>
      </logic:present>
  
      <logic:notPresent name="sites" scope="request">
          <logic:iterate id="siteset" name="siteLists">
            <logic:iterate id="site" name="siteset" property="sites">
              opt = new Option ("<jsp:getProperty name="site" property="displayName" />");
              X.options[X.length] = opt;
              opt.value = "<jsp:getProperty name="site" property="name" />";
            </logic:iterate>
          </logic:iterate>
      </logic:notPresent>
    }
  
  </logic:notPresent>
   
  
}
-->
</script>
</logic:present>
 
  
</body>
</html>
  
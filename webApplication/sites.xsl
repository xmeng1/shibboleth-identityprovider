<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:shib="urn:mace:shibboleth:1.0" version="1.0">

<!-- set the output properties -->
<xsl:output method="html"/>

<!-- main rule for outer element -->
<xsl:template match="shib:Sites">
<HTML>
  <HEAD>
    <LINK REL="stylesheet" TYPE="text/css" HREF="main.css"/>
    <TITLE>Shibboleth Site Registry</TITLE>
  </HEAD>
  <BODY BGCOLOR="white">
  <DIV CLASS="head">
  <H1><IMG SRC="images/internet2.gif" ALT="Logo" ALIGN="middle"/>Shibboleth Site Registry</H1>
  </DIV>
  <xsl:for-each select="shib:OriginSite">
    <xsl:sort select="@Name"/>
    <P>
    <B>Origin Site</B>:
    <xsl:value-of select="@Name"/>
    <BLOCKQUOTE>
      <U>Alias(es)</U>
      <xsl:for-each select="shib:Alias">
        <BR/><xsl:value-of select="."/>
      </xsl:for-each>
    </BLOCKQUOTE>
    <BLOCKQUOTE>
      <U>Handle Service(s):</U>
      <xsl:for-each select="shib:HandleService">
        <BR/><xsl:value-of select="@Name"/>
        <xsl:text> - </xsl:text>
        <I><xsl:value-of select="@Location"/></I>
      </xsl:for-each>
    </BLOCKQUOTE>
    </P>
  </xsl:for-each>
  </BODY>
</HTML>
</xsl:template>

</xsl:stylesheet>


<?xml version="1.0" encoding="utf-8"?>
<!-- =========================================================================
 This file is part of ADVNessusAnalyzer
 Copyright (c) 2011 ADVtools SARL - www.advtools.com
 Written by Flora Bottaccio

 Version 1.0

 Analyze Nessus Scan Results
 Provide vulnerabilities reference list
============================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" exclude-result-prefixes="msxsl">
  <xsl:output method="xml" version="1.0" indent="yes"/>

  <!-- Vulnerabilities reference list -->
  <xsl:param name="vulnerabilities" select="'Vulnerabilities.xml'"/>
  <xsl:variable name="Vulnerabilities" select="document($vulnerabilities)/NessusVulnerabilities"/>

  <!-- Excluded plugins -->
  <xsl:param name="excludedPlugins" select="'Parameters.xml'"/>
  <xsl:variable name="ExcludedPlugins" select="document($excludedPlugins)/Parameters/PluginsExcluded/PluginsIds"/>

  <xsl:template match="*|/">
    <xsl:apply-templates/>
  </xsl:template>

  <xsl:template match="/NessusClientData_v2">
    <xsl:element name="NessusVulnerabilities">
      <xsl:element name="Vulnerabilities">
        <!-- Get all documented plugins -->
        <xsl:copy-of select="$Vulnerabilities/Vulnerabilities/Vulnerability"/>
        <!-- Add no documented plugins -->
        <xsl:apply-templates/>
      </xsl:element>
    </xsl:element>
  </xsl:template>

  <xsl:template match="/NessusClientData_v2/Report/ReportHost/ReportItem">

    <xsl:if test="not(@pluginID=preceding-sibling::ReportItem/@pluginID) and not(@pluginID=../preceding-sibling::ReportHost/ReportItem/@pluginID)">
      
      <!-- Documented Vulnerabilites -->
      <xsl:variable name="Vulnerability" select="$Vulnerabilities/Vulnerabilities/Vulnerability[PluginsIds/PluginId=current()/@pluginID]"/>
      <!-- Excluded plugins -->
      <xsl:variable name="ExcludedPlugin" select="$ExcludedPlugins[PluginId=current()/@pluginID]"/>

      <!-- If the vulnerability is not existing and is not excluded -->
      <xsl:if test="not($Vulnerability) and not($ExcludedPlugin)">
        <xsl:element name="Vulnerability">
          <!-- Default description is pluginName -->
          <xsl:attribute name="desc">
            <xsl:value-of select="@pluginName"/>
          </xsl:attribute>
          <!-- documented value enabled to quickly identify non documentd plugins -->
          <xsl:attribute name="documented">false</xsl:attribute>
          <xsl:element name="PluginsIds">
            <xsl:element name="PluginId">
              <xsl:value-of select="@pluginID"/>
            </xsl:element>
          </xsl:element>
          <!-- Default levels are nessus plugins severity -->
          <xsl:element name="Levels">
            <xsl:element name="Level">
              <xsl:attribute name="system-type">Server</xsl:attribute>
              <xsl:value-of select="@severity"/>
            </xsl:element>
            <xsl:element name="Level">
              <xsl:attribute name="system-type">Station</xsl:attribute>
              <xsl:value-of select="@severity"/>
            </xsl:element>
            <xsl:element name="Level">
              <xsl:attribute name="system-type">Router</xsl:attribute>
              <xsl:value-of select="@severity"/>
            </xsl:element>
            <xsl:element name="Level">
              <xsl:attribute name="system-type">Printer</xsl:attribute>
              <xsl:value-of select="@severity"/>
            </xsl:element>
          </xsl:element>
        </xsl:element>
      </xsl:if>

    </xsl:if>

  </xsl:template>

  <xsl:template match="text()|@*"/>

</xsl:stylesheet>

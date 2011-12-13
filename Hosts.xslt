<?xml version="1.0" encoding="utf-8"?>
<!-- =========================================================================
 This file is part of ADVNessusAnalyzer
 Copyright (c) 2011 ADVtools SARL - www.advtools.com
 Written by Flora Bottaccio

 Version 1.0
 
 Analyze Nessus Scan Results
 Provide hosts list
============================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft-com:xslt" exclude-result-prefixes="msxsl">
  <xsl:output method="xml" version="1.0" indent="yes"/>

  <!-- Vulnerabilities reference list -->
  <xsl:param name="vulnerabilities" select="'Vulnerabilities.xml'"/>
  <xsl:variable name="Vulnerabilities" select="document($vulnerabilities)/NessusVulnerabilities"/>
  
  <!-- Vulnerable ports -->
  <xsl:param name="ports" select="'Ports.xml'"/>
  <xsl:variable name="Ports" select="document($ports)/Ports"/>
  
  <xsl:template match="/">
    <xsl:variable name="Smallcase" select="'abcdefghijklmnopqrstuvwxyz'" />
    <xsl:variable name="Uppercase" select="'ABCDEFGHIJKLMNOPQRSTUVWXYZ'" />

    <xsl:element name="hosts">
      <!-- For each host scanned... -->
      <xsl:for-each select="NessusClientData_v2/Report/ReportHost">
        <xsl:sort select="substring-after(substring-after(substring-after(@name,'.'),'.'),'.')" data-type="number"/>
        
        <!-- Retrieve vulnerabilities for the host -->
        <xsl:variable name="Vulnerability" select="ReportItem[@pluginID=$Vulnerabilities/Vulnerabilities/Vulnerability/PluginsIds/PluginId]"/>

        <!-- Retrieve vulnerable ports for the host -->
        <xsl:variable name="VulnerablePort" select="ReportItem[@port=$Ports/Port/@portID]"/>
        
        <!-- The host has at least one vulnerability or an opened vulnerable port -->
        <xsl:if test="$Vulnerability or $VulnerablePort">
          <xsl:element name="host">
            <xsl:attribute name="ip">
              <!-- Host IP -->
              <xsl:value-of select="@name"/>
            </xsl:attribute>
            <xsl:attribute name="fqdn">
              <!-- Host domain name -->
              <xsl:value-of select="HostProperties/tag[@name='host-fqdn']"/>
            </xsl:attribute>
            <xsl:attribute name="netbios-name">
              <!-- Host name -->
              <xsl:value-of select="HostProperties/tag[@name='netbios-name']"/>
            </xsl:attribute>
            <xsl:attribute name="system-type">
              <!-- Host system type, it will be used to select the level of vulnerability -->
              <xsl:choose>
                <xsl:when test="HostProperties/tag[@name='system-type']='router'">Router</xsl:when>
                <xsl:when test="HostProperties/tag[@name='system-type']='switch'">Router</xsl:when>
                <xsl:when test="HostProperties/tag[@name='system-type']='hypervisor'">Server</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'server')">Server</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'catalystos')">Server</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'linux')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows xp')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows 7')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows vista')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows 2000')">Server</xsl:when>
                <xsl:otherwise>Station</xsl:otherwise>
              </xsl:choose>
            </xsl:attribute>
            <xsl:attribute name="system-name">
              <!-- Host system name -->
              <xsl:choose>
                <xsl:when test="HostProperties/tag[@name='system-type']='router'">
                  <xsl:choose>
                    <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'cisco')">Cisco Device</xsl:when>
                    <xsl:otherwise>Router</xsl:otherwise>
                  </xsl:choose>
                </xsl:when>
                <xsl:when test="HostProperties/tag[@name='system-type']='switch'">
                  <xsl:choose>
                    <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'cisco')">Cisco Switch</xsl:when>
                    <xsl:otherwise>Switch</xsl:otherwise>
                  </xsl:choose>
                </xsl:when>
                <xsl:when test="HostProperties/tag[@name='system-type']='hypervisor'">Virtual machine</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'server')">Server</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'catalystos')">ILO</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'linux')">Linux</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows xp')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows 7')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows vista')">Station</xsl:when>
                <xsl:when test="contains(translate(HostProperties/tag[@name='operating-system'], $Uppercase, $Smallcase),'windows 2000')">Server</xsl:when>
                <xsl:otherwise>
                  <xsl:value-of select="HostProperties/tag[@name='operating-system']"/>
                </xsl:otherwise>
              </xsl:choose>
            </xsl:attribute>
          </xsl:element>
        </xsl:if>
      </xsl:for-each>
    </xsl:element>
  </xsl:template>
</xsl:stylesheet>

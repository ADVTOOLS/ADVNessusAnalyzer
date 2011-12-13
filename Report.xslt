<?xml version="1.0" encoding="utf-8"?>
<!-- =========================================================================
 This file is part of ADVNessusAnalyzer
 Copyright (c) 2011 ADVtools SARL - www.advtools.com
 Written by Flora Bottaccio
 
 Version 1.0
 
 Analyze Nessus Scan Results
 Provide vulnerabilities list for each host
============================================================================== -->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:common="http://exslt.org/common" exclude-result-prefixes="common">
  <xsl:output method="html" encoding="UTF-8" indent="yes"/>

  <!-- Vulnerabilities reference list -->
  <xsl:param name="vulnerabilities" select="'Vulnerabilities.xml'"/>
  <xsl:variable name="Vulnerabilities" select="document($vulnerabilities)/NessusVulnerabilities"/>
  
  <!-- Vulnerable ports -->
  <xsl:param name="ports" select="'Ports.xml'"/>
  <xsl:variable name="Ports" select="document($ports)/Ports"/>

  <!-- Hosts reference list -->
  <xsl:param name="hosts" select="'Hosts.xml'"/>
  <xsl:variable name="Hosts" select="document($hosts)/hosts"/>
  
  <!-- Nessus vulnerabilities -->
  <xsl:variable name="Nessus" select="/NessusClientData_v2"/>

  <!-- Line feeds -->
  <xsl:variable name="new_line" select="'&#xa;'"/>
  
  <xsl:template match="/">
    <html>
      <head>
        <title>
          Hosts vulnerabilities <xsl:value-of select="Policy/Preferences/ServerPreferences/preference[name='TARGET']/value"/>
        </title>
        <style type="text/css">
          body { margin: 0px; background-color: #FFFFFF; color: #000000; font-family: Century Gothic, Verdana, Helvetica, sans-serif; text-align: center; }
          table { color: #000000; background-color: #000000; border-collapse: collapse; border-spacing: 0px; border: 1px solid black; }
          thead { display: table-header-group; }
          tr { font-size: 9pt; background-color: #FFFFFF; border: 1px solid black; }
          tr.head { font-weight: bold; }
          td { border: 1px solid black; text-align: left; font-family: Century Gothic; font-size: 9pt; padding-left:8px; padding-right:8px; padding-top:6px; padding-bottom:6px;}
          td.ip { width:106px }
          td.host { width:145px }
          td.kind { width:112px }
          td.critical { background-color: #7030A0; color: #FFFFFF; font-weight: bold; width:65px; }
          td.high { background-color: #FF0000; color: #FFFFFF; font-weight: bold; width:65px; }
          td.medium { background-color: #FFC000; font-weight: bold; width:65px; }
          td.low { background-color: #FFFF00; width:65px; }
          td.problems { width:214px }
          p { font-size: 9pt; text-align: left; margin:4px 0px 0px 10px; }
        </style>
      </head>
      <body>
        <table>
          <tr class="head">
            <td title="IP">IP</td>
            <td title="Host name">Name</td>
            <td title="Host kind">Kind</td>
            <td title="Vulnerability level">Level</td>
            <td title="Vulnerabilities">Security problems</td>
          </tr>
          <xsl:for-each select="$Hosts/host">
            <xsl:variable name="ip" select="@ip"/>
            <xsl:variable name="system-type" select="@system-type"/>
            <xsl:variable name="system-name" select="@system-name"/>
            <tr>
              <td class="ip">
                <!-- Host IP -->
                <xsl:value-of select="$ip"/>
              </td>
              <td class="host">
                <!-- Host name -->
                <xsl:choose>
                  <xsl:when test="@netbios-name=''">
                    <xsl:value-of select="@fqdn"/>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="@netbios-name"/>
                  </xsl:otherwise>
                </xsl:choose>
              </td>
              <td class="kind">
                <!-- Host system type -->
                <xsl:value-of select="$system-name"/>
              </td>
              
              <!-- Contains all information about the host (Vulnerabilities and vulnerable ports) -->
              <xsl:variable name="ReportHost" select="$Nessus/Report/ReportHost[@name=$ip]"/>
              
              <!-- Get all levels corresponding to vulnerabilities -->
              <xsl:variable name="Level">
                <xsl:for-each select="$ReportHost/ReportItem">
                  <!-- Search corresponding vulnerability -->
                  <xsl:variable name="Vulnerability" select="$Vulnerabilities/Vulnerabilities/Vulnerability[PluginsIds/PluginId=current()/@pluginID]"/>

                  <xsl:if test="$Vulnerability">
                    <Level><xsl:value-of select="$Vulnerability/Levels/Level[@system-type=$system-type]"/></Level>
                  </xsl:if>
                </xsl:for-each>
              </xsl:variable>

              <!-- Get maximum level of vulnerabilities -->
              <xsl:variable name="MaxLevel">
                <xsl:for-each select="common:node-set($Level)/Level">
                  <xsl:sort order="descending" select="."/>
                  <xsl:if test="position()=1">
                    <xsl:value-of select="."/>
                  </xsl:if>
                </xsl:for-each>
              </xsl:variable>
              
              <!-- Get all levels corresponding to vulnerable ports -->
              <xsl:variable name="PortLevel">
                <xsl:for-each select="$ReportHost/ReportItem[@severity=0]">
                  <xsl:variable name="Port" select="@port"/>

                  <!-- Search if port is dangerous -->
                  <xsl:variable name="VulnerablePort" select="$Ports/Port[@portID=$Port]"/>
                  
                  <xsl:if test="$VulnerablePort">
                    <Level><xsl:value-of select="$VulnerablePort/Levels/Level[@system-type=$system-type]"/></Level>
                  </xsl:if>
                </xsl:for-each>
              </xsl:variable>

              <!-- Get maximum level of vulnerable ports -->
              <xsl:variable name="MaxPortLevel">
                <xsl:for-each select="common:node-set($PortLevel)/Level">
                  <xsl:sort order="descending" select="."/>
                  <xsl:if test="position()=1">
                    <xsl:value-of select="."/>
                  </xsl:if>
                </xsl:for-each>
              </xsl:variable>
              
              <!-- Compute final Level -->
              <xsl:variable name="FinalLevel">
                <xsl:choose>
                  <xsl:when test="$MaxPortLevel=''">
                    <xsl:value-of select="$MaxLevel"/>
                  </xsl:when>
                  <xsl:when test="$MaxLevel > $MaxPortLevel">
                    <xsl:value-of select="$MaxLevel"/>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:value-of select="$MaxPortLevel"/>
                  </xsl:otherwise>
                </xsl:choose>
              </xsl:variable>
              
              <!-- Fill the cells Level and Problems -->
              <!-- Level -->
              <xsl:choose>
                <xsl:when test="$FinalLevel=4">
                  <td class="critical">Critical</td>
                </xsl:when>
                <xsl:when test="$FinalLevel=3">
                  <td class="high">High</td>
                </xsl:when>
                <xsl:when test="$FinalLevel=2">
                  <td class="medium">Medium</td>
                </xsl:when>
                <xsl:when test="$FinalLevel=1">
                  <td class="low">Low</td>
                </xsl:when>
                <xsl:otherwise>
                  <td></td>
                </xsl:otherwise>
              </xsl:choose>
                           
              <!-- Problems -->
              <td class="problems">
                <xsl:for-each select="$ReportHost/ReportItem">
                  <xsl:sort data-type="number" order="descending" select="@severity"/>

                  <!-- Search corresponding vulnerability -->
                  <xsl:variable name="Vulnerability" select="$Vulnerabilities/Vulnerabilities/Vulnerability[PluginsIds/PluginId=current()/@pluginID]"/>
                    
                  <xsl:choose>
                    <xsl:when test="$Vulnerability">
                      <!-- The vulnerability exists and is not already in a preceding ReportItem -->
                      <xsl:if test="not(preceding-sibling::ReportItem[@pluginID=$Vulnerability/PluginsIds/PluginId])">
                        <p>
                          <xsl:value-of select="$Vulnerability/@desc"/>
                        </p>                          
                      </xsl:if>
                    </xsl:when>
                    <xsl:otherwise>
                      <!-- Search corresponding port -->
                      <xsl:variable name="Port" select="@port"/>
                      <!-- Search if port is dangerous -->
                      <xsl:variable name="VulnerablePort" select="$Ports/Port[@portID=$Port]"/>   
                      <!-- The port is vulnerable -->
                      <xsl:if test="$VulnerablePort">
                        <!-- The port is not already in a preceding ReportItem -->
                        <xsl:if test="not(preceding-sibling::ReportItem[@port=$VulnerablePort/@portID])">
                          <p>
                            <xsl:value-of select="$VulnerablePort/@desc"/>
                          </p>
                        </xsl:if>
                      </xsl:if>
                    </xsl:otherwise>
                  </xsl:choose>
                    
                </xsl:for-each>
              </td>
            </tr>
          </xsl:for-each>
        </table>
      </body>
    </html>
  </xsl:template>

</xsl:stylesheet>

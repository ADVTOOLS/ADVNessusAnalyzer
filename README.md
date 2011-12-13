# What is ADVNessusAnalyzer?

ADVNessusAnalyzer is a set of tools to analyze and customize Nessus reports. It outputs an html report with categorized vulnerabilities for each host.

Nessus reports are very technical and contain a lot of information. The purposes of ADVNessusAnalyzer are to:

- Make a detailed report centered on the hosts
- Re-categorize Nessus vulnerabilities providing a custom and more comprehensive description and adjusting the security level by system type (server, station, router, printer)
- Exclude plugins not relevant (Parameters.xml)
- Add vulnerable opened port like ftp, telnet, etc... (Ports.xml)
- Group multiple Nessus vulnerabilities under one vulnerability

Examples:

- Nessus Plugin: 26928 - SSL Weak Cipher Suites Supported

- Nessus Plugin: 42873 - SSL Medium Strength Cipher Suites Supported

are grouped under: Weak SSL algorithms supported

- Nessus Plugin: 46868 - Apache Tomcat 5.x &lt; 5.5.21 Multiple Vulnerabilities

- Nessus Plugin: 46753 - Apache Tomcat &lt; 4.1.40 / 5.5.28 / 6.0.20 Multiple Vulnerabilities

- Nessus Plugin: 47028 - Apache Tomcat 5.x &lt; 5.5.1 Information Disclosure

are grouped under: The Tomcat server is vulnerable

# How to use ADVNessusAnalyzer?

ADVNessusAnalyzer has two reference files:

- Parameters.xml contains the list of Nessus excluded plugins that will not appear in the final report
- Ports.xml contains the list of vulnerable opened ports

ADVNessusAnalyzer contains several steps to follow.

- Prepare the vulnerabilities reference list that will be used for the final report

`xsltproc -o Vulnerabilities.xml Vulnerabilities.xslt nessus_report.nessus`

Vulnerabilities.xml will contain all Nessus plugin items, excluding those in Parameters.xml. You can modify Parameters.xml to exclude other plugins adding them to this file and re-processing Vulnerabilities.xslt. You can modify Vulnerabilities.xml to group some plugins under the same vulnerability and to adjust the security level by system type. Each time you re-process Vulnerabilities.xslt, it will add to Vulnerabilities.xml the Nessus missing plugins and will allow you to adjust this reference list. New plugins added to Vulnerabilities.xml after a process are identified by the attribute `documented="false"`.

During the first process of Vulnerabilities.xslt, the file Vulnerabilities.xml is not yet existing and a warning is displayed to the command line window.

- Prepare the list of hosts

`xsltproc -o Hosts.xml Hosts.xslt nessus_report.nessus`

Hosts.xml will contain all hosts having at least one vulnerability or one vulnerable opened port. Other host will not be displayed in the final report.

- Make the html report

`xsltproc -o Report.html Report.xslt nessus_report.nessus`

Report.html will contain the html customized report listing vulnerabilities by hosts (see the example Report.html).

# How to process ADVNessusAnalyzer files?

In order to process ADVNessusAnalyzer files, you need to have a tool for applying XSLT stylesheets to XML documents. For example, you can use [Libxml](http://www.zlatkovic.com/libxml.en.html)

# ADVNessusAnalyzer files

Parameters.xml: list of excluded plugins

Ports.xml: list of vulnerable opened ports

Vulnerabilities.xslt: provide xml vulnerabilities reference list. Parameters:

- vulnerabilities: xml file containing the list of customized vulnerabilities. Default file is Vulnerabilities.xml.

- excludedPlugins: xml file containing the list of excluded plugins. Default file is Parameters.xml.

Hosts.xslt: provide the list of hosts. Parameters:

- vulnerabilities: xml file containing the list of customized vulnerabilities. Default file is Vulnerabilities.xml.

- ports: xml file containing the list of vulnerable opened ports. Default file is Ports.xml

Report.xslt: generate the final report. Parameters:

- vulnerabilities: xml file containing the list of customized vulnerabilities. Default file is Vulnerabilities.xml.

- ports: xml file containing the list of vulnerable opened ports. Default file is Ports.xml

- hosts: xml file containing the list of hosts. Default file is Hosts.xml, result of Hosts.xslt process.

# References

[Libxml](http://www.zlatkovic.com/libxml.en.html)

# Copyright and license

Copyright (c) 2011 - [ADVTOOLS SARL](http://www.advtools.com)
 
This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.

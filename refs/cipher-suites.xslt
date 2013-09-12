<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="2.0"
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
        xmlns:iana="http://www.iana.org/assignments"
>

        <xsl:output method="text" omit-xml-declaration="yes" encoding="UTF-8"/>

        <xsl:variable name='nl'><xsl:text>&#xa;</xsl:text></xsl:variable>
        <xsl:variable name='sep'><xsl:text>,</xsl:text></xsl:variable>

        <xsl:template match="/">
                <xsl:for-each select="iana:registry/iana:registry[@id='tls-parameters-4']/iana:record">
                        <xsl:variable name="xref"><xsl:for-each select="iana:xref[@type='rfc']"><xsl:value-of select="@data"/></xsl:for-each></xsl:variable>

                        <xsl:if test="matches(iana:value, '^0x[0-9A-Z]{2},0x[0-9A-Z]{2}$')">
                                <xsl:value-of select="concat('toCipherSuite ',substring(iana:value,1,4),substring(iana:value,8,2),' = ',normalize-space(iana:description),$nl)" />
                        </xsl:if>
                </xsl:for-each>
        </xsl:template>

</xsl:stylesheet>

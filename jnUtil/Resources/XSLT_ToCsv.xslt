<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:msxsl="urn:schemas-microsoft-com:xslt" exclude-result-prefixes="msxsl"
>
    <xsl:key name="field" match="/*/*/*" use="name()" />
    <xsl:output encoding="utf-8" method="text" indent="yes"/>

    <xsl:template match="/">
        <xsl:for-each select="*/*/*[generate-id() = generate-id(key('field',name())[1])]">
            <xsl:value-of select="name()" />
            <xsl:if test="position() != last()">,</xsl:if>
        </xsl:for-each>
        <xsl:text>&#10;</xsl:text>
        <xsl:apply-templates select="*/*" mode="row"/>
    </xsl:template>

    <xsl:template match="*" mode="row">
        <xsl:variable name="row" select="*" />
        <xsl:for-each select="/*/*/*[generate-id() = generate-id(key('field',name())[1])]">
            <xsl:variable name="name" select="name()" />
            <xsl:apply-templates select="$row[name()=$name]" mode="data" />
            <xsl:if test="position() != last()">,</xsl:if>
        </xsl:for-each>
        <xsl:text>&#10;</xsl:text>
    </xsl:template>

    <xsl:template match="*" mode="data">
        <xsl:choose>
            <xsl:when test="contains(text(),',')">
                <xsl:text>&quot;</xsl:text>
                <xsl:call-template name="doublequotes">
                    <xsl:with-param name="text" select="text()" />
                </xsl:call-template>
                <xsl:text>&quot;</xsl:text>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="." />
            </xsl:otherwise>
        </xsl:choose>
        <xsl:if test="position() != last()">,</xsl:if>
    </xsl:template>

    <xsl:template name="doublequotes">
        <xsl:param name="text" />
        <xsl:choose>
            <xsl:when test="contains($text,'&quot;')">
                <xsl:value-of select="concat(substring-before($text,'&quot;'),'&quot;&quot;')" />
                <xsl:call-template name="doublequotes">
                    <xsl:with-param name="text" select="substring-after($text,'&quot;')" />
                </xsl:call-template>
            </xsl:when>
            <xsl:otherwise>
                <xsl:value-of select="$text" />
            </xsl:otherwise>
        </xsl:choose>
    </xsl:template>
</xsl:stylesheet>
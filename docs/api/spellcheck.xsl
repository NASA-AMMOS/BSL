<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <!-- Leave out raw code -->
  <xsl:template match="compoundname"/>
  <xsl:template match="type"/>
  <xsl:template match="definition"/>
  <xsl:template match="argsstring"/>
  <xsl:template match="param"/>
  <xsl:template match="name"/>
  <xsl:template match="qualifiedname"/>
  <xsl:template match="initializer"/>
  <xsl:template match="listofallmembers"/>
  <xsl:template match="term"/>
  <xsl:template match="parametername"/>
  <xsl:template match="incdepgraph"/>
  <xsl:template match="invincdepgraph"/>
  <xsl:template match="collaborationgraph"/>
  <xsl:template match="innerclass"/>
  <xsl:template match="includes"/>
  <xsl:template match="includedby"/>
  <xsl:template match="innerdir"/>
  <xsl:template match="innerfile"/>
  <xsl:template match="references"/>
  <xsl:template match="referencedby"/>
  <xsl:template match="ref"/>
  <xsl:template match="computeroutput"/>
  <xsl:template match="verbatim"/>
  <xsl:template match="programlisting"/>
  <xsl:template match="dot"/>
  <!-- remove characters that aspell cannot handle -->
  <xsl:template match="para/text()">
    <xsl:value-of select="translate(., '&#8217;', '')"/>
  </xsl:template>
  <!-- standard copy template -->
  <xsl:template match="@*|node()">
    <xsl:copy>
      <!-- ignore attributes -->
      <xsl:apply-templates />
    </xsl:copy>
  </xsl:template>
</xsl:stylesheet>

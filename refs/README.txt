
Requires saxonb-xslt (debian package libsaxonb-java)

generate toCipherSuite in CipherSuites.hs:
    saxonb-xslt tls-parameters.xml cipher-suites.xslt

generate toTLSAlertDescription in EnumTexts.hs
    saxonb-xslt tls-parameters.xml alerts.xslt

toTLSEllipticNameCurve in EnumTexts.hs
    saxonb-xslt tls-parameters.xml ec-named-curves.xslt


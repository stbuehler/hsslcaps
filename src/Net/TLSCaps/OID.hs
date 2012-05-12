
module Net.TLSCaps.OID where

import Data.List (intercalate)

showOID :: String -> [Integer] -> String
showOID _ [2,5,4,10] = "organizationName"
showOID _ [2,5,4,11] = "organizationUnitName"
showOID _ [2,5,4,3] = "commonName"
showOID _ [1,2,840,113549,1,9,1] = "emailAddress"
showOID _ [1,2,840,113549,1,1,1] = "rsaEncryption"
showOID _ [1,2,840,113549,1,1,4] = "md5WithRSAEncryption"
showOID _ [1,2,840,113549,1,1,5] = "sha1WithRSAEncryption"
showOID _ [1,3,6,1,5,5,7,1,1] = "authorityInfoAccess"
showOID _ [2,5,4,6] = "countryName"
showOID _ [2,5,4,7] = "localityName"
showOID _ [2,5,4,8] = "stateOrProvinceName"
showOID _ [2,5,29,14] = "subjectKeyIdentifier"
showOID _ [2,5,29,15] = "keyUsage"
showOID _ [2,5,29,17] = "subjectAltName"
showOID _ [2,5,29,19] = "basicConstraints"
showOID _ [2,5,29,31] = "cRLDistributionPoints"
showOID _ [2,5,29,35] = "authorityKeyIdentifier"
showOID _ [2,5,29,37] = "extKeyUsage"
showOID _ [2,16,840,1,113730,1,4] = "ca-revocation-url"
showOID _ [2,16,840,1,113730,1,8] = "ca-policy-url"
showOID _ [2,16,840,1,113730,1,13] = "comment"

showOID _ l = "OID " ++ intercalate "." (map show l)

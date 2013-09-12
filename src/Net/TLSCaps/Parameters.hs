
module Net.TLSCaps.Parameters
	( TLSParameters(..)
	, defaultParameters
	) where

import Net.TLSCaps.EnumTexts
import Net.TLSCaps.Record

import qualified Data.ByteString.Lazy as B

data TLSParameters = TLSParameters { tlsMinVersion, tlsMaxVersion :: TLSVersion, tlsRandom, tlsSessionID :: B.ByteString, tlsCipherSuites :: [CipherSuite], tlsCompressionMethods :: [TLSCompressionMethod], tlsExtensions :: [Extension] }

defaultCipherSuites :: [CipherSuite]
defaultCipherSuites = [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_RC4_128_SHA,TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
defaultCompressionMethods :: [TLSCompressionMethod]
defaultCompressionMethods = [TLS_Comp_None]

defaultEllipticCurves :: Extension
defaultEllipticCurves = ExtensionEllipticCurves [TLS_EC_sect163k1,TLS_EC_sect163r1,TLS_EC_sect163r2,TLS_EC_sect193r1,TLS_EC_sect193r2,TLS_EC_sect233k1,TLS_EC_sect233r1,TLS_EC_sect239k1,TLS_EC_sect283k1,TLS_EC_sect283r1,TLS_EC_sect409k1,TLS_EC_sect409r1,TLS_EC_sect571k1,TLS_EC_sect571r1,TLS_EC_secp160k1,TLS_EC_secp160r1,TLS_EC_secp160r2,TLS_EC_secp192k1,TLS_EC_secp192r1,TLS_EC_secp224k1,TLS_EC_secp224r1,TLS_EC_secp256k1,TLS_EC_secp256r1,TLS_EC_secp384r1,TLS_EC_secp521r1,TLS_EC_brainpoolP256r1,TLS_EC_brainpoolP384r1,TLS_EC_brainpoolP512r1,TLS_EC_arbitrary_explicit_prime_curves,TLS_EC_arbitrary_explicit_char2_curves]
defaultECPointFormats :: Extension
defaultECPointFormats = ExtensionECPointFormats [TLS_ECPF_uncompressed,TLS_ECPF_ansiX962_compressed_prime,TLS_ECPF_ansiX962_compressed_char2]

defaultExtensions :: [Extension]
defaultExtensions = [defaultEllipticCurves,defaultECPointFormats,ExtensionSessionTicket B.empty,ExtensionRenegotiationInfo B.empty]

defaultParameters :: TLSParameters
defaultParameters = TLSParameters { tlsMinVersion = TLS1_0, tlsMaxVersion = TLS1_2, tlsRandom = B.empty, tlsSessionID = B.empty, tlsCipherSuites = defaultCipherSuites, tlsCompressionMethods = defaultCompressionMethods, tlsExtensions = defaultExtensions }

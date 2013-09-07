
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

defaultParameters :: TLSParameters
defaultParameters = TLSParameters { tlsMinVersion = TLS1_0, tlsMaxVersion = TLS1_0, tlsRandom = B.empty, tlsSessionID = B.empty, tlsCipherSuites = defaultCipherSuites, tlsCompressionMethods = defaultCompressionMethods, tlsExtensions = [] }

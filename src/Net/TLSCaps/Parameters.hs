
module Net.TLSCaps.Parameters
	( TLSParameters(..)
	, defaultParameters
	) where

import Net.TLSCaps.CipherSuites
import Net.TLSCaps.EnumTexts
import Net.TLSCaps.Record

import Data.Word (Word8, Word16)
import qualified Data.ByteString.Lazy as B

data TLSParameters = TLSParameters { tlsMinVersion, tlsMaxVersion :: Word16, tlsRandom, tlsSessionID :: B.ByteString, tlsCipherSuites :: [Word16], tlsCompressionMethods :: [Word8], tlsExtensions :: [Extension] }

defaultCipherSuites :: [Word16]
defaultCipherSuites = map cipherSuiteID $ [TLS_RSA_WITH_RC4_128_SHA,TLS_EMPTY_RENEGOTIATION_INFO_SCSV]
defaultCompressionMethods :: [Word8]
defaultCompressionMethods = [comp_null,comp_deflate]

defaultParameters :: TLSParameters
defaultParameters = TLSParameters { tlsMinVersion = rv_tls1_0, tlsMaxVersion = rv_tls1_2, tlsRandom = B.empty, tlsSessionID = B.empty, tlsCipherSuites = defaultCipherSuites, tlsCompressionMethods = defaultCompressionMethods, tlsExtensions = [] }

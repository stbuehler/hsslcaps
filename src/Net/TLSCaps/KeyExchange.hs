
module Net.TLSCaps.KeyExchange
	( ServerKeyExchange(..)
	, skx_parse_ECDHE_RSA
	) where

import qualified Data.ByteString.Lazy as B

import Net.TLSCaps.Serialize
-- import Net.TLSCaps.Utils
-- import Net.TLSCaps.CipherSuites
import Net.TLSCaps.EllipticCurves
import Net.TLSCaps.EnumTexts

import Control.Monad (ap)

data ServerKeyExchange
	= SKX_ECDHE_RSA ECCurve ECPoint (TLSHashAlgorithm, TLSSignatureAlgorithm, B.ByteString)
	deriving (Eq, Show)

parse_Signature :: Monad m => Deserializer m (TLSHashAlgorithm, TLSSignatureAlgorithm, B.ByteString)
parse_Signature = do
	return (,,) `ap` getEnum `ap` getEnum `ap` getString16

skx_parse_ECDHE_RSA :: Monad m => Deserializer m ServerKeyExchange
skx_parse_ECDHE_RSA = do
	curve <- parseCurve
	return (SKX_ECDHE_RSA curve) `ap` parsePoint curve `ap` parse_Signature

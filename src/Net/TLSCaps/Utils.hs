module Net.TLSCaps.Utils
	( hexA
	, hexS
	, netEncode
	, netDecode
	, showAsnTree
	, decodeDER_ASN1
	, createTLSRandom
	) where

import qualified Data.Array.IArray as A
import Data.Word (Word8)
import qualified Data.ByteString.Lazy as B
import Data.List (intercalate)

import qualified Data.ASN1.DER as DER
import qualified Data.ASN1.Types as ASN1
import Data.ASN1.BitArray (BitArray(..))

import qualified Control.Monad as M
import Data.Time.Clock.POSIX (getPOSIXTime)
import System.Random

import Net.TLSCaps.OID

hexChars :: A.Array Word8 Char
hexChars = A.listArray (0,15) (['0'..'9'] ++ ['A'..'F'])

hexA :: [Word8] -> String
hexA [] = []
hexA (x:xs) = let (high,low) = divMod x 16 in hexChars A.! high:hexChars A.! low:hexA xs

hexS :: B.ByteString -> String
hexS = hexA . B.unpack

netEncode :: (Integral n) => Int -> n -> [Word8]
netEncode bytes value = _work bytes [] value where
	_work 0 r _ = r
	_work n r v = let (d, m) = divMod v 256 in _work (n-1) (fromIntegral m:r) d

netDecode :: (Integral n) => Int -> [Word8] -> n
netDecode bytes list = _work bytes 0 list where
	_work 0 r _ = r
	_work n r (v:l) = _work (n-1) (r*256+fromIntegral v) l
	_work _ _ [] = error "Not enough bytes"

showAsnTree :: [ASN1.ASN1t] -> String
showAsnTree [asn] = _showAsnTree1 asn
showAsnTree asn = _showAsnTreeL asn

_showAsnTreeL :: [ASN1.ASN1t] -> String
_showAsnTreeL asn = "[" ++ intercalate "," (map _showAsnTree1 asn) ++ "]"

_showAsnTree1 :: ASN1.ASN1t -> String
_showAsnTree1 asn = case asn of
		ASN1.OID oid -> showOID (show asn) oid
		ASN1.PrintableString s -> show s
		ASN1.OctetString s -> "OctetString 0x(" ++ hexS s ++ ")"
		ASN1.BitString (BitArray len s) -> "BitString " ++ show len ++ " 0x(" ++ hexS s ++ ")"
		ASN1.Sequence l -> if (all isMapEntry l) then _showAsnMap l else "Sequence " ++ _showAsnTreeL l
		ASN1.Set l -> "Set " ++ _showAsnTreeL l
		ASN1.Container cl tag l -> "Container " ++ show cl ++ " " ++ show tag ++ " " ++ _showAsnTreeL l
		_ -> show asn
	where
		isMapEntry :: ASN1.ASN1t -> Bool
		isMapEntry (ASN1.Set [ASN1.Sequence [ASN1.OID _, _]]) = True
		isMapEntry _ = False

_showAsnMap :: [ASN1.ASN1t] -> String
_showAsnMap l = "[" ++ intercalate "," (map _showAsnMap1 l) ++ "]"

_showAsnMap1 :: ASN1.ASN1t -> String
_showAsnMap1 (ASN1.Set [ASN1.Sequence [key, value]]) = _showAsnTree1 key ++ " => " ++ _showAsnTree1 value
_showAsnMap1 _ = error "Internal error"

decodeDER_ASN1 :: B.ByteString -> String
decodeDER_ASN1 buf = case DER.decodeASN1Stream buf of
	Right asn -> showAsnTree (ASN1.ofStream asn)
	Left err -> "(DER decode error: " ++ show err ++ ") " ++ show (B.unpack buf)


createTLSRandom :: IO B.ByteString
createTLSRandom = do
	now <- getPOSIXTime
	rnd <- M.replicateM 28 $ getStdRandom (randomR (0, 255::Int))
	return $ B.pack $ netEncode 4 (floor (now) :: Integer) ++ (map fromIntegral rnd)

module Net.TLSCaps.Utils
	( hexA
	, hexS
	, netEncode
	, netDecode
	, decodeDER_ASN1
	, createTLSRandom
	, ErrorMonad(..)
	) where

import qualified Data.Array.IArray as A
import Data.Word (Word8)
import qualified Data.ByteString.Lazy as B

import Data.ASN1.Encoding (decodeASN1)
import Data.ASN1.BinaryEncoding (DER(..))

import qualified Control.Monad as M
import Data.Time.Clock.POSIX (getPOSIXTime)
import System.Random

-- import Net.TLSCaps.OID

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

decodeDER_ASN1 :: B.ByteString -> String
decodeDER_ASN1 buf = case decodeASN1 DER buf of
	Right asn -> show asn
	Left err -> "(DER decode error: " ++ show err ++ ") " ++ show (B.unpack buf)


createTLSRandom :: IO B.ByteString
createTLSRandom = do
	now <- getPOSIXTime
	rnd <- M.replicateM 28 $ getStdRandom (randomR (0, 255::Int))
	return $ B.pack $ netEncode 4 (floor (now) :: Integer) ++ (map fromIntegral rnd)


data ErrorMonad x = Result x | Error String
instance  Monad ErrorMonad  where
    (Result x) >>= k  = k x
    (Error s)  >>= _  = Error s
    (Result _) >> k   = k
    (Error s) >> _    = Error s
    return            = Result
    fail              = Error


module Net.TLSCaps.Extensions
	( Extension(..)

	, ServerName(..)

	, MaxFragmentLength(..)
	, toMaxFragmentLength
	, fromMaxFragmentLength

	, putExtension
	, parseClientHelloExtensions
	, parseServerHelloExtensions
	) where

import Data.Word (Word8, Word16)
import qualified Data.ByteString.Lazy as B

import Net.TLSCaps.Serialize
import Net.TLSCaps.Utils
import Net.TLSCaps.EnumTexts

import Control.Monad (when)

import Data.List (intercalate)

-- server_name extension
data ServerName = HostName B.ByteString | ServerName_Raw Word8 B.ByteString deriving (Eq, Show)

-- max_fragment_length extension
newtype MaxFragmentLength = MaxFragmentLength Word8 deriving (Eq)
toMaxFragmentLength :: Integer -> Maybe MaxFragmentLength
toMaxFragmentLength 512  = Just $ MaxFragmentLength 1
toMaxFragmentLength 1024 = Just $ MaxFragmentLength 2
toMaxFragmentLength 2048 = Just $ MaxFragmentLength 3
toMaxFragmentLength 4096 = Just $ MaxFragmentLength 4
toMaxFragmentLength _ = Nothing
fromMaxFragmentLength :: MaxFragmentLength -> Maybe Integer
fromMaxFragmentLength (MaxFragmentLength 1) = Just 512
fromMaxFragmentLength (MaxFragmentLength 2) = Just 1024
fromMaxFragmentLength (MaxFragmentLength 3) = Just 2048
fromMaxFragmentLength (MaxFragmentLength 4) = Just 4096
fromMaxFragmentLength _ = Nothing

instance Show MaxFragmentLength where
	show l@(MaxFragmentLength c) = case fromMaxFragmentLength l of
		Just n -> show n
		Nothing -> "(fragmentlengthcode " ++ show c ++ ")"

data CertificateStatusRequest= OCSPStatusRequest [B.ByteString] B.ByteString deriving (Eq)
instance Show CertificateStatusRequest where
	show (OCSPStatusRequest responder_ids extensions) = "OCSPStatusRequest (responder_ids: [" ++ intercalate "," (map hexS responder_ids) ++ "], extensions: " ++ hexS extensions ++ ")"

data Extension
	= ExtensionRaw Word16 B.ByteString
	| ExtensionServerName [ServerName]
	| ExtensionMaxFragmentLength MaxFragmentLength
	| ExtensionClientCertificateUrl
--	| ExtensionTrustedCaKeys
	| ExtensionTruncatedHMAC
	| ExtensionStatusRequest CertificateStatusRequest
	| ExtensionStatusRequest_Response -- empty reply from server
--	| ExtensionUserMapping
--	| ExtensionClientAuthz
--	| ExtensionServerAuthz
--	| ExtensionCertType
	| ExtensionEllipticCurves [TLSEllipticNameCurve]
	| ExtensionECPointFormats [TLSECPointFormat]
--	| ExtensionSrp
--	| ExtensionSignatureAlgorithms
--	| ExtensionUseSrtp
--	| ExtensionHeartbeat
	| ExtensionApplicationLayerProtocolNegotiation [B.ByteString]
--	| ExtensionStatusRequestV2
--	| ExtensionSignedCertificateTimestamp
	| ExtensionSessionTicket B.ByteString
	| ExtensionRenegotiationInfo B.ByteString
	deriving (Eq)

instance Show Extension where
	show (ExtensionRaw t d) = "ExtensionRaw " ++ show t ++ " " ++ show (B.unpack d)
	show (ExtensionServerName names) = "SNI: " ++ show names
	show (ExtensionMaxFragmentLength len) = "MaxFragmentLength: " ++ show len
	show (ExtensionClientCertificateUrl) = "ClientCertificateURL"
	show (ExtensionTruncatedHMAC) = "TruncatedHMAC"
	show (ExtensionStatusRequest request) = "StatusRequest: " ++ show request
	show (ExtensionStatusRequest_Response) = "StatusRequest: (reply)"
	show (ExtensionEllipticCurves names) = "Elliptic Curves: " ++ show names
	show (ExtensionECPointFormats formats) = "Elliptic Curve Point Formats: " ++ show formats
	show (ExtensionApplicationLayerProtocolNegotiation protocols) = "ALPN: " ++ show protocols
	show (ExtensionSessionTicket ticket) = "SessionTicket: (" ++ hexS ticket ++ ")"
	show (ExtensionRenegotiationInfo info) = "RenegotiationInfo: (" ++ hexS info ++ ")"


parseClientHelloExtensions :: Monad m => Deserializer m [Extension]
parseClientHelloExtensions = do
	hasExts <- inputAvailable 2
	if (hasExts) then getBlock16 (whileHasInput $ _parseExtension False) else return []

parseServerHelloExtensions :: Monad m => Deserializer m [Extension]
parseServerHelloExtensions = do
	hasExts <- inputAvailable 2
	if (hasExts) then getBlock16 (whileHasInput $ _parseExtension True) else return []


_parseExtension :: Monad m => Bool -> Deserializer m Extension
_parseExtension server = flip getCatch (do; t <- getWord16; d <- getString16; return $ ExtensionRaw t d) $ do
		t <- getWord16
		getBlock16 $ case t of
			0x0000 -> parseExtensionServerName
			0x0001 -> parseMaxFragmentLength
			0x0002 -> return ExtensionClientCertificateUrl
			0x0004 -> return ExtensionTruncatedHMAC
			0x0005 -> if server then return ExtensionStatusRequest_Response else parseStatusRequest
			0x000a -> parseEllipticCurves
			0x000b -> parseECPointFormats
			0x0010 -> parseApplicationLayerProtocolNegotiation
			0x0023 -> parseSessionTicket
			0xff01 -> parseRenegotiationInfo
			_ -> fail "unknown extension"

parseExtensionServerName :: Monad m => Deserializer m Extension
parseExtensionServerName = do
	names <- getBlock16 $ whileHasInput $ do
		t <- getByte
		name <- getString16
		if t == 0 then return $ HostName name else return $ ServerName_Raw t name
	return $ ExtensionServerName names

parseMaxFragmentLength :: Monad m => Deserializer m Extension
parseMaxFragmentLength = do
	code <- getByte
	return $ ExtensionMaxFragmentLength $ MaxFragmentLength code

parseStatusRequest :: Monad m => Deserializer m Extension
parseStatusRequest = do
	fail "not implemented yet" -- TODO

parseEllipticCurves :: Monad m => Deserializer m Extension
parseEllipticCurves = do
	names <- getBlock16 $ whileHasInput $ getWord16 >>= return . toTLSEllipticNameCurve
	return $ ExtensionEllipticCurves names

parseECPointFormats :: Monad m => Deserializer m Extension
parseECPointFormats = do
	names <- getBlock8 $ whileHasInput $ getByte >>= return . toTLSECPointFormat
	return $ ExtensionECPointFormats names

parseApplicationLayerProtocolNegotiation :: Monad m => Deserializer m Extension
parseApplicationLayerProtocolNegotiation = do
	protocols <- getBlock16 $ whileHasInput $ getString8
	return $ ExtensionApplicationLayerProtocolNegotiation protocols

parseSessionTicket :: Monad m => Deserializer m Extension
parseSessionTicket = do
	availableInput >>= getString >>= return . ExtensionSessionTicket

parseRenegotiationInfo :: Monad m => Deserializer m Extension
parseRenegotiationInfo = do
	info <- getString8
	return $ ExtensionRenegotiationInfo info

putExtension :: Monad m => Extension -> Serializer m ()
putExtension (ExtensionRaw t d) = putWord16 t >> putString16 "Extension" d
putExtension (ExtensionServerName names) = do
	putWord16 0x0000 -- 0
	putBlock16 "Extension ServerName" $ do
		putBlock16 "server_name_list" $ mapM_ putServerName names
putExtension (ExtensionMaxFragmentLength (MaxFragmentLength code)) = do
	putWord16 0x0001 -- 1
	putBlock16 "Extension MaxFragmentLength" $ do
		putByte code
putExtension (ExtensionClientCertificateUrl) = do
	putWord16 0x0002 -- 2
	putBlock16 "Extension ClientCertificateURL" $ return ()
putExtension (ExtensionTruncatedHMAC) = do
	putWord16 0x0004 -- 4
	putBlock16 "Extension TruncatedHMAC" $ return ()
putExtension (ExtensionStatusRequest request) = do
	putWord16 0x0005 -- 5
	putBlock16 "Extension StatusRequest" $ do
		putCertificateStatusRequest request
putExtension (ExtensionStatusRequest_Response) = do
	putWord16 0x0005 -- 5
	putBlock16 "Extension StatusRequest (server response)" $ return ()
putExtension (ExtensionEllipticCurves names) = do
	putWord16 0x000a -- 10
	putBlock16 "Extension EllipticCurves" $ do
		putBlock16 "elliptic_curve_list" $ mapM_ putEnum names
putExtension (ExtensionECPointFormats formats) = do
	putWord16 0x000b -- 10
	putBlock16 "Extension ECPointFormats" $ do
		putBlock8 "ec_point_format_list" $ mapM_ putEnum formats
putExtension (ExtensionApplicationLayerProtocolNegotiation protocols) = do
	putWord16 0x0010 -- 16
	putBlock16 "Extension ApplicationLayerProtocolNegotiation" $ do
		when (length protocols == 0) $ fail ("protocol_name_list empty")
		putBlock16 "protocol_name_list" $ flip mapM_ protocols $ \protocol -> do
			when (B.length protocol == 0) $ fail ("protocol empty")
			putString8 "protocol" protocol
putExtension (ExtensionSessionTicket ticket) = do
	putWord16 0x0023 -- 35
	putString16 "Extension SessionTicket" ticket
putExtension (ExtensionRenegotiationInfo info) = do
	putWord16 0xff01 -- 65281
	putBlock16 "Extension RenegotiationInfo" $ do
		putString8 "renegotiated_connection" info

putServerName :: Monad m => ServerName -> Serializer m ()
putServerName (HostName name) = do
	putByte 0 -- type "host_name"
	putString16 "host_name" name
putServerName (ServerName_Raw t name) = do
	putByte t
	putString16 "server_name entry" name

putCertificateStatusRequest :: Monad m => CertificateStatusRequest -> Serializer m ()
putCertificateStatusRequest (OCSPStatusRequest responder_ids extensions) = do
	putByte 0x01 -- ocsp
	putBlock16 "responder id list" $ flip mapM_ responder_ids $ \resp_id -> do
		when (B.length resp_id == 0) $ fail ("responder id empty")
		putString16 "responder id" resp_id
	putString16 "extension" extensions

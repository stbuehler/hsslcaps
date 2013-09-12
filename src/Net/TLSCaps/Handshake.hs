
module Net.TLSCaps.Handshake
	( Handshake(..)
	, SignatureAndHashAlgorithm(..)
	, URLAndHash(..)
	, Extension(..)
	, parseHandshake
	, writeHandshake
	) where


import qualified Data.ByteString.Lazy as B

import Net.TLSCaps.Serialize
import Net.TLSCaps.Utils
import Net.TLSCaps.EnumTexts
import Net.TLSCaps.Extensions
import Net.TLSCaps.KeyExchange

import Control.Monad (when, unless, ap)
import Data.Word (Word16, Word32)

import Text.Show (showListWith)

data Cert = Cert B.ByteString deriving (Eq)
data SignatureAndHashAlgorithm = SignatureAndHashAlgorithm { sahaHash :: TLSHashAlgorithm, sahaSignature :: TLSSignatureAlgorithm } deriving (Eq)
data URLAndHash = URLAndHash { urlAndHashUrl :: B.ByteString, urlAndHashHash :: B.ByteString } deriving (Eq)

instance Show Cert where
	show (Cert c) = "Cert " ++ decodeDER_ASN1 c
instance Show SignatureAndHashAlgorithm where
	show (SignatureAndHashAlgorithm hash sig) = show (hash, sig)
instance Show URLAndHash where
	show (URLAndHash url hash) = show url ++ " (sha1: " ++ hexS hash ++ ")"


data Handshake = HelloRequest
	| ClientHello { hChClientVersion :: TLSVersion, hChRandom :: B.ByteString, hChSessionId :: B.ByteString, hChCipherSuites :: [CipherSuite], hChCompressionMethods :: [TLSCompressionMethod], hChExtensions :: [Extension] }
	| ServerHello { hShServerVersion :: TLSVersion, hShRandom :: B.ByteString, hShSessionId :: B.ByteString, hShCipherSuite :: CipherSuite, hShCompressionMethod :: TLSCompressionMethod, hShExtensions :: [Extension] }
	| NewSessionTicket {  hStLifetimeHint :: Word32, hStTicket :: B.ByteString }
	| Certificate [Cert]
	| ServerKeyExchange ServerKeyExchange -- B.ByteString -- format depends on key exch algorithm
	| CertificateRequest { hCrCertificateTypes :: [TLSClientCertificateType], hCrAlgorithms :: [SignatureAndHashAlgorithm], hCrCertificateAuthorities :: [B.ByteString] }
	| ServerHelloDone
	| CertificateVerify B.ByteString -- signature
	| ClientKeyExchange B.ByteString -- format depends on key exch algorithm
	| Finished B.ByteString -- verify data
	| CertificateURL_IndividualCerts [URLAndHash]
	| CertificateURL_PKIPath URLAndHash
	| CertificateStatus_OCSP B.ByteString -- ocsp response
	| SupplementalData [(Word16, B.ByteString)]
	deriving (Eq)

showDN :: B.ByteString -> ShowS
showDN dn pre = pre ++ "DN " ++ decodeDER_ASN1 dn

instance Show Handshake where
	show (HelloRequest) = "HelloRequest"
	show (ClientHello ver rand sess suites comps exts) = "ClientHello (" ++ show ver ++ ", Random [" ++ hexS rand ++ "], SessionID [" ++ hexS sess ++ "], CipherSuites [" ++ show suites ++ "], CompressionMethods " ++ show comps ++ ", Extensions " ++ show exts ++ ")"
	show (ServerHello ver rand sess suite comp exts) = "ServerHello (" ++ show ver ++ ", Random [" ++ hexS rand ++ "], SessionID [" ++ hexS sess ++ "], CipherSuite " ++ show suite ++ ", CompressionMethod " ++ show comp ++ ", Extensions " ++ show exts ++ ")"
	show (NewSessionTicket lifetime ticket) = "NewSessionTicket (TTL " ++ show lifetime ++ ", Ticket [" ++ hexS ticket ++ "])"
	show (Certificate _) = "Certificates [...]" -- ++ show certs -- (intercalate "," $ map showDN certs)
	show (ServerKeyExchange d) = "ServerKeyExchange (" ++ show d ++ ")"
	show (CertificateRequest types algs cas) = "CertificateRequest (Certificate Types " ++ (show types) ++ ", Supported Algorithms " ++ show algs ++ ", CAs [" ++ showListWith showDN cas "" ++ "])"
	show (ServerHelloDone) = "ServerHelloDone"
	show (CertificateVerify d) = "CertificateVerify (" ++ hexS d ++ ")"
	show (ClientKeyExchange d) = "ClientKeyExchange (" ++ hexS d ++ ")"
	show (Finished _) = "Finished [...]"
	show (CertificateURL_IndividualCerts urls) = "CertificateURL (" ++ show urls ++ ")"
	show (CertificateURL_PKIPath url) = "CertificateURL (" ++ show url ++ ")"
	show (CertificateStatus_OCSP response) = "CertificateStatus (OSCP response [" ++ hexS response ++ "])"
	show (SupplementalData d) = "SupplementalData (" ++ showListWith (\(t,v) post -> "(" ++ show t ++ ", " ++ hexS v ++ ")" ++ post) d "" ++ ")"

parseHandshake :: Monad m => TLSVersion -> TLSHandshakeType -> B.ByteString -> m Handshake
parseHandshake ver ht hdata = deserialize hdata (select ht)
	where
		select TLS_HT_HelloRequest = return HelloRequest
		select TLS_HT_ClientHello = return ClientHello
			`ap` getEnum
			`ap` getString 32
			`ap` _parseSessionID
			`ap` (getBlock16 $ whileHasInput $ getEnum)
			`ap` (getBlock8 $ whileHasInput $ getEnum)
			`ap` parseClientHelloExtensions
		select TLS_HT_ServerHello = return ServerHello
			`ap` getEnum
			`ap` getString 32
			`ap` _parseSessionID
			`ap` getEnum
			`ap` getEnum
			`ap` parseServerHelloExtensions
-- 		select TLS_HT_HelloVerifyRequest -- DTLS
		select TLS_HT_NewSessionTicket = return NewSessionTicket `ap` getWord32 `ap` getString16
		select TLS_HT_Certificate = return Certificate `ap` (getBlock24 $ whileHasInput $ return Cert `ap` getString24)
		select TLS_HT_ServerKeyExchange = return ServerKeyExchange `ap` skx_parse_ECDHE_RSA -- availableInput >>= getString >>= return . ServerKeyExchange
		select TLS_HT_CertificateRequest = return CertificateRequest `ap` (getBlock8 $ whileHasInput $ getEnum) `ap` _parseSignatureAndHashAlgorithms `ap` (getBlock16 $ whileHasInput $ getString16)
		select TLS_HT_ServerHelloDone = return ServerHelloDone
		select TLS_HT_CertificateVerify = availableInput >>= getString >>= return . CertificateVerify
		select TLS_HT_ClientKeyExchange = availableInput >>= getString >>= return . ClientKeyExchange
		select TLS_HT_Finished = availableInput >>= getString >>= return . Finished
		select TLS_HT_CertificateUrl = do
			getByte >>= \t -> case t of
				0x00 -> do -- individual_certs
					return CertificateURL_IndividualCerts `ap` (getBlock16 $ whileHasInput _parseURLAndHash)
				0x01 -> do -- pkipath
					return CertificateURL_PKIPath `ap` (getBlock16 $ _parseURLAndHash)
				_ -> fail $ "Unknown CertChainType " ++ show t
		select TLS_HT_CertificateStatus = do
			getByte >>= \t -> case t of
				0x01 -> do -- oscp
					response <- getString24
					when (0 == B.length response) $ fail "Empty OCSP CertificateStatus response"
					return $ CertificateStatus_OCSP response
				_ -> fail $ "Unknown CertificateStatusType " ++ show t
		select TLS_HT_SupplementalData = do
			return SupplementalData `ap` (getBlock24 $ do
				(inputAvailable 1) >>= flip unless (fail "Empty SupplementalData")
				whileHasInput $ return (,) `ap` getWord16 `ap` getString16)
		select _ = fail ("Cannot parse handshake type: " ++ show ht)

		_parseSessionID :: Monad m => Deserializer m B.ByteString
		_parseSessionID = do
			session <- getString8
			when (B.length session > 32) $ fail $ "Session ID too long: (" ++ hexS session ++ ")"
			return session

		_parseSignatureAndHashAlgorithms :: Monad m => Deserializer m [SignatureAndHashAlgorithm]
		_parseSignatureAndHashAlgorithms =
			if (ver >= TLS1_2) then getBlock16 $ whileHasInput $ return SignatureAndHashAlgorithm `ap` getEnum `ap` getEnum else return []

		_parseURLAndHash :: Monad m => Deserializer m URLAndHash
		_parseURLAndHash = do
			url <- getString8
			when (B.length url == 0) $ fail $ "Empty URL"
			getByte >>= \padding -> when (0x01 /= padding) $ fail $ "Wrong padding"
			hash <- getString 20
			return $ URLAndHash url hash


handshakeType :: Handshake -> TLSHandshakeType
handshakeType (HelloRequest) = TLS_HT_HelloRequest
handshakeType (ClientHello _ _ _ _ _ _) = TLS_HT_ClientHello
handshakeType (ServerHello _ _ _ _ _ _) = TLS_HT_ServerHello
handshakeType (NewSessionTicket _ _) = TLS_HT_NewSessionTicket
handshakeType (Certificate _) = TLS_HT_Certificate
handshakeType (ServerKeyExchange _) = TLS_HT_ServerKeyExchange
handshakeType (CertificateRequest _ _ _) = TLS_HT_CertificateRequest
handshakeType (ServerHelloDone) = TLS_HT_ServerHelloDone
handshakeType (CertificateVerify _) = TLS_HT_CertificateVerify
handshakeType (ClientKeyExchange _) = TLS_HT_ClientKeyExchange
handshakeType (Finished _) = TLS_HT_Finished
handshakeType (CertificateURL_IndividualCerts _) = TLS_HT_CertificateUrl
handshakeType (CertificateURL_PKIPath _) = TLS_HT_CertificateUrl
handshakeType (CertificateStatus_OCSP _) = TLS_HT_CertificateStatus
handshakeType (SupplementalData _) =  TLS_HT_SupplementalData


writeHandshake :: Monad m => TLSVersion -> Handshake -> m (TLSHandshakeType, B.ByteString)
writeHandshake ver handshake = do
	d <- serialize (putHandshake ver handshake)
	return (handshakeType handshake, d)

putHandshake :: Monad m => TLSVersion -> Handshake -> Serializer m ()
putHandshake hver handshake = case handshake of
		HelloRequest -> return ()
		ClientHello ver random session ciphers comps exts -> do
			putEnum ver
			_putRandom random
			putBlockLimit 32 "SessionID" $ putString  session
			putBlock16 "ciphersuites" $ mapM_ putEnum ciphers
			putBlock8 "compression methods" $ mapM_ putEnum comps
			putBlock16 "Extensions" $ mapM_ putExtension exts
		ServerHello ver random session cipher comp exts -> do
			putEnum ver
			_putRandom random
			putBlockLimit 32 "SessionID" $ putString  session
			putEnum cipher
			putEnum comp
			putBlock16 "Extensions" $ mapM_ putExtension exts
		NewSessionTicket lifetime_hint ticket -> do
			putWord32 lifetime_hint
			putString16 "session ticket" ticket
		Certificate certs -> do
			putBlock24 "Certificates" $ flip mapM_ certs $ \(Cert d) -> putString24 "Certificate" d
		ServerKeyExchange exch -> fail "not supported" -- putString exch
		CertificateRequest types algs cas -> do
			putBlock8 "client certificate types" $ mapM_ putEnum types
			if (hver >= TLS1_2)
				then _putSignatureAndHashAlgorithms algs
				else when (algs /= []) $ fail ("Signature and hash algorithms not usable in version " ++ show hver)
			putBlock16 "certificate authorities" $ mapM_ (putString16 "Distinguished name") cas
		ServerHelloDone -> return ()
		CertificateVerify sig -> putString sig
		ClientKeyExchange exch -> putString exch
		Finished verify -> putString verify
		CertificateURL_IndividualCerts urls -> do
			putByte 0x00 -- individual_certs
			when (0 == length urls) $ fail "No URLs"
			putBlock16 "url_and_hash_list" $ mapM_ _putURLAndHash urls
		CertificateURL_PKIPath url -> do
			putByte 0x01 -- pkipath
			putBlock16 "url_and_hash_list" $ _putURLAndHash url
		CertificateStatus_OCSP response -> do
			putByte 0x01 -- ocsp
			when (0 == B.length response) $ fail "Empty OCSP CertificateStatus response"
			putString24 "OCSPResponse" response
		SupplementalData entries -> do
			when (0 == length entries) $ fail "Empty SupplementalData"
			putBlock24 "supp_data" $ flip mapM_ entries $ \(t, d) -> do
				when (0 == B.length d) $ fail "Empty SupplementalData entry"
				putWord16 t
				putString16 "supp_entry_data" d
	where
		_putRandom :: Monad m => B.ByteString -> Serializer m ()
		_putRandom rnd = do
			when (32 /= B.length rnd) $ fail ("Random isn't 32 bytes long")
			putString rnd

		_putSignatureAndHashAlgorithms :: Monad m => [SignatureAndHashAlgorithm] -> Serializer m ()
		_putSignatureAndHashAlgorithms algs = do
			putBlock16 "signature and hash algorithms" $ flip mapM_ algs $ \(SignatureAndHashAlgorithm hash sig) -> putEnum hash >> putEnum sig

		_putURLAndHash :: Monad m => URLAndHash -> Serializer m ()
		_putURLAndHash (URLAndHash url hash) = do
			when (0 == B.length url) $ fail "Empty URL"
			putString16 "CertificateURL URL" url
			putByte 0x01 -- "padding"
			when (20 /= B.length hash) $ fail "Invalid hash length"
			putString hash

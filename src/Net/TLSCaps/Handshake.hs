
module Net.TLSCaps.Handshake
	( Handshake(..)
	, SignatureAndHashAlgorithm(..)
	, Extension(..)
	, parseHandshake
	, writeHandshake
	) where


import Data.Word (Word8, Word16)
import qualified Data.ByteString.Lazy as B

import Net.TLSCaps.Stream
import Net.TLSCaps.Utils
import Net.TLSCaps.EnumTexts
import Net.TLSCaps.CipherSuites

import qualified Control.Monad as M
import Control.Monad (when)
import Control.Monad.State (StateT, evalStateT, execStateT)

import Data.List (intercalate)

data Extension = Extension Word16 B.ByteString deriving (Eq)
data Cert = Cert B.ByteString deriving (Eq)

data SignatureAndHashAlgorithm = SignatureAndHashAlgorithm { sahaHash, sahaSignature :: Word8 } deriving (Eq)

instance Show Extension where
	show (Extension t d) = "Extension " ++ show t ++ " " ++ show (B.unpack d)

instance Show Cert where
	show (Cert c) = "Cert " ++ decodeDER_ASN1 c

instance Show SignatureAndHashAlgorithm where
	show (SignatureAndHashAlgorithm hash sig) = "(" ++ hashAlgorithmText hash ++ "," ++ signatureAlgorithmText sig ++ ")"

data Handshake = HelloRequest
	| ClientHello { hChClientVersion :: Word16, hChRandom :: B.ByteString, hChSessionId :: B.ByteString, hChCipherSuites :: [Word16], hChCompressionMethods :: [Word8], hChExtensions :: [Extension] }
	| ServerHello { hShServerVersion :: Word16, hShRandom :: B.ByteString, hShSessionId :: B.ByteString, hShCipherSuite :: Word16, hShCompressionMethod :: Word8, hShExtensions :: [Extension] }
	| Certificate [Cert]
	| ServerKeyExchange B.ByteString -- format depends on key exch algorithm
	| CertificateRequest { hCrCertificateTypes :: [Word8], hCrAlgorithms :: [SignatureAndHashAlgorithm], hCrCertificateAuthorities :: [B.ByteString] }
	| ServerHelloDone
	| CertificateVerify B.ByteString -- signature
	| ClientKeyExchange B.ByteString -- format depends on key exch algorithm
	| Finished B.ByteString -- verify data
	deriving (Eq)

showDN :: B.ByteString -> String
showDN dn = "DN " ++ decodeDER_ASN1 dn

instance Show Handshake where
	show (HelloRequest) = "HelloRequest"
	show (ClientHello ver rand sess suites comps exts) = "ClientHello (" ++ versionText ver ++ ", Random [" ++ hexS rand ++ "], SessionID [" ++ hexS sess ++ "], CipherSuites [" ++ (intercalate "," $ map cipherText suites) ++ "], CompressionMethods [" ++ (intercalate "," $ map compressionMethodText comps) ++ "], Extensions " ++ show exts ++ ")"
	show (ServerHello ver rand sess suite comp exts) = "ServerHello (" ++ versionText ver ++ ", Random [" ++ hexS rand ++ "], SessionID[" ++ hexS sess ++ "], " ++ cipherText suite ++ ", " ++ compressionMethodText comp ++ ", Extensions " ++ show exts ++ ")"
	show (Certificate certs) = "Certificates " ++ show certs
	show (ServerKeyExchange _) = "ServerKeyExchange [...]"
	show (CertificateRequest types algs cas) = "CertificateRequest (Certificate Types [" ++ (intercalate "," $ map clientCertificateTypeDesc types) ++ "], Supported Algorithms " ++ show algs ++ ", CAs [" ++ (intercalate "," $ map showDN cas) ++ "])"
	show (ServerHelloDone) = "ServerHelloDone"
	show (CertificateVerify _) = "CertificateVerify [...]"
	show (ClientKeyExchange _) = "ClientKeyExchange [...]"
	show (Finished _) = "Finished [...]"

parseHandshake :: Monad m => Word16 -> Word8 -> B.ByteString -> m Handshake
parseHandshake ver ht hdata = evalStateT select hdata
	where
		select
			| ht == ht_hello_request = parseHelloRequest
			| ht == ht_client_hello = parseClientHello
			| ht == ht_server_hello = parseServerHello
-- 			| ht == ht_hello_verify_request
-- 			| ht == ht_new_session_ticket
			| ht == ht_certificate = parseCertificate
			| ht == ht_server_key_exchange = return $ ServerKeyExchange hdata
			| ht == ht_certificate_request = parseCertificateRequest ver
			| ht == ht_server_hello_done = parseServerHelloDone
			| ht == ht_certificate_verify = return $ CertificateVerify hdata
			| ht == ht_client_key_exchange = return $ ClientKeyExchange hdata
			| ht == ht_finished = return $ Finished hdata
-- 			| ht == ht_certificate_url
-- 			| ht == ht_certificate_status
-- 			| ht == ht_supplemental_data
			| otherwise = fail ("Cannot parse handshake type: " ++ handshakeTypeDesc ht)

handshakeType :: Handshake -> Word8
handshakeType handshake = case handshake of
	HelloRequest -> ht_hello_request
	ClientHello _ _ _ _ _ _ -> ht_client_hello
	ServerHello _ _ _ _ _ _ -> ht_server_hello
	Certificate _ -> ht_certificate
	ServerKeyExchange _ -> ht_server_key_exchange
	CertificateRequest _ _ _ -> ht_certificate_request
	ServerHelloDone -> ht_server_hello_done
	CertificateVerify _ -> ht_certificate_verify
	ClientKeyExchange _ -> ht_client_key_exchange
	Finished _ -> ht_finished


writeHandshake :: Monad m => Word16 -> Handshake -> m (Word8, B.ByteString)
writeHandshake ver handshake = do
	d <- execStateT (putHandshake ver handshake) B.empty
	return (handshakeType handshake, d)

putRandom :: OutputStream s m => B.ByteString -> StateT s m ()
putRandom rnd = do
	when (32 /= B.length rnd) $ fail ("Random isn't 32 bytes long")
	putString rnd

putSession :: OutputStream s m => B.ByteString -> StateT s m ()
putSession session = do
	when (32 < B.length session) $ fail ("SessionID too long")
	putByte (fromIntegral $ B.length session)
	putString session

putExtensions :: OutputStream s m => [Extension] -> StateT s m ()
putExtensions exts = when (exts /= []) $ do
		d <- execStateT (mapM_ (\(Extension t d) -> do
				putWord16 t
				when (B.length d >= 65536) $ fail ("Extension too large")
				putWord16 (fromIntegral $ B.length d)
				putString d
			) exts) B.empty
		when (B.length d >= 65536) $ fail ("Extensions too large")
		putWord16 (fromIntegral $ B.length d)
		putString d

putSignatureAndHashAlgorithms :: OutputStream s m => [SignatureAndHashAlgorithm] -> StateT s m ()
putSignatureAndHashAlgorithms algs = do
	when (length algs >= 32768) $ fail "Too many signature and hash algorithms"
	putWord16 (fromIntegral $ 2 * length algs)
	mapM_ (\(SignatureAndHashAlgorithm hash sig) -> putBytes [hash, sig]) algs

putHandshake :: OutputStream s m => Word16 -> Handshake -> StateT s m ()
putHandshake hver handshake = case handshake of
	HelloRequest -> return ()
	ClientHello ver random session ciphers comps exts -> do
		putWord16 ver
		putRandom random
		putSession session
		when (length ciphers >= 32768) $ fail ("Too many ciphers")
		putWord16 (fromIntegral $ 2 * length ciphers)
		mapM_ putWord16 ciphers
		when (length comps >= 256) $ fail ("Too many compression methods")
		putByte (fromIntegral $ length comps)
		mapM_ putByte comps
		putExtensions exts
	ServerHello ver random session cipher comp exts -> do
		putWord16 ver
		putRandom random
		putSession session
		putWord16 cipher
		putByte comp
		putExtensions exts
	Certificate certs -> do
		d <- execStateT (mapM_ (\(Cert d) -> do
				when (B.length d >= 2^(24::Int)) $ fail ("Certificate too large")
				putBytes (netEncode 3 $ B.length d)
				putString d
			) certs) B.empty
		when (B.length d >= 2^(24::Int)) $ fail ("Certificates too large")
		putBytes (netEncode 3 $ B.length d)
		putString d
	ServerKeyExchange exch -> putString exch
	CertificateRequest types algs cas -> do
		when (length types >= 256) $ fail ("Too many client certificate types")
		putByte $ fromIntegral $ length types
		mapM_ putByte types
		if (hver >= rv_tls1_2)
			then putSignatureAndHashAlgorithms algs
			else when (algs /= []) $ fail ("Signature and hash algorithms not usable in version " ++ versionText hver)
		d <- execStateT (mapM_ (\d -> do
				when (B.length d >= 65536) $ fail ("Distinguished name too long")
				putWord16 (fromIntegral $ B.length d)
				putString d
			) cas) B.empty
		when (B.length d >= 65536) $ fail ("Certificate authorities too large")
		putWord16 (fromIntegral $ B.length d)
		putString d
	ServerHelloDone -> return ()
	CertificateVerify sig -> putString sig
	ClientKeyExchange exch -> putString exch
	Finished verify -> putString verify


whileHasInput :: InputStream s m => StateT s m a -> StateT s m [a]
whileHasInput f = inputAvailable 1 >>= \t -> if (t) then f >>= \e -> whileHasInput f >>= \l -> return (e:l) else return []

parseHelloRequest :: InputStream s m => StateT s m Handshake
parseHelloRequest = do
	hasData <- inputAvailable 1
	when hasData (fail "Hello Request with data")
	return HelloRequest


parseRandom :: InputStream s m => StateT s m B.ByteString
parseRandom = getString 32

parseSessionID :: InputStream s m => StateT s m B.ByteString
parseSessionID = do
	sessionLen <- getByte
	when (sessionLen > 32) $ fail ("Session ID too long: " ++ show sessionLen)
	getString (fromIntegral sessionLen)

parseExtensions :: InputStream s m => StateT s m [Extension]
parseExtensions = whileHasInput $ do
	t <- getWord16
	d <- getWord16 >>= getString . fromIntegral
	return $ Extension t d

parseClientHello :: InputStream s m => StateT s m Handshake
parseClientHello = do
	ver <- getWord16
	random <- parseRandom
	session <- parseSessionID
	ciphersLen <- getWord16
	when (ciphersLen `mod` 2 /= 0) $ fail ("Odd length for ciphers: " ++ show ciphersLen)
	ciphers <- M.replicateM (fromIntegral $ ciphersLen `div` 2) getWord16
	compsLen <- getByte
	comps <- M.replicateM (fromIntegral compsLen) getByte
	hasExts <- inputAvailable 2
	extData <- if (hasExts) then getWord16 >>= getString . fromIntegral else return B.empty
	exts <- evalStateT parseExtensions extData
	hasData <- inputAvailable 1
	when hasData (fail "Client Hello too: large record")
	return $ ClientHello ver random session ciphers comps exts

parseServerHello :: InputStream s m => StateT s m Handshake
parseServerHello = do
	ver <- getWord16
	random <- parseRandom
	session <- parseSessionID
	cipher <- getWord16
	comp <- getByte
	hasExts <- inputAvailable 2
	extData <- if (hasExts) then getWord16 >>= getString . fromIntegral else return B.empty
	exts <- evalStateT parseExtensions extData
	hasData <- inputAvailable 1
	when hasData (fail "Server Hello: too large record")
	return $ ServerHello ver random session cipher comp exts

parseCerts :: InputStream s m => StateT s m [Cert]
parseCerts = whileHasInput $ do
	len <- getBytes 3 >>= return . netDecode 3
	cert <- getString len
	return $ Cert cert

parseCertificate :: InputStream s m => StateT s m Handshake
parseCertificate = do
	len <- getBytes 3 >>= return . netDecode 3
	certsData <- getString len
	certs <- evalStateT parseCerts certsData
	hasData <- inputAvailable 1
	when hasData (fail "Certificate: too large record")
	return $ Certificate certs

parseSignatureAndHashAlgorithm :: InputStream s m => StateT s m SignatureAndHashAlgorithm
parseSignatureAndHashAlgorithm = do
	hash <- getByte; sig <- getByte
	return $ SignatureAndHashAlgorithm hash sig

parseSignatureAndHashAlgorithms :: InputStream s m => StateT s m [SignatureAndHashAlgorithm]
parseSignatureAndHashAlgorithms = do
	len <- getWord16
	when (len `mod` 2 /= 0) $ fail ("Odd length for signature and hash algorithms: " ++ show len)
	M.replicateM (fromIntegral $ len `div` 2) parseSignatureAndHashAlgorithm

parseCertificateRequest :: InputStream s m => Word16 -> StateT s m Handshake
parseCertificateRequest ver = do
		types <- getByte >>= getBytes . fromIntegral
		algs <- if (ver >= rv_tls1_2) then parseSignatureAndHashAlgorithms else return []
		authoritiesData <- getWord16 >>= getString . fromIntegral
		hasData <- inputAvailable 1
		when hasData (fail "Certificate Request: too large record")
		authorities <- evalStateT readDNs authoritiesData
		return $ CertificateRequest types algs authorities
	where
		readDNs = whileHasInput $ getWord16 >>= getString . fromIntegral

parseServerHelloDone :: InputStream s m => StateT s m Handshake
parseServerHelloDone = do
	hasData <- inputAvailable 1
	when hasData (fail "Server Hello Done with data")
	return ServerHelloDone
{-# LANGUAGE ExistentialQuantification,RankNTypes #-}

module Net.TLSCaps.Record
	( StreamTransformer(..)
	, StreamTransformOut
	, StreamTransformIn
	, Message(..)
	, TLSState(..)
	, Handshake(..)
	, emptyState
	, tlsReceived
	, tlsSend
	, tlsSendHandshake
	, _tlsRecv
	, tlsRecv
	, testRecv
	) where

import Data.Word (Word8, Word16)
import qualified Data.ByteString.Lazy as B
import Data.Int (Int64)

import qualified Control.Monad as M
import Control.Monad (when)
import Control.Monad.State (StateT, get, gets, put, modify, evalStateT)
import Control.Monad.Trans.Class (lift)

import qualified System.IO as IO


import qualified Net.TLSCaps.Stream as Stream
import Net.TLSCaps.Handshake
import Net.TLSCaps.Utils
import Net.TLSCaps.EnumTexts

type StreamTransformOut s = forall m. Monad m => s -> B.ByteString -> StateT TLSState m [B.ByteString]
type StreamTransformIn s = forall m. Monad m => s -> B.ByteString -> StateT TLSState m B.ByteString
data StreamTransformer = forall s. StreamTransformer { rtState :: s, rtTransIn :: StreamTransformIn s, rtTransOut :: StreamTransformOut s }

_fragments :: Int -> B.ByteString -> [B.ByteString]
_fragments n s = if (B.length s > (fromIntegral n)) then let (a,b) = B.splitAt (fromIntegral n) s in a:_fragments n b else [s]

data Message = ChangeCipherSpec | Alert Word8 Word8 | Handshake Word16 Word8 B.ByteString | AppData B.ByteString deriving (Eq)

data ErrorMonad x = Result x | Error String
instance  Monad ErrorMonad  where
    (Result x) >>= k  = k x
    (Error s)  >>= _  = Error s
    (Result _) >> k   = k
    (Error s) >> _    = Error s
    return            = Result
    fail              = Error


instance Show Message where
	show (ChangeCipherSpec) = "ChangeCipherSpec"
	show (Alert lvl alert) = "Alert (" ++ show lvl ++ "," ++ show alert ++ ")"
	show (Handshake ver t h) = case parseHandshake ver t h of
		Result handshake -> "Handshake " ++ show handshake
		Error err -> err ++ ": Handshake[" ++ versionText ver ++ "] " ++ handshakeTypeDesc t ++ " (" ++ hexS h ++ ")"
	show (AppData d) = "AppData (" ++ show d ++ ")"

msg_code :: Message -> Word8
msg_code (ChangeCipherSpec) = rt_change_cipher_spec
msg_code (Alert _ _) = rt_alert
msg_code (Handshake _ _ _) = rt_handshake
msg_code (AppData _) = rt_application_data

-- only serialiaze the data part, no header
msg_serialize :: Message -> B.ByteString
msg_serialize (ChangeCipherSpec) = B.pack [1]
msg_serialize (Alert lvl alert) = B.pack [lvl,alert]
msg_serialize (Handshake _ t h) = B.append (B.pack $ t:Stream.netEncode 3 (B.length h)) h
msg_serialize (AppData d) = d

data TLSState = TLSState { tsStreamAlert, tsStreamHandshake, tsStreamIn, tsStreamOut :: B.ByteString, tsTransform :: StreamTransformer, tsVersion :: Word16, tsLastReceivedVersion :: Word16, tsMessagesIn :: [Message] }

dummyTransformer :: StreamTransformer
dummyTransformer = StreamTransformer () (\_ r -> return r) (\_ r -> return $ _fragments (2^(14::Int)) r)
emptyState :: TLSState
emptyState = TLSState { tsStreamAlert = B.empty, tsStreamHandshake = B.empty, tsStreamIn = B.empty, tsStreamOut = B.empty, tsTransform = dummyTransformer, tsVersion = rv_tls1_0, tsLastReceivedVersion = 0, tsMessagesIn = [] }

tlsTranformIn :: Monad m => B.ByteString -> StateT TLSState m B.ByteString
tlsTranformIn r = do
	state <- get
	case tsTransform state of StreamTransformer s f _ -> f s r

tlsTranformOut :: Monad m => B.ByteString -> StateT TLSState m [B.ByteString]
tlsTranformOut r = do
	state <- get
	case tsTransform state of StreamTransformer s _ f -> f s r

tlsReceived :: Monad m => B.ByteString -> StateT TLSState m ()
tlsReceived d = do
	state <- get
	put $ state { tsStreamIn = B.append (tsStreamIn state) d }
	_tlsDecode

__tlsSend :: Monad m => Word8 -> Word16 -> B.ByteString -> StateT TLSState m ()
__tlsSend rtyp rver d = do
	fragments <- tlsTranformOut d
	let rhead = B.pack (rtyp:Stream.netEncode 2 rver)
	let buf = B.concat $ concat $ map (\f -> [rhead, B.pack $ Stream.netEncode 2 (B.length f), f]) fragments
	modify $ \state -> state { tsStreamOut = B.append (tsStreamOut state) buf }

_tlsSend :: Monad m => Message -> StateT TLSState m ()
_tlsSend msg = do
	state <- get
	__tlsSend (msg_code msg) (tsVersion state) (msg_serialize msg)
	-- todo: show to tranformer. store for debug?

tlsSend :: Monad m => B.ByteString -> StateT TLSState m ()
tlsSend msg = _tlsSend $ AppData msg

tlsSendHandshake :: Monad m => Handshake -> StateT TLSState m ()
tlsSendHandshake handshake = do
	hver <- gets tsVersion
	(t, h) <- writeHandshake hver handshake
	_tlsSend $ Handshake hver t h

_tlsRecv :: Monad m => StateT TLSState m (Maybe Message)
_tlsRecv = do
	state <- get
	case (tsMessagesIn state) of
		msg:l -> put (state { tsMessagesIn = l }) >> return (Just msg)
		_ -> return Nothing

-- drop non AppData messages
tlsRecv :: Monad m => StateT TLSState m B.ByteString
tlsRecv = do
	mmsg <- _tlsRecv
	case mmsg of
		Just msg -> case msg of
			AppData d -> return d
			_ -> tlsRecv -- next message
		Nothing -> return B.empty

_tlsAlert :: Monad m => Word8 -> Word8 -> StateT TLSState m ()
_tlsAlert lvl alert = _tlsSend $ Alert lvl alert

_tlsPutInMessage :: Monad m => Message -> StateT TLSState m ()
_tlsPutInMessage msg = do
	state <- get
	put $ state { tsMessagesIn = tsMessagesIn state ++ [msg] }
	-- todo: show to transformer

_tlsDecode :: Monad m => StateT TLSState m ()
_tlsDecode = do
		stream <- gets tsStreamIn
		M.when (B.length stream >= 5) $ do
			let [rtyp, rvmaj, rvmin, lHigh, lLow] = B.unpack $ B.take 5 stream
			let len = Stream.netDecode 2 [lHigh, lLow] :: Int64
			M.when (B.length stream >= (5 + len)) $ do
				let rver = Stream.netDecode 2 [rvmaj, rvmin] :: Word16
				modify $ \state -> state { tsStreamIn = B.drop (5 + len) stream, tsLastReceivedVersion = rver }
				fragment <- tlsTranformIn (B.take len (B.drop 5 stream))
				handle rtyp rver fragment
				_tlsDecode -- loop
	where
		handle rtyp _ fragment
			| rtyp == rt_change_cipher_spec = handle_csc fragment
			| rtyp == rt_alert = handle_alert fragment
			| rtyp == rt_handshake = handle_handshake fragment
			| rtyp == rt_application_data = handle_appdata fragment
			| otherwise = _tlsAlert al_fatal ad_decode_error >> fail ("Unknown content type: " ++ show rtyp)
		handle_csc fragment = do
			when (fragment /= B.pack [1]) $ _tlsAlert al_fatal ad_decode_error >> fail ("Unexpected Change Cipher Spec data")
			_tlsPutInMessage ChangeCipherSpec
		handle_alert fragment = do
			when (B.length fragment == 0) $ _tlsAlert al_fatal ad_decode_error >> fail ("Empty alert fragment")
			modify $ \state -> state { tsStreamAlert = B.append (tsStreamAlert state) fragment }
			_tlsDecodeAlerts
		handle_handshake fragment = do
			when (B.length fragment == 0) $ _tlsAlert al_fatal ad_decode_error >> fail ("Empty handshake fragment")
			modify $ \state -> state { tsStreamHandshake = B.append (tsStreamHandshake state) fragment }
			_tlsDecodeHandshakes
		handle_appdata fragment = do
			when (B.length fragment > 0) $ _tlsPutInMessage $ AppData fragment

_tlsDecodeAlerts :: Monad m => StateT TLSState m ()
_tlsDecodeAlerts = do
		buf <- gets tsStreamAlert
		let (alerts, back) = decode $ B.unpack buf
		modify $ \state -> state { tsStreamAlert = B.pack back }
		-- todo: process alerts for internal state
		mapM_ _tlsPutInMessage alerts
	where
		decode :: [Word8] -> ([Message], [Word8])
		decode (a:b:l) = let (x,y) = decode l in (Alert a b:x, y)
		decode x = ([], x)

_tlsDecodeHandshakes :: Monad m => StateT TLSState m ()
_tlsDecodeHandshakes = do
	stream <- gets tsStreamHandshake
	M.when (B.length stream >= 4) $ do
		let htype:hlen = B.unpack $ B.take 4 stream
		let len = Stream.netDecode 3 hlen :: Int64
		M.when (B.length stream >= (4 + len)) $ do
			modify $ \state -> state { tsStreamHandshake = B.drop (4 + len) stream }
			curVer <- gets tsLastReceivedVersion
			let handshake = B.take len (B.drop 4 stream)
			_tlsPutInMessage $ Handshake curVer htype handshake
			_tlsDecodeHandshakes -- loop

testRecv :: B.ByteString -> IO.IO ()
testRecv buf = do
		let state = emptyState
		flip evalStateT state (tlsReceived buf >> go)
		return ()
	where
		go :: StateT TLSState IO ()
		go = do
			msg <- _tlsRecv
			case msg of
				Just x -> lift (putStrLn $ show x) >> go
				Nothing -> return ()

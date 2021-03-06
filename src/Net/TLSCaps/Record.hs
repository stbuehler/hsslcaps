{-# LANGUAGE ExistentialQuantification,RankNTypes #-}

module Net.TLSCaps.Record
	( StreamTransformer(..)
	, StreamTransformOut
	, StreamTransformIn
	, Message(..)
	, TLSIOState(..)
	, TLSState(..)
	, Handshake(..)
	, Extension(..)
	, emptyState
	, tlsReceived
	, tlsSend
	, tlsSendHandshake
	, tlsKill
	, tlsClose
	, tlsCloseWithAlert
	, _tlsRecv
	, tlsRecv
	, whenTLSOpen
	, tlsProcess
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


import qualified Net.TLSCaps.Serialize as Serialize
import Net.TLSCaps.Handshake
import Net.TLSCaps.Utils
import Net.TLSCaps.EnumTexts

type StreamTransformOut s = forall m. Monad m => s -> B.ByteString -> StateT TLSState m [B.ByteString]
type StreamTransformIn s = forall m. Monad m => s -> B.ByteString -> StateT TLSState m B.ByteString
data StreamTransformer = forall s. StreamTransformer { rtState :: s, rtTransIn :: StreamTransformIn s, rtTransOut :: StreamTransformOut s }

data TLSIOState = TLS_Open | TLS_Closed | TLS_Killed deriving (Show, Eq)

-- tsTraceMessages contains recent messages in front; True: in, False: out
data TLSState = TLSState
	{ tsStreamAlert, tsStreamHandshake, tsStreamIn, tsStreamOut :: B.ByteString
	, tsCurrentHandshakeInMessages :: [Message]
	, tsCurrentHandshakeInData, tsCurrentHandshakeOutData :: B.ByteString
	, tsTransform :: StreamTransformer
	, tsVersion :: TLSVersion
	, tsLastReceivedVersion :: TLSVersion
	, tsMessagesIn :: [Message]
	, tsState :: TLSIOState
	, tsTraceMessages :: Maybe [(Bool,Message)]
	}

_fragments :: Int -> B.ByteString -> [B.ByteString]
_fragments n s = if (B.length s > (fromIntegral n)) then let (a,b) = B.splitAt (fromIntegral n) s in a:_fragments n b else [s]

data Message = ChangeCipherSpec | Alert TLSAlertLevel TLSAlertDescription | Handshake TLSVersion TLSHandshakeType B.ByteString | AppData B.ByteString deriving (Eq)


instance Show Message where
	show (ChangeCipherSpec) = "ChangeCipherSpec"
	show (Alert lvl alert) = "Alert " ++ show (lvl, alert)
	show (Handshake ver t h) = case parseHandshake ver t h of
		Result handshake -> "Handshake " ++ show handshake
		Error err -> err ++ ": Handshake[" ++ show ver ++ "] " ++ show t ++ " (" ++ hexS h ++ ")"
	show (AppData d) = "AppData (" ++ show d ++ ")"

msg_code :: Message -> Word8
msg_code (ChangeCipherSpec) = fromTLSRecordType $ TLS_RT_ChangeCipherSpec
msg_code (Alert _ _) = fromTLSRecordType $ TLS_RT_Alert
msg_code (Handshake _ _ _) = fromTLSRecordType $ TLS_RT_Handshake
msg_code (AppData _) = fromTLSRecordType $ TLS_RT_ApplicationData

-- only serialiaze the data part, no header
msg_serialize :: Message -> B.ByteString
msg_serialize (ChangeCipherSpec) = B.pack [1]
msg_serialize (Alert lvl alert) = B.pack [fromTLSAlertLevel lvl, fromTLSAlertDescription alert]
msg_serialize (Handshake _ t h) = B.append (B.pack $ fromTLSHandshakeType t:Serialize.netEncode 3 (B.length h)) h
msg_serialize (AppData d) = d

dummyTransformer :: StreamTransformer
dummyTransformer = StreamTransformer () (\_ r -> return r) (\_ r -> return $ _fragments (2^(14::Int)) r)
emptyState :: TLSState
emptyState = TLSState
	{ tsStreamAlert = B.empty, tsStreamHandshake = B.empty, tsStreamIn = B.empty, tsStreamOut = B.empty
	, tsCurrentHandshakeInMessages = [], tsCurrentHandshakeInData = B.empty, tsCurrentHandshakeOutData = B.empty
	, tsTransform = dummyTransformer
	, tsVersion = TLS1_0
	, tsLastReceivedVersion = toEnum 0
	, tsMessagesIn = []
	, tsState = TLS_Open
	, tsTraceMessages = Nothing }

whenTLSOpen :: Monad m => StateT TLSState m () -> StateT TLSState m ()
whenTLSOpen f = gets tsState >>= \s -> when (s == TLS_Open) f

tlsTranformIn :: Monad m => B.ByteString -> StateT TLSState m B.ByteString
tlsTranformIn r = do
	state <- get
	case tsTransform state of StreamTransformer s f _ -> f s r

tlsTranformOut :: Monad m => B.ByteString -> StateT TLSState m [B.ByteString]
tlsTranformOut r = do
	state <- get
	case tsTransform state of StreamTransformer s _ f -> f s r

tlsReceived :: Monad m => B.ByteString -> StateT TLSState m ()
tlsReceived d = whenTLSOpen $ do
	state <- get
	put $ state { tsStreamIn = B.append (tsStreamIn state) d }
	_tlsDecode

__tlsSend :: Monad m => Word8 -> TLSVersion -> B.ByteString -> StateT TLSState m ()
__tlsSend rtyp rver d = whenTLSOpen $ do
	fragments <- tlsTranformOut d
	let rhead = B.pack (rtyp:Serialize.netEncode 2 (fromTLSVersion rver))
	let buf = B.concat $ concat $ map (\f -> [rhead, B.pack $ Serialize.netEncode 2 (B.length f), f]) fragments
	modify $ \state -> state { tsStreamOut = B.append (tsStreamOut state) buf }

_tlsSend :: Monad m => Message -> StateT TLSState m ()
_tlsSend msg = whenTLSOpen $ do
	state <- get
	case (tsTraceMessages state) of
		Nothing -> return ()
		Just msgs -> put $ state { tsTraceMessages = Just $ (False,msg):msgs }
	__tlsSend (msg_code msg) (tsVersion state) (msg_serialize msg)
	-- todo: show to tranformer. store for debug?

-- sends no alert, 
tlsKill :: Monad m => StateT TLSState m ()
tlsKill = modify $ \state -> state { tsStreamAlert = B.empty, tsStreamHandshake = B.empty, tsStreamIn = B.empty, tsStreamOut = B.empty, tsMessagesIn = [], tsState = TLS_Killed }

tlsClose :: Monad m => StateT TLSState m ()
tlsClose = tlsCloseWithAlert TLS_Warning TLS_Alert_close_notify

tlsCloseWithAlert :: Monad m => TLSAlertLevel -> TLSAlertDescription -> StateT TLSState m ()
tlsCloseWithAlert lvl alert = whenTLSOpen $ do
	_tlsSend (Alert lvl alert)
	modify $ \state -> state { tsStreamAlert = B.empty, tsStreamHandshake = B.empty, tsStreamIn = B.empty, tsMessagesIn = [], tsState = TLS_Closed }


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
			_ -> tlsProcess msg >> tlsRecv -- next message
		Nothing -> return B.empty

_tlsAlert :: Monad m => TLSAlertLevel -> TLSAlertDescription -> StateT TLSState m ()
_tlsAlert lvl alert = _tlsSend $ Alert lvl alert

_tlsPutInMessage :: Monad m => Message -> StateT TLSState m ()
_tlsPutInMessage msg = whenTLSOpen $ do
	state <- get
	let nmsgs = case (tsTraceMessages state) of
		Nothing -> Nothing
		Just msgs -> Just $ (True,msg):msgs
	put $ state { tsMessagesIn = tsMessagesIn state ++ [msg], tsTraceMessages = nmsgs }
	-- todo: show to transformer
	tlsProcessAlways msg

_tlsDecode :: Monad m => StateT TLSState m ()
_tlsDecode = do
		stream <- gets tsStreamIn
		M.when (B.length stream >= 5) $ do
			let [rtyp, rvmaj, rvmin, lHigh, lLow] = B.unpack $ B.take 5 stream
			let len = Serialize.netDecode 2 [lHigh, lLow] :: Int64
			M.when (B.length stream >= (5 + len)) $ do
				let rver = Serialize.netDecode 2 [rvmaj, rvmin] :: Word16
				modify $ \state -> state { tsStreamIn = B.drop (5 + len) stream, tsLastReceivedVersion = toTLSVersion rver }
				fragment <- tlsTranformIn (B.take len (B.drop 5 stream))
				handle (toTLSRecordType rtyp) fragment
				_tlsDecode -- loop
	where
		handle TLS_RT_ChangeCipherSpec fragment = do
			when (fragment /= B.pack [1]) $ _tlsAlert TLS_Fatal TLS_Alert_decode_error >> fail ("Unexpected Change Cipher Spec data")
			_tlsPutInMessage ChangeCipherSpec
		handle TLS_RT_Alert fragment = do
			when (B.length fragment == 0) $ _tlsAlert TLS_Fatal TLS_Alert_decode_error >> fail ("Empty alert fragment")
			modify $ \state -> state { tsStreamAlert = B.append (tsStreamAlert state) fragment }
			_tlsDecodeAlerts
		handle TLS_RT_Handshake fragment = do
			when (B.length fragment == 0) $ _tlsAlert TLS_Fatal TLS_Alert_decode_error >> fail ("Empty handshake fragment")
			modify $ \state -> state { tsStreamHandshake = B.append (tsStreamHandshake state) fragment }
			_tlsDecodeHandshakes
		handle TLS_RT_ApplicationData fragment = do
			when (B.length fragment > 0) $ _tlsPutInMessage $ AppData fragment
		handle rtyp _ = _tlsAlert TLS_Fatal TLS_Alert_decode_error >> fail ("Unknown content type: " ++ show rtyp)

_tlsDecodeAlerts :: Monad m => StateT TLSState m ()
_tlsDecodeAlerts = do
		buf <- gets tsStreamAlert
		let (alerts, back) = decode $ B.unpack buf
		modify $ \state -> state { tsStreamAlert = B.pack back }
		-- todo: process alerts for internal state
		mapM_ _tlsPutInMessage alerts
	where
		decode :: [Word8] -> ([Message], [Word8])
		decode (a:b:l) = let (x,y) = decode l in (Alert (toTLSAlertLevel a) (toTLSAlertDescription b):x, y)
		decode x = ([], x)

_tlsDecodeHandshakes :: Monad m => StateT TLSState m ()
_tlsDecodeHandshakes = whenTLSOpen $ do
	stream <- gets tsStreamHandshake
	M.when (B.length stream >= 4) $ do
		let htype:hlen = B.unpack $ B.take 4 stream
		let len = Serialize.netDecode 3 hlen :: Int64
		M.when (B.length stream >= (4 + len)) $ do
			modify $ \state -> state { tsStreamHandshake = B.drop (4 + len) stream }
			curVer <- gets tsLastReceivedVersion
			let handshake = B.take len (B.drop 4 stream)
			_tlsPutInMessage $ Handshake curVer (toTLSHandshakeType htype) handshake
			_tlsDecodeHandshakes -- loop

-- run this always before returning message to the user
-- only passive stuff, don't send anything
tlsProcessAlways :: Monad m => Message -> StateT TLSState m ()
tlsProcessAlways msg = case msg of
	Alert lvl _ -> do
		when (lvl == TLS_Fatal) tlsKill
	Handshake ver t h -> case parseHandshake ver t h of
		Result (ServerHello shver _ _ _ _ _) -> do
			modify $ \state -> state { tsVersion = shver }
		_ -> return ()
	_ -> return ()

-- run this if the user doesn't want to see it
-- or run manually by user to apply default action
tlsProcess :: Monad m => Message -> StateT TLSState m ()
tlsProcess msg = case msg of
	Alert _ _ -> do
		tlsClose
		error (show msg)
	Handshake ver t h -> case parseHandshake ver t h of
		Result _ -> return ()
		Error _ -> tlsKill -- err
	_ -> return ()



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

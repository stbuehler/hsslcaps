{-# LANGUAGE DeriveDataTypeable
           , MultiParamTypeClasses
           , FlexibleInstances
  #-}

module Net.TLSCaps.TLSStream
	(tlsStart
	, TLSRecvMessage
	) where

import Data.IORef

import Control.Monad (when, unless)
import Control.Monad.Fix (mfix)
import Control.Concurrent.MVar
import qualified Data.ByteString.Lazy as B
import Control.Exception (throwIO, SomeException)

import Net.TLSCaps.StreamParser
import Net.TLSCaps.Handshake
import Net.TLSCaps.Utils (netDecode)
import Net.TLSCaps.Stream
import Net.TLSCaps.EnumTexts




data TLSStream = TLSStream { tlsStreamParserState :: TLSStreamParserState }
type TLSStreamType = BidirectionalStream B.ByteString (TLSVersion, TLSRecvMessage) B.ByteString B.ByteString

tlsStreamAbort :: TLSStreamType -> TLSStream -> SomeException -> IO ()
tlsStreamAbort b _ e = do
	-- TODO: send alert
	streamAbort (streamUp b) e
	streamAbort (streamDown b) e
	throwIO e

instance IBiStream TLSStream B.ByteString (TLSVersion, TLSRecvMessage) B.ByteString B.ByteString where
	sUpReceive b tls str = do
		writeIORef (_tlsPushMessage $ tlsStreamParserState tls) $ \msg -> streamWrite (streamUp b) (Just msg)
		tlsDecode (tlsStreamParserState tls) str
		-- TODO: streamWrite Nothing if closed
	sUpReceiveAbort = tlsStreamAbort
	sUpSendAbort = tlsStreamAbort
	sDownReceive b _ str = streamWrite (streamDown b) str
	sDownReceiveAbort = tlsStreamAbort
	sDownSendAbort = tlsStreamAbort

tlsStart :: IO TLSStreamType
tlsStart = do
	parser <- tlsStartStreamParser
	let tls = TLSStream parser
	startBiStream tls












data TLSRecvMessage = TLSRecvMessage_AppData B.ByteString | TLSRecvMessage_ChangeCipherSpec | TLSRecvMessage_Handshake Handshake | TLSRecvMessage_Alert TLSAlertLevel TLSAlertDescription deriving (Show)

data TLSRecvState = TLSRecvState_Starting | TLSRecvState_ChangedCipherSpec | TLSRecvState_Running | TLSRecvState_Rehandshake | TLSRecvState_Closed | TLSRecvState_Aborted

data TLSStreamParserState = TLSStreamParserState {
	tlsPStateRecord :: MVar (ByteStreamParserState IO),
	tlsPStateHandshakes :: MVar (ByteStreamParserState IO),
	tlsPStateAlerts :: MVar (ByteStreamParserState IO),
	tlsPStateDecrypt :: MVar (B.ByteString -> IO B.ByteString),
	tlsPStateLastVersion :: IORef TLSVersion,
	_tlsPushMessage :: IORef ((TLSVersion, TLSRecvMessage) -> IO ()),
	tlsPStateRecvState :: IORef TLSRecvState
}


tlsStartStreamParser :: IO TLSStreamParserState
tlsStartStreamParser = (mfix :: (TLSStreamParserState -> IO TLSStreamParserState) -> IO TLSStreamParserState) $ \state -> do
	let pRecord = streamRepeatParser (tlsHandleRecord state) tlsParseRecord
	let pHandshake = streamRepeatParser (tlsHandleHandshake state) tlsParseHandshake
	let pAlert = streamRepeatParser (tlsHandleAlert state) tlsParseAlert
	mPRecord <- newMVar pRecord
	mPHandshake <- newMVar pHandshake
	mPAlert <- newMVar pAlert
	mDecrypt <- newMVar nullDecoder
	vers <- newIORef $ toTLSVersion 0
	push <- newIORef (\_ -> fail $ "No message handler")
	recvState <- newIORef TLSRecvState_Starting
	return $ TLSStreamParserState mPRecord mPHandshake mPAlert mDecrypt vers push recvState

nullDecoder :: B.ByteString -> IO B.ByteString
nullDecoder str = return str


tlsPushMessage :: TLSStreamParserState -> TLSRecvMessage -> IO ()
tlsPushMessage state msg = do
	ver <- readIORef (tlsPStateLastVersion state)
	push <- readIORef (_tlsPushMessage state)
	push (ver, msg)

_tlsDecode :: (TLSStreamParserState -> MVar (ByteStreamParserState IO)) -> TLSStreamParserState -> Maybe B.ByteString -> IO ()
_tlsDecode selector state str = let s = selector state in do
--	putStrLn $ "decoding: " ++ show str
	rdata <- takeMVar s
	rdata' <- streamParserPush rdata str
	putMVar s rdata'

tlsDecode :: TLSStreamParserState -> Maybe B.ByteString -> IO ()
tlsDecode = _tlsDecode tlsPStateRecord



_tlsGotChangeCipherSpec :: TLSStreamParserState -> IO ()
_tlsGotChangeCipherSpec state = do
		_assertEmpty (tlsPStateHandshakes state) "Handshake stream not empty on ChangeCipherSpec"
		_assertEmpty (tlsPStateAlerts state) "Alert stream not empty on ChangeCipherSpec"
		writeIORef (tlsPStateRecvState state) TLSRecvState_ChangedCipherSpec
		tlsPushMessage state $ TLSRecvMessage_ChangeCipherSpec
	where
		_assertEmpty :: MVar (ByteStreamParserState IO) -> String -> IO ()
		_assertEmpty s msg = readMVar s >>= \d -> unless (streamParserEmpty d) $ fail msg


tlsCheckRecordType :: TLSStreamParserState -> TLSRecordType -> IO ()
tlsCheckRecordType state ctype = do
	case ctype of
		TLS_RT_ChangeCipherSpec -> return ()
		TLS_RT_Alert            -> return ()
		TLS_RT_Handshake        -> return ()
		TLS_RT_ApplicationData  -> return ()
		_ -> fail $ "Unknown fragment content type " ++ show ctype
	recvState <- readIORef (tlsPStateRecvState state)
	case (recvState, ctype) of
		(TLSRecvState_Starting         , TLS_RT_ChangeCipherSpec) -> return ()
		(TLSRecvState_Starting         , TLS_RT_Alert           ) -> return ()
		(TLSRecvState_Starting         , TLS_RT_Handshake       ) -> return ()
		(TLSRecvState_Starting         , _                      ) -> fail $ "Application data not allowed before first handshake is finished"
		(TLSRecvState_ChangedCipherSpec, TLS_RT_Handshake       ) -> return ()
		(TLSRecvState_ChangedCipherSpec, _                      ) -> fail "Finished Handshake required after ChangeCipherSpec"
		(TLSRecvState_Running          , _                      ) -> return ()
		(TLSRecvState_Rehandshake      , _                      ) -> return ()
		(TLSRecvState_Closed           , _                      ) -> fail "Received data after closure alert"
		(TLSRecvState_Aborted          , _                      ) -> throwIO DisconnectException

tlsHandleRecord :: TLSStreamParserState -> (TLSRecordType, TLSVersion, B.ByteString) -> IO ()
tlsHandleRecord state (ctype, version, fragment) = do
--	putStrLn $ "handling fragment: " ++ show (recordTypeText ctype, version, fragment)
	writeIORef (tlsPStateLastVersion state) version
	tlsCheckRecordType state ctype
	noDecoder <- isEmptyMVar (tlsPStateDecrypt state)
	when noDecoder $ putStrLn $ "Waiting for new decoder after ChangeCipherSpec"
	decoder <- takeMVar (tlsPStateDecrypt state)
	decodedFragment <- decoder fragment
	when (TLS_RT_ApplicationData /= ctype && B.empty == decodedFragment) $ fail "Empty non application data fragment"
	case ctype of
		TLS_RT_ChangeCipherSpec -> _tlsGotChangeCipherSpec state
		TLS_RT_Alert            -> _tlsDecode tlsPStateAlerts state (Just decodedFragment)
		TLS_RT_Handshake        -> _tlsDecode tlsPStateHandshakes state (Just decodedFragment)
		TLS_RT_ApplicationData  -> tlsPushMessage state $ TLSRecvMessage_AppData decodedFragment -- TODO: make sure first handshake is done
		_ -> fail $ "Unknown fragment content type " ++ show ctype
	when (TLS_RT_ChangeCipherSpec /= ctype) $ putMVar (tlsPStateDecrypt state) decoder -- don't put decoder back on ChangeCipherSpec


tlsParseRecord :: IStreamParser m => m (TLSRecordType, TLSVersion, B.ByteString)
tlsParseRecord = do
	ctype' <- getByte
	let ctype = toTLSRecordType ctype'
	case ctype of
		TLS_RT_ChangeCipherSpec -> return ()
		TLS_RT_Alert            -> return ()
		TLS_RT_Handshake        -> return ()
		TLS_RT_ApplicationData  -> return ()
		_ -> fail $ "Unknown fragment content type " ++ show ctype
	version <- getWord16
	len <- getWord16
	fragment <- getString (fromIntegral $ len)
	return (ctype, toTLSVersion version, fragment)

tlsHandleAlert :: TLSStreamParserState -> (TLSAlertLevel, TLSAlertDescription) -> IO ()
tlsHandleAlert state (level, description) = do
	recvState <- readIORef (tlsPStateRecvState state)
	case recvState of
		TLSRecvState_Closed -> fail "Received data after closure alert"
		TLSRecvState_Aborted -> throwIO DisconnectException
		_ -> return ()
	case (level, description) of
		(TLS_Warning, TLS_Alert_close_notify) -> writeIORef (tlsPStateRecvState state) TLSRecvState_Closed
		(TLS_Warning, _) -> return ()
		(TLS_Fatal, _) -> writeIORef (tlsPStateRecvState state) TLSRecvState_Aborted
		_ -> fail $ "Invalid alert level: " ++ show (level, description)

tlsParseAlert :: IStreamParser m => m (TLSAlertLevel, TLSAlertDescription)
tlsParseAlert = do
	level <- getByte
	description <- getByte
	return (toTLSAlertLevel level, toTLSAlertDescription description)


tlsHandleHandshake :: TLSStreamParserState -> (TLSHandshakeType, B.ByteString) -> IO ()
tlsHandleHandshake state (ht, hdata) = do
	ver <- readIORef (tlsPStateLastVersion state)
	recvState <- readIORef (tlsPStateRecvState state)
	case (recvState, ht) of
		(TLSRecvState_ChangedCipherSpec, TLS_HT_Finished) -> writeIORef (tlsPStateRecvState state) TLSRecvState_Running
		(TLSRecvState_ChangedCipherSpec, _) -> fail "Finished Handshake required after ChangeCipherSpec"
		(_, TLS_HT_Finished) -> fail "Unexpected Finished Handshake"
		(TLSRecvState_Rehandshake, TLS_HT_ClientHello) -> fail "ClientHello while Handshake is already in progress"
		(TLSRecvState_Rehandshake, TLS_HT_ServerHello) -> fail "ServerHello while Handshake is already in progress"
		(TLSRecvState_Running, TLS_HT_ClientHello) -> writeIORef (tlsPStateRecvState state) TLSRecvState_Rehandshake
		(TLSRecvState_Running, TLS_HT_ServerHello) -> writeIORef (tlsPStateRecvState state) TLSRecvState_Rehandshake
		_ -> return ()
	h <- parseHandshake ver ht hdata
	tlsPushMessage state $ TLSRecvMessage_Handshake h

tlsParseHandshake :: IStreamParser m => m (TLSHandshakeType, B.ByteString)
tlsParseHandshake = do
	handshakeType <- getByte
	raw_msglen <- getBytes 3
	let msglen = netDecode 3 raw_msglen :: Int
	msg <- getString msglen
	return (toTLSHandshakeType handshakeType, msg)

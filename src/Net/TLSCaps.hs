{-# LANGUAGE RankNTypes #-}

module Net.TLSCaps
	( Message(..)
	, Handshake(..)
	, TLSState(..)
	, MonadIO
	, liftIO
	, TLSMonad
	, tlsRun
	, tlsRunTrace
	, tlsInitialize
	, tlsDefaultParameters
	, tlsSendHandshake
	, tlsSend
	, tlsProcess
	, tlsClose
	, tlsCloseWithAlert
	, tlsKill
	, connectTo
	, createTLSRandom
	) where

import Net.TLSCaps.Record
import Net.TLSCaps.Utils (createTLSRandom)
import qualified Net.TLSCaps.Parameters as P

import Control.Concurrent

import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy

import qualified Data.ByteString.Lazy as B

import qualified Control.Exception as Exception
import Control.Monad.State (StateT, gets, modify, evalStateT)
import Control.Monad (when, unless)
import Control.Monad.IO.Class



type TLSMonad m a = StateT TLSState m a


_tlsRunTrace :: MonadIO m => Socket -> TLSMonad m () -> TLSMonad m a -> (Message -> TLSMonad m ()) -> ((Bool, Message) -> TLSMonad m ()) -> m a
_tlsRunTrace sock initialize finalize handleMsg traceMsg = flip evalStateT emptyState $ do
		w <- liftIO $ startWriteThread sock
		initialize
		go w
		s <- gets tsState
		case s of
			TLS_Killed -> liftIO $ killWrite w
			_ -> do
				writeTo w
				liftIO $ stopWrite w
		traceMessages
		finalize
	where
		go w = go1 where
			go1 = whenTLSOpen $ do
				traceMessages
				handleMessages
				traceMessages
				go2
			go2 = whenTLSOpen $ do
				writeTo w
				buf <- liftIO $ recv sock (16*1024)
				when (buf == B.empty) $ tlsKill --"Connection closed"
				go3 buf
			go3 buf = whenTLSOpen $ do
				tlsReceived buf
				go1
		writeTo w = do
			out <- gets tsStreamOut
			when (out /= B.empty) $ do
				modify $ \stream -> stream { tsStreamOut = B.empty }
				liftIO $ write w out
		handleMessages = do
			msg <- _tlsRecv
			case msg of
				Just m -> handleMsg m >> handleMessages
				Nothing -> return ()
		traceMessages = do
			msgs <- gets tsTraceMessages
			case msgs of
				Nothing -> return ()
				Just [] -> return ()
				Just x -> do
					modify $ \state -> state { tsTraceMessages = Just [] }
					mapM_ traceMsg $ reverse x

tlsRun :: MonadIO m => Socket -> TLSMonad m () -> TLSMonad m a -> (Message -> TLSMonad m ()) -> m a
tlsRun sock initialize finalize handleMsg = _tlsRunTrace sock initialize finalize handleMsg (const $ return ())

tlsRunTrace :: MonadIO m => Socket -> TLSMonad m () -> TLSMonad m a -> (Message -> TLSMonad m ()) -> ((Bool, Message) -> TLSMonad m ()) -> m a
tlsRunTrace sock initialize = _tlsRunTrace sock ((modify $ \state -> state { tsTraceMessages = Just [] }) >> initialize)

--

tlsDefaultParameters :: P.TLSParameters
tlsDefaultParameters = P.defaultParameters

tlsInitialize :: MonadIO m => P.TLSParameters -> TLSMonad m ()
tlsInitialize params = do
	rnd <- if (B.empty == P.tlsRandom params) then liftIO createTLSRandom else return (P.tlsRandom params)
	modify $ \state -> state { tsVersion = P.tlsMinVersion params }
	tlsSendHandshake $ ClientHello (P.tlsMaxVersion params) rnd (P.tlsSessionID params) (P.tlsCipherSuites params) (P.tlsCompressionMethods params) (P.tlsExtensions params)




-- ******************************
-- write thread for non blocking writes
data WriteThread = WriteThread (MVar (Maybe B.ByteString)) (MVar ())

startWriteThread :: Socket -> IO WriteThread
startWriteThread sock = do
		mvar <- newEmptyMVar
		mvarTerm <- newEmptyMVar
		_ <- forkIO $ run mvar mvarTerm
		return $ WriteThread mvar mvarTerm
	where
		run mvar mvarTerm = go where
			go = do
				mbuf <- takeMVar mvar
				case mbuf of
					Nothing -> putMVar mvarTerm ()
					Just buf -> sendAll sock buf >> go

stopWrite :: WriteThread -> IO ()
stopWrite (WriteThread mvar mvarTerm) = do
	putMVar mvar Nothing
	_ <- takeMVar mvarTerm
	return ()

-- waits until last sendAll finished (if one is pending)
killWrite :: WriteThread -> IO ()
killWrite (WriteThread mvar mvarTerm) = do
		replaceNothing
		_ <- takeMVar mvarTerm
		return ()
	where
		replaceNothing = do
			res <- tryPutMVar mvar Nothing
			unless res $ tryTakeMVar mvar >>= \_ -> replaceNothing

-- not "thread-safe" (apart from interacting with the backend write thread)
write :: WriteThread -> B.ByteString -> IO ()
write t@(WriteThread mvar _) buf = do
	res <- tryPutMVar mvar $ Just buf
	unless res $ tryTakeMVar mvar >>= \content -> case content of
		-- race: someone else could have put something into mvar, destroying order of the byte stream
		Just Nothing -> error "write thread stopped"
		Just (Just c) -> putMVar mvar $ Just $ B.append c buf
		Nothing -> write t buf -- again
-- ******************************


-- ******************************
-- connectTo that returns Socket instead of Handle
firstSuccessful :: [IO a] -> IO a
firstSuccessful [] = error "firstSuccessful: empty list"
firstSuccessful (p:ps) = Exception.catch p $ \e ->
	case ps of
		[] -> Exception.throw (e :: Exception.IOException)
		_  -> firstSuccessful ps

connectTo :: String -> Int -> IO Socket
connectTo host port = do
		let hints = defaultHints { addrFlags = [AI_ADDRCONFIG], addrSocketType = Stream }
		addrs <- getAddrInfo (Just hints) (Just host) (Just $ show port)
		firstSuccessful $ map tryToConnect addrs
	where
		tryToConnect addr = Exception.bracketOnError
			(socket (addrFamily addr) (addrSocketType addr) (addrProtocol addr))
			(sClose)  -- only done if there's an error
			(\sock -> do
				connect sock (addrAddress addr)
				return sock
			)
-- ******************************

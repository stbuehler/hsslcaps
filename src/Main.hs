module Main where

import Net.TLSCaps.Record
import Net.TLSCaps.Utils (createTLSRandom)

import Control.Concurrent

import Network.Socket hiding (send, sendTo, recv, recvFrom)
import Network.Socket.ByteString.Lazy

import qualified Data.ByteString.Lazy as B

import qualified Control.Exception as Exception
import Control.Monad.State (StateT, gets, modify, runStateT)
import Control.Monad (when, forever, unless)
import Control.Monad.IO.Class (liftIO)

import System( getArgs )

tlsHandle :: Message -> StateT TLSState IO ()
tlsHandle _ = return ()

data WriteThread = WriteThread (MVar B.ByteString) ThreadId

startWriteThread :: Socket -> IO WriteThread
startWriteThread sock = do
		mvar <- newEmptyMVar
		tid <- forkIO $ run mvar
		return $ WriteThread mvar tid
	where
		run mvar = forever $ do
			buf <- takeMVar mvar
			sendAll sock buf

-- only call this from one thread
write :: WriteThread -> B.ByteString -> IO ()
write t@(WriteThread mvar _) buf = do
	res <- tryPutMVar mvar buf
	unless res $ tryTakeMVar mvar >>= \content -> case content of
		Just c -> putMVar mvar $ B.append c buf
		Nothing -> write t buf -- again

tlsIO :: Socket -> StateT TLSState IO ()
tlsIO sock = do
		w <- liftIO $ startWriteThread sock
		forever $ do
			handleMessages
			out <- gets tsStreamOut
			when (out /= B.empty) $ do
				modify $ \stream -> stream { tsStreamOut = B.empty }
				liftIO $ write w out
			buf <- liftIO $ recv sock (16*1024)
			when (buf == B.empty) $ fail "Connection closed"
			tlsReceived buf
	where
		handleMessages = do
			msg <- _tlsRecv
			case msg of
				Just m -> tlsHandle m >> handleMessages
				Nothing -> return ()

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


-- data TLSParameters = TLSParameters { pMaxVersion :: Word16, 

tlsStart :: StateT TLSState IO ()
tlsStart = do
-- 	tlsSendHandshake $ HelloRequest
	rnd <- liftIO $ createTLSRandom
	tlsSendHandshake $ ClientHello 0x303 rnd B.empty [0x0005,0x00ff] [0,1] []

main :: IO()
main = do
	(host:_) <- getArgs
	s <- connectTo host 443
	_ <- runStateT (tlsStart >> tlsIO s) emptyState
	return ()

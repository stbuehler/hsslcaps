{-# LANGUAGE ExistentialQuantification
           , DeriveDataTypeable
           , MultiParamTypeClasses
           , Rank2Types
           , FlexibleInstances
  #-}

module Net.TLSCaps.Network
	( connectTo
	, listenTo
	, socketStream
	) where

import Prelude

import qualified Data.ByteString.Lazy as B
import Data.Word (Word16)
import Control.Monad (forever, when)
import Control.Concurrent.MVar (MVar, newEmptyMVar, putMVar, tryTakeMVar)
import Control.Exception (SomeException, throwIO, bracket, bracketOnError, catch, throwTo, onException)
import Control.Concurrent (forkIOWithUnmask, ThreadId)
import qualified Network.Socket as N
import qualified Network.Socket.ByteString.Lazy as NB

import Net.TLSCaps.Stream


data SockStream = SockStream N.Socket (MVar ThreadId)

_closeSockStream :: SockStream -> IO ()
_closeSockStream (SockStream socket tid) = do
	t <- tryTakeMVar tid
	case t of
		Just thread-> throwTo thread DisconnectException
		Nothing -> return ()
--	putStrLn $ "Closing socket " ++ show socket
	catch (N.shutdown socket N.ShutdownBoth) ((const $ return ()) :: SomeException -> IO ())
	catch (N.sClose socket) ((const $ return ()) :: SomeException -> IO ())

_checkSockStream :: SockStream -> IO ()
_checkSockStream s@(SockStream socket _) = do
	writable <- N.sIsWritable socket
	readable <- N.sIsReadable socket
	let finished = not writable && not readable
	when finished $ _closeSockStream s


instance IBiStream SockStream () B.ByteString B.ByteString () where
	sUpReceive _ _ _ = throwIO DisconnectException
	sUpSendAbort b s e = do
		_closeSockStream s
		streamAbort (streamDown b) e
	sDownReceive _ s@(SockStream socket _) (Just buf) = (NB.sendAll socket buf) `onException` (_closeSockStream s)
	sDownReceive _ s@(SockStream socket _) Nothing = N.shutdown socket N.ShutdownSend >> _checkSockStream s
	sDownReceiveAbort b s e = do
		_closeSockStream s
		streamAbort (streamUp b) e

socketStream :: N.Socket -> IO (BidirectionalStream () B.ByteString B.ByteString ())
socketStream socket = do
		tid <- newEmptyMVar
		let state = SockStream socket tid
		b <- startBiStream state
		recvThread <- forkIOWithUnmask $ \unmask -> unmask $ do_recv state b >> _checkSockStream state
		putMVar tid recvThread
		return b
	where
		do_recv :: SockStream -> BidirectionalStream () B.ByteString B.ByteString () -> IO ()
		do_recv s@(SockStream sock _) b = do
			buf <- NB.recv sock (16*1024)
--			putStrLn $ "Got data on socket " ++ show sock ++ ": " ++ show buf
			if (B.empty == buf) then (streamWrite (streamUp b) Nothing) else do
				streamWrite (streamUp b) (Just buf)
				do_recv s b


firstSuccessful :: [IO a] -> IO a
firstSuccessful [] = fail "firstSuccessful: empty list"
firstSuccessful (p:ps) = catch p $ \e ->
	case ps of
		[] -> throwIO (e :: SomeException)
		_  -> firstSuccessful ps

connectTo :: String -> Int -> IO N.Socket
connectTo host port = do
		let hints = N.defaultHints { N.addrFlags = [N.AI_ADDRCONFIG], N.addrSocketType = N.Stream }
		addrs <- N.getAddrInfo (Just hints) (Just host) (Just $ show port)
		firstSuccessful $ map tryToConnect addrs
	where
		tryToConnect addr = bracketOnError
			(N.socket (N.addrFamily addr) (N.addrSocketType addr) (N.addrProtocol addr))
			(N.sClose)  -- only done if there's an error
			(\sock -> do
				N.connect sock (N.addrAddress addr)
				return sock
			)


listenTo :: Word16 -> (BidirectionalStream () B.ByteString B.ByteString () -> N.SockAddr -> IO ()) -> IO ()
listenTo port thing = do
	bracket
		(N.socket N.AF_INET6 N.Stream N.defaultProtocol)
		(\sock -> do
--			putStrLn "Closing listening socket"
			N.sClose sock
		)
		(\sock -> do
			N.setSocketOption sock N.ReuseAddr 1
			N.bindSocket sock (N.SockAddrInet6 (fromIntegral port) 0 N.iN6ADDR_ANY 0)
			N.listen sock 128
			forever $ do
				(conn, addr) <- N.accept sock
--				putStrLn $ "Accepted connection " ++ show conn ++ " from " ++ show addr
				s <- socketStream conn
				forkIOWithUnmask $ \unmask -> unmask (thing s addr)
		)

-- example, not exported
listenEchoServer :: Word16 -> IO ()
listenEchoServer port = listenTo port $ \stream _ -> do
	_ <- connect (streamUp stream) (streamDown stream)
	return ()
_unused1 :: Word16 -> IO ()
_unused1 = listenEchoServer

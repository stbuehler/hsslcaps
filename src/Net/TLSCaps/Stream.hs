{-# LANGUAGE ExistentialQuantification
           , DeriveDataTypeable
           , MultiParamTypeClasses
           , Rank2Types
           , FlexibleInstances
  #-}

module Net.TLSCaps.Stream
	( IStream(..)
	, Stream
	, StreamException(..)
	, startStream
	, connect
	, streamWrite
	, streamAbort
	, BidirectionalStream(..)
	, connect2
	, IBiStream(..)
	, startBiStream
	) where

import Prelude hiding (catch)

import Control.Monad (when)
import Control.Monad.Fix (mfix)
import Control.Concurrent.STM (STM, atomically, TVar, newTVarIO, readTVar, writeTVar, throwSTM, TMVar, newTMVarIO, takeTMVar, putTMVar, tryTakeTMVar)
import Control.Exception (SomeException, toException, throwIO, Exception, bracket, catch, throwTo)
import Data.Typeable (Typeable)
import Control.Concurrent (forkIO, ThreadId, myThreadId)


data StreamException = AlreadyConnectedException | DisconnectException
	deriving (Show, Typeable)

instance Exception StreamException

class IStream s i o where
	-- handle incoming data.
	sReceive :: Stream i o -> s -> Maybe i -> IO ()
	-- handle abort by target stream. raise to forward exception.
	sSendAbort :: Stream i o -> s -> SomeException -> IO ()
	-- handle abort by source stream. raise to forward exception.
	sReceiveAbort :: Stream i o -> s -> SomeException -> IO ()

	sSendAbort _ _ e = throwIO e
	sReceiveAbort _ _ e = throwIO e

data StreamOut o = forall i . StreamOut (InnerStream i o) deriving (Typeable)
data StreamIn i = forall o . StreamIn (InnerStream i o) deriving (Typeable)

data InnerStream i o = forall s . (IStream s i o) => InnerStream {
		_streamState :: s,
		streamSource :: TVar (Maybe (StreamOut i)),
		streamDest :: TVar (Maybe (StreamIn o)),
		streamWriteThread :: TMVar (Maybe ThreadId)
	} deriving (Typeable)

data Stream i o = SingleStream (InnerStream i o) | forall d . ConnectedStream (Stream i d) (Stream d o)
	deriving (Typeable)

startStream :: (IStream s i o) => s -> IO (Stream i o)
startStream s = do
	sref <- newTVarIO Nothing
	dref <- newTVarIO Nothing
	writeThread <- newTMVarIO Nothing
	return $ SingleStream $ InnerStream s sref dref writeThread

_firstStream :: Stream i o -> StreamIn i
_firstStream (SingleStream r) = StreamIn $ r
_firstStream (ConnectedStream a _) = _firstStream a

_lastStream :: Stream i o -> StreamOut o
_lastStream (SingleStream r) = StreamOut $ r
_lastStream (ConnectedStream _ b) = _lastStream b

_streamWriteThread :: StreamOut o -> TMVar (Maybe ThreadId)
_streamWriteThread (StreamOut s) = streamWriteThread s
_streamSource :: StreamIn i -> TVar (Maybe (StreamOut i))
_streamSource (StreamIn s) = streamSource s
_streamDest :: StreamOut o -> TVar (Maybe (StreamIn o))
_streamDest (StreamOut s) = streamDest s

scall :: (forall s . IStream s i o => Stream i o -> s -> x) -> InnerStream i o -> x
scall selector stream@(InnerStream state _ _ _ ) = selector (SingleStream stream) state

connect :: Stream i d -> Stream d o -> IO (Stream i o)
connect s1 s2 = do
		_connect (_lastStream s1) (_firstStream s2)
		return $ ConnectedStream s1 s2
	where
		_connect :: StreamOut d -> StreamIn d -> IO ()
		_connect x y = atomically $ do
			x' <- readTVar (_streamDest x)
			y' <- readTVar (_streamSource y)
			case (x',y') of
				(Nothing, Nothing) -> do
					writeTVar (_streamDest x) $ Just y
					writeTVar (_streamSource y) $ Just x
					Nothing <- takeTMVar (_streamWriteThread x)
					return ()
				(_, _) -> throwSTM AlreadyConnectedException

streamWrite :: Stream i o -> Maybe o -> IO ()
streamWrite stream d = _lockWriteTarget (_lastStream stream) $ _streamWrite d
	where
		_lockWriteTarget :: StreamOut d -> (StreamIn d -> IO a) -> IO a
		_lockWriteTarget (StreamOut s) thing = do
			tid <- myThreadId
			bracket
				(atomically $ do -- acquire
					putTMVar (streamWriteThread s) $ Just tid
					dest' <- readTVar (streamDest s)
					case dest' of
						Nothing -> throwSTM DisconnectException
						Just dest -> return dest
				)
				(const $ do -- release
					Just tid' <- atomically $ takeTMVar (streamWriteThread s)
					when (tid /= tid') $ fail "Internal State Error: unmatching thread id"
				)
				(\dest -> catch (thing dest) (_handleException s))

		_streamWrite :: Maybe d -> StreamIn d -> IO ()
		_streamWrite d' (StreamIn s) = (catch (scall sReceive s d') (_handleException s))

		_handleException :: InnerStream i o -> SomeException -> IO x
		_handleException s e = streamAbort (SingleStream s) e >> throwIO e


__disconnect:: StreamOut d -> StreamIn d -> STM (Maybe ThreadId)
__disconnect (StreamOut o) (StreamIn i) = do
	writeTVar (streamDest o) Nothing
	writeTVar (streamSource i) Nothing
	wtid' <- tryTakeTMVar (streamWriteThread o)
	case wtid' of
		Just Nothing -> fail "Internal State Error: disconnect, but write thread not connected"
		Just wtid -> return wtid
		Nothing -> putTMVar (streamWriteThread o) Nothing >> return Nothing

_streamDisconnectTarget :: InnerStream i o -> SomeException -> IO ()
_streamDisconnectTarget source e = do
	trg_wtid <- atomically $ do
		target' <- readTVar (streamDest source)
		case target' of
			Nothing -> return Nothing
			Just target -> __disconnect (StreamOut source) target >>= \wtid -> return $ Just (target, wtid)
	case trg_wtid of
		Nothing -> return ()
		Just (_, Nothing) -> return ()
		Just (StreamIn _, Just wtid) -> do
			throwTo wtid e
			atomically $ putTMVar (streamWriteThread source) Nothing
	case trg_wtid of
		Nothing -> return ()
		Just (StreamIn target, _) -> do
			catch (scall sReceiveAbort target e) (\ee -> _streamDisconnectTarget target ee)
			catch (scall sSendAbort source $ toException DisconnectException) ((\_ -> return ()) :: SomeException -> IO ())

_streamDisconnectSource :: InnerStream i o -> SomeException -> IO ()
_streamDisconnectSource target e = do
	src_wtid <- atomically $ do
		source' <- readTVar (streamSource target)
		case source' of
			Nothing -> return Nothing
			Just source -> __disconnect source (StreamIn target) >>= \wtid -> return $ Just (source, wtid)
	case src_wtid of
		Nothing -> return ()
		Just (_, Nothing) -> return ()
		Just (StreamOut source, Just wtid) -> do
			throwTo wtid e
			atomically $ putTMVar (streamWriteThread source) Nothing
	case src_wtid of
		Nothing -> return ()
		Just (StreamOut source, _) -> do
			catch (scall sSendAbort target $ toException DisconnectException) ((\_ -> return ()) :: SomeException -> IO ())
			catch (scall sReceiveAbort source e) (\ee -> _streamDisconnectSource source ee)

streamAbort :: Exception e => Stream i o -> e -> IO ()
streamAbort s e = (\x -> x >> throwIO e) $ forkIO $ do
	case _firstStream s of (StreamIn i) -> _streamDisconnectSource i (toException e)
	case _lastStream s of (StreamOut o) -> _streamDisconnectTarget o (toException e)






data BidirectionalStream upIn upOut downIn downOut = BidirectionalStream { streamUp :: Stream upIn upOut, streamDown :: Stream downIn downOut }
connect2 :: BidirectionalStream botUpIn up down botDownOut -> BidirectionalStream up topUpOut topDownIn down -> IO (BidirectionalStream botUpIn topUpOut topDownIn botDownOut)
connect2 bottom top = do
	up <- connect (streamUp bottom) (streamUp top)
	down <- connect (streamDown top) (streamDown bottom)
	return $ BidirectionalStream up down

class IBiStream s upIn upOut downIn downOut where
	sUpReceive :: BidirectionalStream upIn upOut downIn downOut -> s -> Maybe upIn -> IO ()
	sUpSendAbort :: BidirectionalStream upIn upOut downIn downOut -> s -> SomeException -> IO ()
	sUpReceiveAbort :: BidirectionalStream upIn upOut downIn downOut -> s -> SomeException -> IO ()
	sUpSendAbort _ _ e = throwIO e
	sUpReceiveAbort _ _ e = throwIO e

	sDownReceive :: BidirectionalStream upIn upOut downIn downOut -> s -> Maybe downIn -> IO ()
	sDownSendAbort :: BidirectionalStream upIn upOut downIn downOut -> s -> SomeException -> IO ()
	sDownReceiveAbort :: BidirectionalStream upIn upOut downIn downOut -> s -> SomeException -> IO ()
	sDownSendAbort _ _ e = throwIO e
	sDownReceiveAbort _ _ e = throwIO e

data BiStream s upIn upOut downIn downOut = BiStream s (BidirectionalStream upIn upOut downIn downOut)
data BiUp s upIn upOut downIn downOut = IBiStream s upIn upOut downIn downOut => BiUp (BiStream s upIn upOut downIn downOut)
data BiDown s upIn upOut downIn downOut = IBiStream s upIn upOut downIn downOut => BiDown (BiStream s upIn upOut downIn downOut)

instance IStream (BiUp s upIn upOut downIn downOut) upIn upOut where
	sReceive _ (BiUp (BiStream state b)) d = sUpReceive b state d
	sSendAbort _ (BiUp (BiStream state b)) e = sUpSendAbort b state e
	sReceiveAbort _ (BiUp (BiStream state b)) e = sUpReceiveAbort b state e

instance IStream (BiDown s upIn upOut downIn downOut) downIn downOut where
	sReceive _ (BiDown (BiStream state b)) d = sDownReceive b state d
	sSendAbort _ (BiDown (BiStream state b)) e = sDownSendAbort b state e
	sReceiveAbort _ (BiDown (BiStream state b)) e = sDownReceiveAbort b state e

startBiStream :: IBiStream s upIn upOut downIn downOut => s -> IO (BidirectionalStream upIn upOut downIn downOut)
startBiStream state = do
	BiStream _ b <- mfix $ \stream -> do
		up <- startStream (BiUp stream)
		down <- startStream (BiDown stream)
		return $ BiStream state (BidirectionalStream up down)
	return b

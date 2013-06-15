
{-# LANGUAGE MultiParamTypeClasses,FlexibleInstances #-}

module Net.TLSCaps.StreamParser
	( IStreamParser(..)
	, ByteStreamParserState
	, streamRepeatParser
	, streamParserPush
	, streamParserFinished
	, streamParserEmpty
	, streamParserAppend
	, streamParserRun
	, ByteStreamParser(..)
	) where

import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.ByteString.Lazy as B

import Control.Monad.Trans (MonadTrans, lift)
import Control.Monad.State (StateT, get, put)

import Net.TLSCaps.Utils

class Monad m => IStreamParser m where
	tryPeekBytes :: Int -> m (Maybe [Word8])
	tryPeekString :: Int -> m (Maybe B.ByteString)
	peekByte :: m Word8
	peekBytes :: Int -> m [Word8]
	peekWord16 :: m Word16
	peekWord32 :: m Word32
	peekWord64 :: m Word64
	peekString :: Int -> m B.ByteString

	tryGetBytes :: Int -> m (Maybe [Word8])
	tryGetString :: Int -> m (Maybe B.ByteString)
	getByte :: m Word8
	getBytes :: Int -> m [Word8]
	getWord16 :: m Word16
	getWord32 :: m Word32
	getWord64 :: m Word64
	getString :: Int -> m B.ByteString

	tryPeekString n = tryPeekBytes n >>= \m -> case m of Nothing -> return Nothing; Just r ->return $ Just $ B.pack r
	tryGetString n = tryGetBytes n >>= \m -> case m of Nothing -> return Nothing; Just r ->return $ Just $ B.pack r

	peekBytes n = tryPeekBytes n >>= \m -> case m of Nothing -> fail "Unexected end of stream"; Just r ->return r
	peekByte = peekBytes 1 >>= \r -> case r of [b] -> return b; _ -> error "Internal error"
	peekWord16 = peekBytes 2 >>= return . netDecode 2
	peekWord32 = peekBytes 4 >>= return . netDecode 4
	peekWord64 = peekBytes 8 >>= return . netDecode 8
	peekString n = tryPeekString n >>= \m -> case m of Nothing -> fail "Unexected end of stream"; Just r ->return r

	getBytes n = tryGetBytes n >>= \m -> case m of Nothing -> fail "Unexected end of stream"; Just r ->return r
	getByte = getBytes 1 >>= \r -> case r of [b] -> return b; _ -> error "Internal error"
	getWord16 = getBytes 2 >>= return . netDecode 2
	getWord32 = getBytes 4 >>= return . netDecode 4
	getWord64 = getBytes 8 >>= return . netDecode 8
	getString n = tryGetString n >>= \m -> case m of Nothing -> fail "Unexected end of stream"; Just r ->return r


instance Monad m => IStreamParser (StateT [Word8] m) where
	tryPeekBytes n = get >>= \a -> if (n > length a) then return Nothing else return $ Just $ take n a
	tryGetBytes n = get >>= \a -> if (n > length a) then return Nothing else let (r,b) = splitAt n a in put b >> return (Just r)

instance Monad m => IStreamParser (StateT B.ByteString m) where
	tryPeekBytes n = tryPeekString n >>= \m -> case m of Nothing -> return Nothing; Just r -> return $ Just $ B.unpack r
	tryGetBytes n = tryGetString n >>= \m -> case m of Nothing -> return Nothing; Just r -> return $ Just $ B.unpack r
	tryPeekString n = get >>= \a -> if ((fromIntegral n) > B.length a) then return Nothing else return $ Just $ B.take (fromIntegral n) a
	tryGetString n = get >>= \a -> if ((fromIntegral n) > B.length a) then return Nothing else let (r,b) = B.splitAt (fromIntegral n) a in put b >> return (Just r)


type ByteStreamParserData = (B.ByteString, Bool)
type ByteStreamParserState m = (ByteStreamParserData, Either (ByteStreamParser m ()) Bool)

data ByteStreamParser m a = ByteStreamParser { runParser :: ByteStreamParserData -> m (ByteStreamParserData, Either (ByteStreamParser m a) a) }

instance Monad m => Monad (ByteStreamParser m) where
	(>>=) (ByteStreamParser f) g = ByteStreamParser $ \state -> do
		(state', result) <- f state
		case result of
			Left cont -> return (state', Left $ cont >>= g)
			Right r -> runParser (g r) state'
	return r = ByteStreamParser $ \state -> return (state, Right r)
	fail msg = ByteStreamParser $ const $ fail msg

parseWait :: Monad m => Int -> ByteStreamParser m (Maybe x) -> ByteStreamParser m (Maybe x)
parseWait n thing = _wait
	where
		_wait = ByteStreamParser $ \(str, finished) -> do
			if ((fromIntegral n) <= B.length str) then runParser thing (str, finished)
				else if (finished) then return ((str, finished), Right Nothing)
					else return ((str, finished), Left _wait)

instance Monad m => IStreamParser (ByteStreamParser m) where
	tryPeekBytes n = tryPeekString n >>= \m -> case m of Nothing -> return Nothing; Just r -> return $ Just $ B.unpack r
	tryGetBytes n = tryGetString n >>= \m -> case m of Nothing -> return Nothing; Just r -> return $ Just $ B.unpack r
	tryPeekString n = parseWait n $ ByteStreamParser $ \s@(str, _) -> return (s, Right $ Just $ B.take (fromIntegral n) str)
	tryGetString n = parseWait n $ ByteStreamParser $ \(str, f) -> let (r,b) = B.splitAt (fromIntegral n) str in return ((b, f), Right $ Just r)

instance MonadTrans (ByteStreamParser) where
	lift thing = ByteStreamParser $ \state -> thing >>= \r -> return (state, Right r)

streamParserRun :: Monad m => ByteStreamParserState m -> m (ByteStreamParserState m)
streamParserRun ((str, finished), Right _) = if (str /= B.empty) then fail "Too much data" else return ((str, finished), Right finished)
streamParserRun ((str, finished), Left p) = do
	(state', result) <- runParser p (str, finished)
	case result of
		Left cont -> return (state', Left cont)
		Right () -> streamParserRun (state', Right False)

streamParserEmpty :: Monad m => ByteStreamParserState m -> Bool
streamParserEmpty ((str, _), _) = str == B.empty

streamParserFinished :: Monad m => ByteStreamParserState m -> Bool
streamParserFinished ((_, False), _) = False
streamParserFinished ((str, True), _) = str == B.empty

streamParserAppend :: Monad m => ByteStreamParserData -> Maybe B.ByteString -> m (ByteStreamParserData)
streamParserAppend (str, _) Nothing = return (str, True)
streamParserAppend (str, False) (Just newstr) = return (B.append str newstr, False)
streamParserAppend (_, True) (Just _) = fail "Stream already closed"


streamParserPush :: Monad m => ByteStreamParserState m -> Maybe B.ByteString -> m (ByteStreamParserState m)
streamParserPush ((str, _), x) Nothing = streamParserRun ((str, True), x)
streamParserPush ((str, False), x) (Just newstr) = streamParserRun ((B.append str newstr, False), x)
streamParserPush ((_, True), _) (Just _) = fail "Stream already closed"

streamRepeatParser :: Monad m => (x -> m ()) -> ByteStreamParser m x -> ByteStreamParserState m
streamRepeatParser handle parse = ((B.empty, False), Left go) where
	go = tryPeekBytes 1 >>= \b -> case b of
		Nothing -> return ()
		Just _ -> parse >>= (lift . handle) >> go

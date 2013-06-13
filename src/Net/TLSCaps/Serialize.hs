{-# LANGUAGE MultiParamTypeClasses,FlexibleInstances #-}

module Net.TLSCaps.Serialize
	( OutputStream(..)
	, InputStream(..)
	, netEncode
	, netDecode
	) where

import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.ByteString.Lazy as B

import qualified Control.Monad as M
import Control.Monad.State (StateT, get, put)

import Net.TLSCaps.Utils

class Monad m => OutputStream s m where
	putByte :: Word8 -> StateT s m ()
	putBytes :: [Word8] -> StateT s m ()
	putWord16 :: Word16 -> StateT s m ()
	putWord32 :: Word32 -> StateT s m ()
	putWord64 :: Word64 -> StateT s m ()
	putString :: B.ByteString -> StateT s m ()

	putBytes a = M.mapM_ putByte a
	putWord16 w = putBytes $ netEncode 2 w
	putWord32 w = putBytes $ netEncode 4 w
	putWord64 w = putBytes $ netEncode 8 w
	putString s = putBytes $ B.unpack s

instance Monad m => OutputStream [Word8] m where
	putByte b = get >>= \a -> put (a ++ [b])
	putBytes b = get >>= \a -> put (a ++ b)

instance Monad m => OutputStream B.ByteString m where
	putByte b = get >>= \a -> put (B.append a $ B.pack [b])
	putString b = get >>= \a -> put (B.append a b)


class Monad m => InputStream s m where
	peekByte :: StateT s m Word8
	peekBytes :: Int -> StateT s m [Word8]
	peekWord16 :: StateT s m Word16
	peekWord32 :: StateT s m Word32
	peekWord64 :: StateT s m Word64
	peekString :: Int -> StateT s m B.ByteString
	
	getByte :: StateT s m Word8
	getBytes :: Int -> StateT s m [Word8]
	getWord16 :: StateT s m Word16
	getWord32 :: StateT s m Word32
	getWord64 :: StateT s m Word64
	getString :: Int -> StateT s m B.ByteString
	
	inputAvailable :: Int -> StateT s m Bool
	
	peekByte = peekBytes 1 >>= \r -> case r of [b] -> return b; _ -> error "Internal error"
	peekWord16 = peekBytes 2 >>= return . netDecode 2
	peekWord32 = peekBytes 4 >>= return . netDecode 4
	peekWord64 = peekBytes 8 >>= return . netDecode 8
	peekString n = peekBytes n >>= \x -> return $ B.pack x
	getByte = getBytes 1 >>= \r -> case r of [b] -> return b; _ -> error "Internal error"
	getWord16 = getBytes 2 >>= return . netDecode 2
	getWord32 = getBytes 4 >>= return . netDecode 4
	getWord64 = getBytes 8 >>= return . netDecode 8
	getString n = getBytes n >>= \x -> return $ B.pack x

instance Monad m => InputStream [Word8] m where
	peekBytes n = get >>= \a -> if (n > length a) then fail "Unexected end of stream" else return $ take n a
	getBytes n = get >>= \a -> if (n > length a) then fail "Unexected end of stream" else let (r,b) = splitAt n a in put b >> return r
	inputAvailable n = get >>= \a -> return (n <= length a)

instance Monad m => InputStream B.ByteString m where
	peekString n = get >>= \a -> if ((fromIntegral n) > B.length a) then fail "Unexected end of stream" else return $ B.take (fromIntegral n) a
	getString n = get >>= \a -> if ((fromIntegral n) > B.length a) then fail "Unexected end of stream" else let (r,b) = B.splitAt (fromIntegral n) a in put b >> return r
	peekBytes n = peekString n >>= return . B.unpack
	getBytes n = getString n >>= return . B.unpack
	inputAvailable n = get >>= \a -> return ((fromIntegral n) <= B.length a)

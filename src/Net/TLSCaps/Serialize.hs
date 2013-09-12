{-# LANGUAGE MultiParamTypeClasses,FlexibleInstances,UndecidableInstances #-}

module Net.TLSCaps.Serialize
	( netEncode
	, netDecode

	, Serializer
	, serialize
	, putByte
	, putBytes
	, putUnsigned
	, putWord16
	, putWord24
	, putWord32
	, putWord64
	, putString
	, putEnum
	, putBlockLimit
	, putBlock8
	, putBlock16
	, putBlock24
	, putString8
	, putString16
	, putString24

	, Deserializer
	, peekByte
	, peekBytes
	, peekWord16
	, peekWord24
	, peekWord32
	, peekWord64
	, peekString
	, getByte
	, getBytes
	, getUnsigned
	, getWord16
	, getWord24
	, getWord32
	, getWord64
	, getString
	, availableInput
	, inputAvailable
	, deserialize
	, whileHasInput
	, getEnum
	, getBlock8
	, getBlock16
	, getBlock24
	, getString8
	, getString16
	, getString24
	, getCatch
	) where

import Data.Word (Word8, Word16, Word32, Word64)
import qualified Data.ByteString.Lazy as B

import qualified Control.Monad as M
import Control.Monad.Error.Class (MonadError(..))
import Control.Monad.Trans.Class (MonadTrans(..))
import Control.Monad.IO.Class (MonadIO(..))
import Control.Monad (MonadPlus(..))
--import Data.Functor.Identity (Functor(..))
import Control.Applicative (Applicative(..), Alternative(..))
import Control.Monad.Fix (MonadFix(..))

import Control.Monad.State (StateT, get, put, evalStateT, execStateT, runStateT)
import Control.Monad.Trans.Maybe (MaybeT, runMaybeT)

import Net.TLSCaps.Utils



newtype Serializer m a = Serializer { _runSerializer :: StateT B.ByteString m a }

instance Monad m => Monad (Serializer m) where
	~(Serializer a) >>= b = Serializer $ a >>= _runSerializer . b
	~(Serializer a) >> ~(Serializer b) = Serializer $ a >> b
	return = Serializer . return
	fail = Serializer . fail
instance MonadError e m => MonadError e (Serializer m) where
	throwError = Serializer . throwError
	catchError ~(Serializer f) h = Serializer $ catchError f (_runSerializer . h)
instance MonadTrans Serializer where
	lift f = Serializer $ lift f
instance (Functor m) => Functor (Serializer m) where
	fmap f ~(Serializer m) = Serializer $ fmap f m
instance (Functor m, Monad m) => Applicative (Serializer m) where
	pure = return
	(<*>) = M.ap
instance (Functor m, MonadPlus m) => Alternative (Serializer m) where
	empty = mzero
	(<|>) = mplus
instance (MonadPlus m) => MonadPlus (Serializer m) where
	mzero       = Serializer $ mzero
	~(Serializer a) `mplus` ~(Serializer b) = Serializer $ a `mplus` b
instance (MonadFix m) => MonadFix (Serializer m) where
	mfix f = Serializer $ mfix (_runSerializer . f)
instance (MonadIO m) => MonadIO (Serializer m) where
	liftIO = lift . liftIO

serialize :: Monad m => Serializer m x -> m B.ByteString
serialize s = execStateT (_runSerializer s) B.empty

putByte   :: Monad m => Word8 -> Serializer m ()
putByte b = putBytes [b]
putBytes  :: Monad m => [Word8] -> Serializer m ()
putBytes a = putString $ B.pack a
putUnsigned :: (Monad m, Integral u) => Int -> u -> Serializer m ()
putUnsigned n u = putBytes $ netEncode n u
putWord16 :: Monad m => Word16 -> Serializer m ()
putWord16 = putUnsigned 2
putWord24 :: Monad m => Word32 -> Serializer m ()
putWord24 = putUnsigned 3
putWord32 :: Monad m => Word32 -> Serializer m ()
putWord32 = putUnsigned 4
putWord64 :: Monad m => Word64 -> Serializer m ()
putWord64 = putUnsigned 8
putString :: Monad m => B.ByteString -> Serializer m ()
putString b = Serializer $ get >>= \a -> put (B.append a b)

_enumUpper :: (Enum e, Bounded e) => e -> Int
_enumUpper v = let [_,b] = [v,maxBound] in fromEnum b

putEnum :: (Monad m, Enum e, Bounded e) => e -> Serializer m ()
putEnum v = let u = _enumUpper v in
	if (u < 2^(8::Int)) then putByte (fromIntegral $ fromEnum v)
	else if (u < 2^(16::Int)) then putWord16 (fromIntegral $ fromEnum v)
	else if (u < 2^(24::Int)) then putWord24 (fromIntegral $ fromEnum v)
	else if (u < 2^(32::Int)) then putWord32 (fromIntegral $ fromEnum v)
	else fail $ "Can't handle enum with upper bound " ++ show u

putBlockLimit :: Monad m => Integer -> String -> Serializer (Serializer m) x -> Serializer m ()
putBlockLimit n name b = do
	d <- serialize b
	M.when (B.length d > fromIntegral n) $ fail $ name ++ " too large"
	if (n < 2^(8::Int)) then putByte (fromIntegral $ B.length d)
		else if (n < 2^(16::Int)) then putWord16 (fromIntegral $ B.length d)
		else if (n < 2^(24::Int)) then putWord24 (fromIntegral $ B.length d)
		else fail $ "Can't handle limit " ++ show n ++ " for " ++ name
	putString d

putBlock8 :: Monad m => String -> Serializer (Serializer m) x -> Serializer m ()
putBlock8 = putBlockLimit (2^(8::Int)-1)
putBlock16 :: Monad m => String -> Serializer (Serializer m) x -> Serializer m ()
putBlock16 = putBlockLimit (2^(16::Int)-1)
putBlock24 :: Monad m => String -> Serializer (Serializer m) x -> Serializer m ()
putBlock24 = putBlockLimit (2^(24::Int)-1)

putString8 :: Monad m => String -> B.ByteString -> Serializer m ()
putString8 n = putBlock8 n . putString
putString16 :: Monad m => String -> B.ByteString -> Serializer m ()
putString16 n = putBlock16 n . putString
putString24 :: Monad m => String -> B.ByteString -> Serializer m ()
putString24 n = putBlock24 n . putString

newtype Deserializer m a = Deserializer { _runDeserializer :: StateT B.ByteString m a }

instance Monad m => Monad (Deserializer m) where
	~(Deserializer a) >>= b = Deserializer $ a >>= _runDeserializer . b
	~(Deserializer a) >> ~(Deserializer b) = Deserializer $ a >> b
	return = Deserializer . return
	fail = Deserializer . fail
instance MonadError e m => MonadError e (Deserializer m) where
	throwError = Deserializer . throwError
	catchError ~(Deserializer f) h = Deserializer $ catchError f (_runDeserializer . h)
instance MonadTrans Deserializer where
	lift f = Deserializer $ lift f
instance (Functor m) => Functor (Deserializer m) where
	fmap f ~(Deserializer m) = Deserializer $ fmap f m
instance (Functor m, Monad m) => Applicative (Deserializer m) where
	pure = return
	(<*>) = M.ap
instance (Functor m, MonadPlus m) => Alternative (Deserializer m) where
	empty = mzero
	(<|>) = mplus
instance (MonadPlus m) => MonadPlus (Deserializer m) where
	mzero       = Deserializer $ mzero
	~(Deserializer a) `mplus` ~(Deserializer b) = Deserializer $ a `mplus` b
instance (MonadFix m) => MonadFix (Deserializer m) where
	mfix f = Deserializer $ mfix (_runDeserializer . f)
instance (MonadIO m) => MonadIO (Deserializer m) where
	liftIO = lift . liftIO


peekByte    :: Monad m => Deserializer m Word8
peekByte     = peekBytes 1 >>= \r -> case r of [b] -> return b; _ -> error "Internal error"
peekBytes   :: Monad m => Int -> Deserializer m [Word8]
peekBytes n  = peekString n >>= return . B.unpack
peekWord16  :: Monad m => Deserializer m Word16
peekWord16   = peekBytes 2 >>= return . netDecode 2
peekWord24  :: Monad m => Deserializer m Word32
peekWord24   = peekBytes 3 >>= return . netDecode 3
peekWord32  :: Monad m => Deserializer m Word32
peekWord32   = peekBytes 4 >>= return . netDecode 4
peekWord64  :: Monad m => Deserializer m Word64
peekWord64   = peekBytes 8 >>= return . netDecode 8
peekString  :: Monad m => Int -> Deserializer m B.ByteString
peekString n = Deserializer $ get >>= \a -> if ((fromIntegral n) > B.length a) then fail "Unexected end of stream" else return $ B.take (fromIntegral n) a

getByte     :: Monad m => Deserializer m Word8
getByte      = getBytes 1 >>= \r -> case r of [b] -> return b; _ -> error "Internal error"
getBytes    :: Monad m => Int -> Deserializer m [Word8]
getBytes n   = getString n >>= return . B.unpack
getUnsigned :: (Monad m, Integral n) => Int -> Deserializer m n
getUnsigned n = getBytes n >>= return . netDecode n
getWord16   :: Monad m => Deserializer m Word16
getWord16    = getUnsigned 2
getWord24   :: Monad m => Deserializer m Word32
getWord24    = getUnsigned 3
getWord32   :: Monad m => Deserializer m Word32
getWord32    = getUnsigned 4
getWord64   :: Monad m => Deserializer m Word64
getWord64    = getUnsigned 8
getString   :: Monad m => Int -> Deserializer m B.ByteString
getString n  = Deserializer $ get >>= \a -> if ((fromIntegral n) > B.length a) then fail "Unexected end of stream" else let (r,b) = B.splitAt (fromIntegral n) a in put b >> return r

availableInput :: Monad m => Deserializer m Int
availableInput = Deserializer $ get >>= return . fromIntegral . B.length
inputAvailable :: Monad m => Int -> Deserializer m Bool
inputAvailable n = availableInput >>= \h -> return $ n <= h



deserialize :: Monad m => B.ByteString -> Deserializer m a -> m a
deserialize d p = flip (evalStateT . _runDeserializer) d $ do
	r <- p
	haveBytes <- availableInput
	M.when (haveBytes > 0) $ fail $ show haveBytes ++ " unused bytes"
	return r

whileHasInput :: Monad m => Deserializer m a -> Deserializer m [a]
whileHasInput f = inputAvailable 1 >>= \t -> if (t) then f >>= \e -> whileHasInput f >>= \l -> return (e:l) else return []

getEnum :: (Monad m, Enum e, Bounded e) => Deserializer m e
getEnum = do
	let b = maxBound
	let u = fromEnum b
	e <- if (u < 2^(8::Int)) then getByte >>= (return .toEnum . fromIntegral)
		else if (u < 2^(16::Int)) then getWord16 >>= (return .toEnum . fromIntegral)
		else if (u < 2^(24::Int)) then getWord24 >>= (return .toEnum . fromIntegral)
		else if (u < 2^(32::Int)) then getWord32 >>= (return .toEnum . fromIntegral)
		else fail $ "Can't handle enum with upper bound " ++ show u
	return $ head [e, b]

getBlock8 :: Monad m => Deserializer (Deserializer m) e -> Deserializer m e
getBlock8 p = do
	d <- getByte >>= getString . fromIntegral
	deserialize d p

getBlock16 :: Monad m => Deserializer (Deserializer m) e -> Deserializer m e
getBlock16 p = do
	d <- getWord16 >>= getString . fromIntegral
	deserialize d p

getBlock24 :: Monad m => Deserializer (Deserializer m) e -> Deserializer m e
getBlock24 p = do
	d <- getWord24 >>= getString . fromIntegral
	deserialize d p

getString8 :: Monad m => Deserializer m B.ByteString
getString8 = getByte >>= getString . fromIntegral
getString16 :: Monad m => Deserializer m B.ByteString
getString16 = getWord16 >>= getString . fromIntegral
getString24 :: Monad m => Deserializer m B.ByteString
getString24 = getWord24 >>= getString . fromIntegral

getCatch :: Monad m => Deserializer (MaybeT (Deserializer m)) e -> Deserializer m e -> Deserializer m e
getCatch t fallback = Deserializer $ do
	s <- get
	x <- _runDeserializer $ runMaybeT $ runStateT (_runDeserializer t) s
	case x of
		Just (r, s') -> put s' >> return r
		Nothing -> (_runDeserializer fallback)

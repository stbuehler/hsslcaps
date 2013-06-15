{-# LANGUAGE ExistentialQuantification
           , DeriveDataTypeable
           , MultiParamTypeClasses
           , Rank2Types
           , FlexibleInstances
  #-}

module Net.TLSCaps.Test where

import qualified Data.ByteString.Lazy as B
import Data.Word (Word16)
import Control.Concurrent (forkIOWithUnmask)

import Net.TLSCaps.TLSStream
import Net.TLSCaps.Examples
import Net.TLSCaps.Stream
import Net.TLSCaps.EnumTexts

data ShowStream = ShowStream

instance Show s => IStream ShowStream s () where
	sReceive _ _ Nothing = putStrLn $ "stream end"
	sReceive _ _ (Just x) = putStrLn $ "stream received: " ++ show x

data MockSource = MockSource

instance IStream (MockSource) () x where
	sReceive _ _ _ = fail "No input allowed"

startMockStream :: IO (Stream () x)
startMockStream = do
	s <- startStream $ MockSource
	return s

runMockStream :: Show x => Stream () x -> x -> IO ()
runMockStream s content = do
--	putStrLn $ "mocking socket read: " ++ show content
	streamWrite s $ Just content
--	putStrLn $ "mocking socket eof"
	streamWrite s $ Nothing

testRecv :: B.ByteString -> IO ()
testRecv testInput = do
	mockSockOut <- startStream ShowStream :: IO (Stream B.ByteString ())
	mockSockIn <- startMockStream :: IO (Stream () B.ByteString)
	let mockSocket = BidirectionalStream mockSockIn mockSockOut
	tls <- tlsStart
	showIn <- startStream ShowStream :: IO (Stream (TLSVersion, TLSRecvMessage) ())
	noOut <- startMockStream :: IO (Stream () B.ByteString)
	connect2 mockSocket tls
	connect2 tls (BidirectionalStream showIn noOut)
	runMockStream mockSockIn testInput
	return ()

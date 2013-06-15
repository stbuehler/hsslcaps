module Main where

import Net.TLSCaps
import Net.TLSCaps.Handshake (parseHandshake)
import Net.TLSCaps.Utils (ErrorMonad(..))
import qualified Net.TLSCaps.Parameters as P
import Net.TLSCaps.EnumTexts

import System.Environment (getArgs)

tlsHandle :: MonadIO m => Message -> TLSMonad m ()
tlsHandle msg = case msg of
	Handshake ver t h -> case parseHandshake ver t h of
		Result (ServerHelloDone) -> do
			liftIO $ putStrLn "Got ServerHelloDone, closing"
			tlsClose
		_ -> do
			tlsProcess msg
	AppData d -> liftIO $ putStrLn $ "Recv: " ++ show d
	_ -> tlsProcess msg

tlsTrace :: MonadIO m => (Bool, Message) -> TLSMonad m ()
tlsTrace (inout,msg) = liftIO (putStrLn $ io ++ show msg) where
	io = if inout then "In : " else "Out: "

tlsStart :: MonadIO m => TLSMonad m ()
tlsStart = do
	tlsInitialize $ tlsDefaultParameters { P.tlsMinVersion = TLS1_1 }

main :: IO ()
main = do
	(host:_) <- getArgs
	s <- connectTo host 443
	tlsRunTrace s tlsStart (return ()) tlsHandle tlsTrace

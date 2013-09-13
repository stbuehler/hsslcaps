
module Net.TLSCaps.Tests.EllipticCurves where

import Net.TLSCaps.EllipticCurves
import Net.TLSCaps.EnumTexts

import Control.Monad (when)

test_curve_exp' :: Monad m => ECCurve -> Integer -> ECPoint -> m ()
test_curve_exp' c e ap = do
	p <- curve_exp' c e
	rap <- curve_affine c p
	when (rap /= ap) $ fail $ "Test failed " ++ show rap ++ " /= " ++ show ap

test_secp160r1_1 :: Monad m => m ()
test_secp160r1_1 = do
	c <- named_curve TLS_EC_secp160r1
	let dU = 971761939728640320549601132085879836204587084162
	let xU = 466448783855397898016055842232266600516272889280
	let yU = 1110706324081757720403272427311003102474457754220
	test_curve_exp' c dU $ ECAffine xU yU

test_sect163k1_1 :: Monad m => m ()
test_sect163k1_1 = do
	c <- named_curve TLS_EC_sect163k1
	let dU = 5321230001203043918714616464614664646674949479949
	let xU = 0x037D529FA37E42195F10111127FFB2BB38644806BC
	let yU = 0x0447026EEE8B34157F3EB51BE5185D2BE0249ED776
	test_curve_exp' c dU $ ECAffine xU yU

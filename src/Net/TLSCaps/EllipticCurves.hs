{-# LANGUAGE RankNTypes,ImpredicativeTypes #-}

module Net.TLSCaps.EllipticCurves
	( ECCurve(..)
	, ECGroup(..)
	, ECField(..)
	, ECPoint(..)
	, ECNumber(..)
	, putPointUncompressed
	, putPointHybrid
	, putPointCompressed
	, parsePoint
	, parsePoint'
	, parseCurve

	, point_op
	, point_dbl
	, point_exp
	, point_inv
	, group_has

	, named_curve

	, curve_exp
	, curve_exp'
	, curve_inv
	, curve_affine
	, curve_has
	, curve_op
	, curve_eq

	, fc
	, fadd
	, fsub
	, fneg
	, fmul
	, fdiv
	, fsqr
	, finv
	, fpow
	, fsqrt
	) where

--import Numeric (showHex)

import Net.TLSCaps.EnumTexts
import Net.TLSCaps.Serialize

import Data.Bits (Bits(..))

import Control.Monad (ap)
import Math.NumberTheory.Moduli

data ECPoint
	= ECPoint_Infinity
	| ECAffine Integer Integer
	| ECJProjective Integer Integer Integer -- only for prime fields
	deriving (Eq, Show) -- simple Eq - can't compare without group

data ECNumber = ECNumber ECGroup ECPoint

affinePoint :: Monad m => ECNumber -> m (Maybe (Integer, Integer))
affinePoint (ECNumber g p) = affineCoords (group_field g) p

affineCoords :: Monad m => ECField -> ECPoint -> m (Maybe (Integer, Integer))
affineCoords _ ECPoint_Infinity      = return Nothing
affineCoords _ (ECAffine x y)        = return $ Just (x, y)
affineCoords _ (ECJProjective _ _ 0) = return $ Nothing
affineCoords _ (ECJProjective x y 1) = return $ Just (x, y)
affineCoords f (ECJProjective x y z) = do
	zinv <- finv (fc z) f
	zinv2 <- fsqr (fc zinv) f
	zinv3 <- fmul (fc zinv2) (fc zinv) f
	ax <- fmul (fc x) (fc zinv2) f
	ay <- fmul (fc y) (fc zinv3) f
	return $ Just (ax, ay)

jProjectiveCoords :: ECPoint -> (Integer, Integer, Integer)
jProjectiveCoords ECPoint_Infinity = (0, 0, 0)
jProjectiveCoords (ECAffine x y) = (x, y, 1)
jProjectiveCoords (ECJProjective x y z) = (x, y, z)


instance Eq ECNumber where
	(ECNumber g1 p1) == (ECNumber g2 p2) = g1 == g2 && field_eq (group_field g1) p1 p2

-- irreducable polynom defining the field F_2^m
data ECGroupChar2Polynom
	= Char2Trinomial !Int !Int -- (m k): X^m + X^k + 1, m > k > 1
	| Char2Pentanomial !Int !Int !Int !Int -- (m k1 k2 k3): X^m + X^k3 + X^k2 + X^k1 + 1, m > k3 > k2 > k1 > 1
	deriving (Eq, Show)

c2degree :: ECGroupChar2Polynom -> Int
c2degree (Char2Trinomial m _) = m
c2degree (Char2Pentanomial m _ _ _) = m

c2mask :: ECGroupChar2Polynom -> Integer
c2mask (Char2Trinomial m k) = 2^m `xor` 2^k `xor` 1
c2mask (Char2Pentanomial m k1 k2 k3) = 2^m `xor` 2^k1 `xor` 2^k2 `xor` 2^k3 `xor` 1

c2bits :: ECGroupChar2Polynom -> [Int]
c2bits (Char2Trinomial m k) = [m, k, 0]
c2bits (Char2Pentanomial m k1 k2 k3) = [m, k1, k2, k3, 0]

c2mod :: ECGroupChar2Polynom -> Integer -> Integer
c2mod p v = let o = log2 0 (v `shiftR` d) in g o v where
	d = c2degree p
	log2 r 0 = r
	log2 r n = r `seq` log2 (r+1) (n `shiftR` 1)
	g :: Int -> Integer -> Integer
	g o n = if o < 0 then n else if testBit n (o+d) then g (o-1) (s o n) else g (o - 1) n
	s :: Int -> Integer -> Integer
	s o n = foldl complementBit n $ map (o+) (c2bits p)

-- ops
c2add' :: Integer -> Integer -> Integer
c2add' x y = x `xor` y
c2add :: Monad m => ECGroupChar2Polynom -> Integer -> Integer -> m Integer
c2add _ x y = return $ c2add' x y
c2sub :: Monad m => ECGroupChar2Polynom -> Integer -> Integer -> m Integer
c2sub = c2add
c2neg :: Monad m => ECGroupChar2Polynom -> Integer -> m Integer
c2neg _ = return
c2mul' :: ECGroupChar2Polynom -> Integer -> Integer -> Integer
c2mul' _ 0 _ = 0
c2mul' _ _ 0 = 0
c2mul' _ 1 y = y
c2mul' _ x 1 = x
c2mul' p x y = c2mod p $ g x y where
	g 0 _ = 0
	g 1 b = b
	g a b = case testBit a 0 of
		False -> g (a `shiftR` 1) (b `shiftL` 1)
		True -> b `xor` g (a `shiftR` 1) (b `shiftL` 1)
c2mul :: Monad m => ECGroupChar2Polynom -> Integer -> Integer -> m Integer
c2mul p x y = return $ c2mul' p x y
c2div :: Monad m => ECGroupChar2Polynom -> Integer -> Integer -> m Integer
c2div p x y = c2inv p y >>= c2mul p x
c2sqr' :: ECGroupChar2Polynom -> Integer -> Integer
c2sqr' p x = c2mod p $ g 0 x where
	g _ 0 = 0
	g o n = case testBit n 0 of
		True -> setBit (g (o+1) (n `shiftR` 1)) (2*o)
		False -> g (o+1) (n `shiftR` 1)
c2sqr :: Monad m => ECGroupChar2Polynom -> Integer -> m Integer
c2sqr p x = return $ c2sqr' p x
c2inv :: Monad m => ECGroupChar2Polynom -> Integer -> m Integer
c2inv p x = inv x >>= return . c2mod p where
	inv :: Monad m => Integer -> m Integer
	inv r = g 1 0 r (c2mask p)
	g :: Monad m => Integer -> Integer -> Integer -> Integer -> m Integer
	g b _ 1 _ = return b
	g _ _ 0 _ = fail $ show x ++ " has no inverse"
	g b c u v = if testBit u 0 then if (u < v) then g (b `xor` c) b (u `xor` v) u else g (b `xor` c) c (u `xor` v) v
		else if testBit b 0 then g (s b `shiftR` 1) c (u `shiftR` 1) v else g (b `shiftR` 1) c (u `shiftR` 1) v
	s n = foldl complementBit n (c2bits p)
c2pow' :: (Integral e, Bits e) => ECGroupChar2Polynom -> Integer -> e -> Integer
c2pow' p x e' = g 1 x e' where
	g r _ 0 = r
	g r a 1 = c2mul' p r a
	g r a e = if (testBit e 0) then g (c2mul' p r a) (c2sqr' p a) (e `shiftR` 1) else g r (c2sqr' p a) (e `shiftR` 1)
c2pow :: (Integral e, Bits e, Monad m) => ECGroupChar2Polynom -> Integer -> e -> m Integer
c2pow p x e = return $ c2pow' p x e
-- we are in a field with 2^m elements, so the multiplicative subgroup has 2^m - 1 elements.
-- => for all elements a: a == a^(2^m-1) * a = a^(2^m) = (a^(2^(m-1)))^2
-- => a^(2^(m-1)) is the square root of a (as a == -a there is only one square root)
c2sqrt' :: ECGroupChar2Polynom -> Integer -> Integer
c2sqrt' p x = c2pow' p x (setBit (0 :: Integer) $ c2degree p - 1)
c2sqrt :: Monad m => ECGroupChar2Polynom -> Integer -> m Integer
c2sqrt p x = return $ c2sqrt' p x

-- r <- c2solveQuad p a: r^2 + r == a (p)
c2solveQuad :: Monad m => ECGroupChar2Polynom -> Integer -> m Integer
c2solveQuad p a = let m = c2degree p in if even m then fail $ "cannot solve easily for even " ++ show m
	else let r = foldl (\x _ -> a `xor` c2sqr' p (c2sqr' p x)) a [1..m `shiftR` 1] in
		if c2mod p (c2sqr' p r `xor` r) == a then return (c2mod p r) else fail "no solution"

padd' :: Integer -> Integer -> Integer -> Integer
padd' p a b = (a + b) `mod` p
padd :: Monad m => Integer -> Integer -> Integer -> m Integer
padd p a b = return $ padd' p a b
psub' :: Integer -> Integer -> Integer -> Integer
psub' p a b = (a - b) `mod` p
psub :: Monad m => Integer -> Integer -> Integer -> m Integer
psub p a b = return $ psub' p a b
pneg' :: Integer -> Integer -> Integer
pneg' p a = (-a) `mod` p
pneg :: Monad m => Integer -> Integer -> m Integer
pneg p a = return $ pneg' p a
pmul' :: Integer -> Integer -> Integer -> Integer
pmul' p a b = (a * b) `mod` p
pmul :: Monad m => Integer -> Integer -> Integer -> m Integer
pmul p a b = return $ pmul' p a b
psqr' :: Integer -> Integer -> Integer
psqr' p a = pmul' p a a
psqr :: Monad m => Integer -> Integer -> m Integer
psqr p a = return $ psqr' p a
pinv :: Monad m => Integer -> Integer -> m Integer
pinv p a = case invertMod a p of Just x -> return x; Nothing -> fail "no inverse - not coprime"
pdiv :: Monad m => Integer -> Integer -> Integer -> m Integer
pdiv p a 2 = if testBit p 0 then if testBit a 0 then return $ (a+p) `shiftR` 1 else return $ a `shiftR` 1 else fail "no inverse - not coprime"
pdiv p a b = pinv p b >>= \binv -> pmul p a binv
ppow' :: (Integral e, Bits e) => Integer -> Integer -> e -> Integer
ppow' p a e = powerMod a e p
ppow :: (Integral e, Bits e, Monad m) => Integer -> Integer -> e -> m Integer
ppow p a e = return $ ppow' p a e
psqrt :: Monad m => Integer -> Integer -> m Integer
psqrt p a = case sqrtModP a p of Just x -> return x; Nothing -> fail "has no square root"

data ECField
	= PrimeField !Integer
	| Char2Field !ECGroupChar2Polynom
	deriving (Eq, Show)

field_len :: ECField -> Int
field_len (PrimeField p) = _bytelen 0 p  where
	_bytelen l 0 = l
	_bytelen l n = l+1 `seq` _bytelen (l+1) (n `div` 256)
field_len (Char2Field p) = (c2degree p + 7) `div` 8

type FieldCalc m = ECField -> m Integer

fc :: Monad m => Integer -> FieldCalc m
fc n _ = return n
_fop1 :: Monad m => (Integer -> Integer -> m Integer, ECGroupChar2Polynom -> Integer -> m Integer) -> FieldCalc m -> FieldCalc m
_fop1 (pop, _ ) x f@(PrimeField p) = x f >>= pop p
_fop1 (_, c2op) x f@(Char2Field p) = x f >>= c2op p
_fop2 :: Monad m => (Integer -> Integer -> Integer -> m Integer, ECGroupChar2Polynom -> Integer -> Integer -> m Integer) -> FieldCalc m -> FieldCalc m -> FieldCalc m
_fop2 (pop, _ ) x y f@(PrimeField p) = x f >>= \a -> y f >>= pop p a
_fop2 (_, c2op) x y f@(Char2Field p) = x f >>= \a -> y f >>= c2op p a
fadd :: Monad m => FieldCalc m -> FieldCalc m -> FieldCalc m
fadd = _fop2 (padd, c2add)
fsub :: Monad m => FieldCalc m -> FieldCalc m -> FieldCalc m
fsub = _fop2 (psub, c2sub)
fneg :: Monad m => FieldCalc m -> FieldCalc m
fneg = _fop1 (pneg, c2neg)
fmul :: Monad m => FieldCalc m -> FieldCalc m -> FieldCalc m
fmul = _fop2 (pmul, c2mul)
fdiv :: Monad m => FieldCalc m -> FieldCalc m -> FieldCalc m
fdiv = _fop2 (pdiv, c2div)
fsqr :: Monad m => FieldCalc m -> FieldCalc m
fsqr = _fop1 (psqr, c2sqr)
finv :: Monad m => FieldCalc m -> FieldCalc m
finv = _fop1 (pinv, c2inv)
fpow :: (Integral e, Bits e, Monad m) => FieldCalc m -> e -> FieldCalc m
fpow x e f@(PrimeField p) = x f >>= \a -> ppow p a e
fpow x e f@(Char2Field p) = x f >>= \a -> c2pow p a e
fsqrt :: Monad m => FieldCalc m -> FieldCalc m
fsqrt = _fop1 (psqrt, c2sqrt)

field_eq :: ECField -> ECPoint -> ECPoint -> Bool
field_eq _ ECPoint_Infinity ECPoint_Infinity = True
field_eq _ ECPoint_Infinity (ECJProjective _ _ 0) = True
field_eq _ (ECJProjective _ _ 0) ECPoint_Infinity = True
field_eq _ (ECJProjective _ _ 0) (ECJProjective _ _ 0) = True
field_eq _ ECPoint_Infinity _ = False
field_eq _ _ ECPoint_Infinity = False
field_eq _ (ECJProjective _ _ 0) _ = False
field_eq _ _ (ECJProjective _ _ 0) = False
field_eq _ (ECAffine x y) (ECAffine x' y') = x == x' && y == y'
field_eq f (ECAffine x y) p = field_eq f (ECJProjective x y 1) p
field_eq f p (ECAffine x y) = field_eq f p (ECJProjective x y 1)
--     x1/z1^2 == x2/z2^2 && y1/z1^3 == y2/z2^3
-- <=> x1*z2^2 == x2*z1^2 && y1*z2^3 == y2*z1^3
field_eq (PrimeField p) (ECJProjective x1 y1 z1) (ECJProjective x2 y2 z2) =
	let sqr = psqr' p; mul = pmul' p; z12 = sqr z1; z13 = mul z1 z12; z22 = sqr z2; z23 = mul z2 z22 in
		mul x1 z22 == mul x2 z12 && mul y1 z23 == mul y2 z13
field_eq (Char2Field p) (ECJProjective x1 y1 z1) (ECJProjective x2 y2 z2) =
	let sqr = c2sqr' p; mul = c2mul' p; z12 = sqr z1; z13 = mul z1 z12; z22 = sqr z2; z23 = mul z2 z22 in
		mul x1 z22 == mul x2 z12 && mul y1 z23 == mul y2 z13


-- elliptic curve group ops
p_point_dbl :: Integer -> Integer -> (Integer, Integer, Integer) -> ECPoint
p_point_dbl p a (x, y, z) =
	let mul = pmul' p; sqr = psqr' p; add = padd' p; sub = psub' p in
	-- n1 = 3*x^2 + a*z^4
	let n1 = add (mul 3 (sqr x)) (mul a $ sqr $ sqr z) in
	-- zr = 2*y*z
	let zr = mul 2 (mul y z) in
	-- n2 = 4*x*y^2
	let n2 = mul 4 (mul x (sqr y)) in
	-- xr = n1^2 - 2*n2
	let xr = sub (sqr n1) (n2 `shiftL` 1) in
	-- yr = n1 * (n2 - xr) - 8 * y^4
	let yr = sub (mul n1 $ sub n2 xr) (mul 8 $ sqr $ sqr y) in
	ECJProjective xr yr zr

p_point_op :: Integer -> Integer -> (Integer, Integer, Integer) -> (Integer, Integer, Integer) -> ECPoint
p_point_op p a (x1, y1, z1) (x2, y2, z2) =
	let mul = pmul' p; sqr = psqr' p; add = padd' p; sub = psub' p in
	-- n1 = x1 * z2^2, n2 = y1 * z2^3
	let n1 = mul x1 (sqr z2); n2 = mul y1 (mul z2 (sqr z2)) in
	-- n3 = x2 * z1^2, n4 = y2 * z1^3
	let n3 = mul x2 (sqr z1); n4 = mul y2 (mul z1 (sqr z1)) in
	-- n5 = n1 - n3 == x1*z2^2 - x2*z1^2
	-- n6 = n2 - n4 == y1*z2^3 - y2*z1^3
	let n5 = sub n1 n3; n6 = sub n2 n4 in
	if n5 == 0 then if n6 == 0 then p_point_dbl p a (x1, y1, z1) else ECPoint_Infinity else
		-- n1 = n7 = n1 + n3 = x1*z2^2 + x2*z1^2
		-- n2 = n8 = n2 + n4 = y1*z2^2 + y2*z1^3
		let n7 = add n1 n3; n8 = add n2 n4 in
		-- zr = n5 * z1 * z2
		let zr = mul n5 (mul z1 z2) in
		-- xr = n6^2 - n5^2 * n7
		let xr = sub (sqr n6) (mul (sqr n5) n7) in
		-- n9 = n5^2 * n7 - 2*xr
		let n9 = sub (mul (sqr n5) n7) (xr `shiftL` 1) in
		-- yr2 = (n6 * n9 - n8 * n5^3)
		let yr2 = sub (mul n6 n9) (mul n8 (mul n5 (sqr n5))) in
		-- yr2/2 - add (odd) p to yr2 if yr2 is odd
		let yr = if testBit yr2 0 then (yr2 + p) `shiftR` 1 else yr2 `shiftR` 1 in
		ECJProjective xr yr zr

c2_point_op :: Monad m => ECGroupChar2Polynom -> Integer -> (Integer, Integer) -> (Integer, Integer) -> m ECPoint
c2_point_op p a (x1,y1) (x2,y2) = do
	-- if x1 == x2 == 0 then y1 == y2 (only one solution), and -(x1,y1) = (x1,y1) = (x2,y2) -> return Infinity
	-- if x1 == x2 and y1 /= y2 (at most two solutions) - then again -(x1,y1) = (x2,y2) -> return Infinity
	let samex = x1 == x2
	if samex && (y1 /= y2 || x1 == 0) then return ECPoint_Infinity else do
		-- HAVE: if samex -> y1 == y2
		-- t = x1 + x2    (samex <=> t = 0)
		let t = c2add' x1 x2
		-- IF samex: s = y2/x2 + x2
		-- ELSE    : s = (y1 + y2) / t
		s <- if samex then c2div p y2 x2 >>= return . c2add' x2 else c2div p (c2add' y1 y2) t
		-- xr = s^2 + s + a + t
		let xr = c2add' (c2sqr' p s) (c2add' s $ c2add' a t)
		-- yr = s*(x2 + xr) + xr + y2
		let yr = c2add' (c2mul' p s $ c2add' x2 xr) $ c2add' xr y2
		return $ ECAffine xr yr

point_dbl :: Monad m => ECGroup -> ECPoint -> m ECPoint
point_dbl _ ECPoint_Infinity = return ECPoint_Infinity
point_dbl (ECGroup (PrimeField p) a _) p1 = return $ p_point_dbl p a (jProjectiveCoords p1)
point_dbl (ECGroup f@(Char2Field p) a _) p1 = do
	Just ap1 <- affineCoords f p1
	c2_point_op p a ap1 ap1

point_op :: Monad m => ECGroup -> ECPoint -> ECPoint -> m ECPoint
point_op _ ECPoint_Infinity x = return x
point_op _ x ECPoint_Infinity = return x
point_op (ECGroup (PrimeField p) a _) p1 p2 = return $ p_point_op p a (jProjectiveCoords p1) (jProjectiveCoords p2)
point_op (ECGroup f@(Char2Field p) a _) p1 p2 = do
	Just ap1 <- affineCoords f p1
	Just ap2 <- affineCoords f p2
	c2_point_op p a ap1 ap2

point_inv :: ECGroup -> ECPoint -> ECPoint
point_inv _                             ECPoint_Infinity     = ECPoint_Infinity
point_inv (ECGroup (PrimeField p) _ _) (ECAffine x y)        = ECAffine x (if y == 0 then 0 else p - y)
point_inv (ECGroup (PrimeField p) _ _) (ECJProjective x y z) = ECJProjective x (if y == 0 then 0 else p - y) z
point_inv (ECGroup (Char2Field _) _ _) (ECAffine x y)        = ECAffine x (c2add' x y)
point_inv (ECGroup (Char2Field p) _ _) (ECJProjective x y z) = ECJProjective x (c2add' y $ c2mul' p x z) z


point_exp :: (Integral e, Bits e, Monad m) => ECGroup -> ECPoint -> e -> m ECPoint
point_exp g p e' = go ECPoint_Infinity p e' where
	go :: (Integral e, Bits e, Monad m) => ECPoint -> ECPoint -> e -> m ECPoint
	go r _ 0 = return r
	go r x 1 = point_op g r x
	go r x e = point_dbl g x >>= \x' -> if testBit e 0 then point_op g r x >>= \r' -> go r' x' (e `shiftR` 1) else go r x' (e `shiftR` 1)

-- Prime: y^2 = x^3 + a*x + b
-- Char2: y^2 + x*y = x^3 + a*x^2 + b
data ECGroup
	= ECGroup { group_field :: ECField, group_a, group_b :: Integer }
	deriving (Eq, Show)

data ECCurve = ECCurve { curve_name :: Maybe TLSEllipticNameCurve, curve_group :: ECGroup, curve_base :: ECPoint, curve_order, curve_cofactor :: Integer}
instance Eq ECCurve where
	(ECCurve _ g b o f) == (ECCurve _ g' b' o' f') = g == g' && b == b' && o == o' && f == f'
instance Show ECCurve where
	show (ECCurve (Just n) _ _ _ _) = "ECCurve {name = " ++ show n ++ "}"
	show (ECCurve Nothing g b o f) = "ECCurve {group = " ++ show g ++ ", base = " ++ show b ++ ", order = " ++ show o ++ ", cofactor = " ++ show f ++ "}"


curve_exp :: Monad m => ECCurve -> ECPoint -> Integer -> m ECPoint
curve_exp c b e = point_exp (curve_group c) b e
curve_exp' :: Monad m => ECCurve -> Integer -> m ECPoint
curve_exp' c e = curve_exp c (curve_base c) e
curve_inv :: ECCurve -> ECPoint -> ECPoint
curve_inv c x = point_inv (curve_group c) x
curve_affine :: Monad m => ECCurve -> ECPoint -> m ECPoint
curve_affine c p = do
	p' <- affineCoords (group_field $ curve_group c) p
	case p' of
		Nothing -> return ECPoint_Infinity
		Just (x, y) -> return $ ECAffine x y
curve_has :: ECCurve -> ECPoint -> Bool
curve_has c p = group_has (curve_group c) p
curve_op :: Monad m => ECCurve -> ECPoint -> ECPoint -> m ECPoint
curve_op c = point_op (curve_group c)
curve_eq :: ECCurve -> ECPoint -> ECPoint -> Bool
curve_eq = field_eq . group_field . curve_group


group_has :: ECGroup -> ECPoint -> Bool
group_has _ ECPoint_Infinity = True
group_has (ECGroup (PrimeField p) a b) (ECJProjective x y z) =
	let mul = pmul' p; sqr = psqr' p; add = padd' p in
	-- y^2/z^6 = b + x/z^2*(a+x^2/z^2)
	-- y^2 = z^6*b + x*(a*z^4 + x^2)
	let z2 = sqr z; z4 = sqr z2; z6 = mul z2 z4 in
	sqr y == add (mul z6 b) (mul x $ add (mul a z4) $ sqr x)
group_has (ECGroup (PrimeField p) a b) (ECAffine x y) =
	let mul = pmul' p; sqr = psqr' p; add = padd' p in
	-- y^2 == b + x*(a+x^2)
	sqr y == (add b $ mul x $ add a $ sqr x)
group_has (ECGroup (Char2Field p) a b) (ECAffine x y) =
	let mul = c2mul' p; sqr = c2sqr' p; add = c2add' in
	-- y^2 == b + x(y + x*(a + x))
	sqr y == (add b $ mul x $ add y $ mul x $ add a x)
group_has (ECGroup (Char2Field p) a b) (ECJProjective x y z) =
	let mul = c2mul' p; sqr = c2sqr' p; add = c2add' in
	-- y^2 == b*z^6 + x*y*z + x^2*a*z^2 + x^3
	-- y^2 == b*z^6 + x*(y*z + x*(x + a*z^2))
	let z2 = sqr z; z6 = mul z2 (sqr z2) in
	sqr y == (add (mul b z6) $ mul x $ add (mul y z) $ mul x $ add x $ mul a z2)

group_len :: ECGroup -> Int
group_len = field_len . group_field

uncompress :: ECGroup -> Integer -> Bool -> Maybe Integer
uncompress (ECGroup (PrimeField field) a b) x ybit = do
	let r = (a * x + b + powerMod x (3::Int) field) `mod` field
	y' <- sqrtModP r field
	return $ if (y' `mod` 2 == 1) /= ybit then field - y' else y'
uncompress (ECGroup (Char2Field p) _ b) 0 False = return $ c2sqrt' p b
uncompress (ECGroup (Char2Field _) _ _) 0 _ = Nothing
uncompress g@(ECGroup (Char2Field p) a b) x ybit = do
	-- solve quad (b / x^2 + a + x)
	xinv <- c2inv p x
	z <- c2solveQuad p $ c2mod p $ c2mul' p b (c2sqr' p xinv) `xor` a `xor` x
	let y = c2mul' p z x
	sign <- pointSign g (x, y)
	if sign == ybit then return y else return $ y `xor` x

pointSign :: ECGroup -> (Integer, Integer) -> Maybe Bool
pointSign (ECGroup (PrimeField _) _ _) (_, y) = Just $ y `mod` 2 == 1
pointSign (ECGroup (Char2Field _) _ _) (0, _) = Just False
pointSign (ECGroup f@(Char2Field _) _ _) (x, y) = do
	i <- fdiv (fc y) (fc x) f
	return $ i `mod` 2 == 1

putPointUncompressed :: Monad m => ECGroup -> ECPoint -> Serializer m ()
putPointUncompressed group p = affinePoint (ECNumber group p) >>= \a -> case a of
	Nothing -> putByte 0x00 -- inifinity
	Just (x, y) -> do
		putByte 0x04
		putUnsigned (group_len group) x
		putUnsigned (group_len group) y
putPointHybrid :: Monad m => ECGroup -> ECPoint -> Serializer m ()
putPointHybrid group p = affinePoint (ECNumber group p) >>= \a -> case a of
	Nothing -> putByte 0x00 -- inifinity
	Just (x, y) -> do
		case pointSign group (x, y) of
			Just True -> putByte 0x06
			Just False -> putByte 0x07
			Nothing -> fail "div failed"
		putUnsigned (group_len group) x
		putUnsigned (group_len group) y
putPointCompressed :: Monad m => ECGroup -> ECPoint -> Serializer m ()
putPointCompressed group p = affinePoint (ECNumber group p) >>= \a -> case a of
	Nothing -> putByte 0x00 -- inifinity
	Just (x, y) -> do
		case pointSign group (x, y) of
			Just True -> putByte 0x02
			Just False -> putByte 0x03
			Nothing -> fail "point sign failed"
		putUnsigned (group_len group) x

parsePoint :: Monad m => ECCurve -> Deserializer m ECPoint
parsePoint curve = parsePoint' (curve_group curve)

parsePoint' :: Monad m => ECGroup -> Deserializer m ECPoint
parsePoint' group = do
	p <- getBlock8 $ _parsePoint group
	if (group_has group p) then return p else fail "point not in curve"

_parsePoint :: Monad m => ECGroup -> Deserializer m ECPoint
_parsePoint group = getByte >>= \t -> case t of
	0x00 -> return ECPoint_Infinity
	0x02 -> do
		x <- getUnsigned (group_len group)
		case uncompress group x False of
			Just y -> case pointSign group (x, y) of
				Just False -> return $ ECAffine x y
				_ -> fail "invalid encoding"
			_ -> fail "invalid encoding"
	0x03 -> do
		x <- getUnsigned (group_len group)
		case uncompress group x True of
			Just y -> case pointSign group (x, y) of
				Just True -> return $ ECAffine x y
				_ -> fail "invalid encoding"
			_ -> fail "invalid encoding"
	0x04 -> return ECAffine `ap` getUnsigned (group_len group) `ap` getUnsigned (group_len group)
	0x06 -> do
		x <- getUnsigned (group_len group)
		y <- getUnsigned (group_len group)
		case pointSign group (x, y) of
			Just False -> return $ ECAffine x y
			_ -> fail "invalid encoding"
	0x07 -> do
		x <- getUnsigned (group_len group)
		y <- getUnsigned (group_len group)
		case pointSign group (x, y) of
			Just True -> return $ ECAffine x y
			_ -> fail "invalid encoding"
	_ -> fail "invalid encoding"

parseCurve :: Monad m => Deserializer m ECCurve
parseCurve = do
		getByte >>= \t -> case t of
			0x01 -> do --explicit prime
				getBigint >>= return . PrimeField >>= cont
			0x02 -> do --explicit char2
				m <- getUnsigned 2
				getByte >>= \tt -> case tt of
					0x01 -> do -- ec_basis_trinomial
						k <- getSmallint
						cont (Char2Field $ Char2Trinomial m k)
					0x02 -> do -- ec_basis_pentanomial
						k1 <- getSmallint
						k2 <- getSmallint
						k3 <- getSmallint
						cont (Char2Field $ Char2Pentanomial m k1 k2 k3)
					_ -> fail $ "Unsupported ECBasisType " ++ show tt
			0x03 -> do -- named_curve
				c <- getEnum
				case named_curve c of
					Just c' -> return c'
					Nothing -> fail $ "Unsupported named curve " ++ show c
			_ -> fail $ "Unknown ECCurveType " ++ show t
	where
		cont :: Monad m => ECField -> Deserializer m ECCurve
		cont field = do
			group <- return (ECGroup field) `ap` getBigint `ap` getBigint
			return (ECCurve Nothing group) `ap` parsePoint' group `ap` getBigint `ap` getBigint
		getSmallint :: Monad m => Deserializer m Int
		getSmallint = getByte >>= getUnsigned . fromIntegral
		getBigint :: Monad m => Deserializer m Integer
		getBigint = getByte >>= getUnsigned . fromIntegral


named_curve :: Monad m => TLSEllipticNameCurve -> m ECCurve
named_curve TLS_EC_secp192k1 = return $ ECCurve (Just TLS_EC_secp192k1)
	(ECGroup (PrimeField
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37)
		0x000000000000000000000000000000000000000000000000
		0x000000000000000000000000000000000000000000000003)
	(ECAffine
		0xDB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D
		0x9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D)
	0xFFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D 1

-- S = 3045AE6F C8422F64 ED579528 D38120EA E12196D5
named_curve TLS_EC_secp192r1 = return $ ECCurve (Just TLS_EC_secp192r1)
	(ECGroup (PrimeField
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF)
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC
		0x64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1)
	(ECAffine
		0x188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012
		0x07192B95FFC8DA78631011ED6B24CDD573F977A11E794811)
	0xFFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831 1

named_curve TLS_EC_secp224k1 = return $ ECCurve (Just TLS_EC_secp224k1)
	(ECGroup (PrimeField
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFE56D)
		0x00000000000000000000000000000000000000000000000000000000
		0x00000000000000000000000000000000000000000000000000000005)
	(ECAffine
		0xA1455B334DF099DF30FC28A169A467E9E47075A90F7E650EB6B7A45C
		0x7E089FED7FBA344282CAFBD6F7E319F7C0B0BD59E2CA4BDB556D61A5)
	0x0000000000000000000000000001DCE8D2EC6184CAF0A971769FB1F7 1

-- S = BD713447 99D5C7FC DC45B59F A3B9AB8F 6A948BC5
named_curve TLS_EC_secp224r1 = return $ ECCurve (Just TLS_EC_secp224r1)
	(ECGroup (PrimeField
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001)
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
		0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4)
	(ECAffine
		0xB70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21
		0xBD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34)
	0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D 1

named_curve TLS_EC_secp256k1 = return $ ECCurve (Just TLS_EC_secp256k1)
	(ECGroup (PrimeField
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
		0x0000000000000000000000000000000000000000000000000000000000000000
		0x0000000000000000000000000000000000000000000000000000000000000007)
	(ECAffine
		0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
		0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
	0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 1

-- S = C49D3608 86E70493 6A6678E1 139D26B7 819F7E90
named_curve TLS_EC_secp256r1 = return $ ECCurve (Just TLS_EC_secp256r1)
	(ECGroup (PrimeField
		0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF)
		0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
		0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B)
	(ECAffine
		0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
		0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
	0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 1

-- S = A335926A A319A27A 1D00896A 6773A482 7ACDAC73
named_curve TLS_EC_secp384r1 = return $ ECCurve (Just TLS_EC_secp384r1)
	(ECGroup (PrimeField
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF)
		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC
		0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF)
	(ECAffine
		0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7
		0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F)
	0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973 1

-- S = D09E8800 291CB853 96CC6717 393284AA A0DA64BA
named_curve TLS_EC_secp521r1 = return $ ECCurve (Just TLS_EC_secp521r1)
	(ECGroup (PrimeField
		0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)
		0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC
		0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00)
	(ECAffine
		0x00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66
		0x011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650)
	0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409 1

named_curve TLS_EC_sect163k1 = return $ ECCurve (Just TLS_EC_sect163k1)
	(ECGroup (Char2Field $ Char2Pentanomial 163 7 6 3) -- X^163 + X^7 + X^6 + X^3 + 1
		0x000000000000000000000000000000000000000001
		0x000000000000000000000000000000000000000001)
	(ECAffine
		0x02FE13C0537BBC11ACAA07D793DE4E6D5E5C94EEE8
		0x0289070FB05D38FF58321F2E800536D538CCDAA3D9)
	0x04000000000000000000020108A2E0CC0D99F8A5EF 2

-- S = 24B7B137 C8A14D69 6E676875 6151756F D0DA2E5C
named_curve TLS_EC_sect163r1 = return $ ECCurve (Just TLS_EC_sect163r1)
	(ECGroup (Char2Field $ Char2Pentanomial 163 7 6 3) -- X^163 + X^7 + X^6 + X^3 + 1
		0x07B6882CAAEFA84F9554FF8428BD88E246D2782AE2
		0x0713612DCDDCB40AAB946BDA29CA91F73AF958AFD9)
	(ECAffine
		0x0369979697AB43897789566789567F787A7876A654
		0x00435EDB42EFAFB2989D51FEFCE3C80988F41FF883)
	0x03FFFFFFFFFFFFFFFFFFFF48AAB689C29CA710279B 2

-- S = 85E25BFE 5C86226C DB12016F 7553F9D0 E693A268
named_curve TLS_EC_sect163r2 = return $ ECCurve (Just TLS_EC_sect163r2)
	(ECGroup (Char2Field $ Char2Pentanomial 163 7 6 3) -- X^163 + X^7 + X^6 + X^3 + 1
		0x000000000000000000000000000000000000000001
		0x020A601907B8C953CA1481EB10512F78744A3205FD)
	(ECAffine
		0x03F0EBA16286A2D57EA0991168D4994637E8343E36
		0x00D51FBC6C71A0094FA2CDD545B11C5C0C797324F1)
	0x040000000000000000000292FE77E70C12A4234C33 2

named_curve TLS_EC_sect233k1 = return $ ECCurve (Just TLS_EC_sect233k1)
	(ECGroup (Char2Field $ Char2Trinomial 233 74) -- X^233 + X^74 + 1
		0x000000000000000000000000000000000000000000000000000000000000
		0x000000000000000000000000000000000000000000000000000000000001)
	(ECAffine
		0x017232BA853A7E731AF129F22FF4149563A419C26BF50A4C9D6EEFAD6126
		0x01DB537DECE819B7F70F555A67C427A8CD9BF18AEB9B56E0C11056FAE6A3)
	0x8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF 4

-- S = 74D59FF0 7F6B413D 0EA14B34 4B20A2DB 049B50C3
named_curve TLS_EC_sect233r1 = return $ ECCurve (Just TLS_EC_sect233r1)
	(ECGroup (Char2Field $ Char2Trinomial 233 74) -- X^233 + X^74 + 1
		0x000000000000000000000000000000000000000000000000000000000001
		0x0066647EDE6C332C7F8C0923BB58213B333B20E9CE4281FE115F7D8F90AD)
	(ECAffine
		0x00FAC9DFCBAC8313BB2139F1BB755FEF65BC391F8B36F8F8EB7371FD558B
		0x01006A08A41903350678E58528BEBF8A0BEFF867A7CA36716F7E01F81052)
	0x01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7 2

named_curve TLS_EC_sect239k1 = return $ ECCurve (Just TLS_EC_sect239k1)
	(ECGroup (Char2Field $ Char2Trinomial 239 158) -- X^239 + X^158 + 1
		0x000000000000000000000000000000000000000000000000000000000000
		0x000000000000000000000000000000000000000000000000000000000001)
	(ECAffine
		0x29A0B6A887A983E9730988A68727A8B2D126C44CC2CC7B2A6555193035DC
		0x76310804F12E549BDB011C103089E73510ACB275FC312A5DC6B76553F0CA)
	0x2000000000000000000000000000005A79FEC67CB6E91F1C1DA800E478A5 4

named_curve TLS_EC_sect283k1 = return $ ECCurve (Just TLS_EC_sect283k1)
	(ECGroup (Char2Field $ Char2Pentanomial 283 12 7 5) -- X^283 + X^12 + X^7 + X^5 + 1
		0x000000000000000000000000000000000000000000000000000000000000000000000000
		0x000000000000000000000000000000000000000000000000000000000000000000000001)
	(ECAffine
		0x0503213F78CA44883F1A3B8162F188E553CD265F23C1567A16876913B0C2AC2458492836
		0x01CCDA380F1C9E318D90F95D07E5426FE87E45C0E8184698E45962364E34116177DD2259)
	0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61 4

-- S = 77E2B073 70EB0F83 2A6DD5B6 2DFC88CD 06BB84BE
named_curve TLS_EC_sect283r1 = return $ ECCurve (Just TLS_EC_sect283r1)
	(ECGroup (Char2Field $ Char2Pentanomial 283 12 7 5) -- X^283 + X^12 + X^7 + X^5 + 1
		0x000000000000000000000000000000000000000000000000000000000000000000000001
		0x027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5)
	(ECAffine
		0x05F939258DB7DD90E1934F8C70B0DFEC2EED25B8557EAC9C80E2E198F8CDBECD86B12053
		0x03676854FE24141CB98FE6D4B20D02B4516FF702350EDDB0826779C813F0DF45BE8112F4)
	0x03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307 2

named_curve TLS_EC_sect409k1 = return $ ECCurve (Just TLS_EC_sect409k1)
	(ECGroup (Char2Field $ Char2Trinomial 409 87) -- X^409 + X^87 + 1
		0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
		0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001)
	(ECAffine
		0x0060F05F658F49C1AD3AB1890F7184210EFD0987E307C84C27ACCFB8F9F67CC2C460189EB5AAAA62EE222EB1B35540CFE9023746
		0x01E369050B7C4E42ACBA1DACBF04299C3460782F918EA427E6325165E9EA10E3DA5F6C42E9C55215AA9CA27A5863EC48D8E0286B)
	0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5F83B2D4EA20400EC4557D5ED3E3E7CA5B4B5C83B8E01E5FCF 4

-- S = 4099B5A4 57F9D69F 79213D09 4C4BCD4D 4262210B
named_curve TLS_EC_sect409r1 = return $ ECCurve (Just TLS_EC_sect409r1)
	(ECGroup (Char2Field $ Char2Trinomial 409 87) -- X^409 + X^87 + 1
		0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
		0x0021A5C2C8EE9FEB5C4B9A753B7B476B7FD6422EF1F3DD674761FA99D6AC27C8A9A197B272822F6CD57A55AA4F50AE317B13545F)
	(ECAffine
		0x015D4860D088DDB3496B0C6064756260441CDE4AF1771D4DB01FFE5B34E59703DC255A868A1180515603AEAB60794E54BB7996A7
		0x0061B1CFAB6BE5F32BBFA78324ED106A7636B9C5A7BD198D0158AA4F5488D08F38514F1FDF4B4F40D2181B3681C364BA0273C706)
	0x010000000000000000000000000000000000000000000000000001E2AAD6A612F33307BE5FA47C3C9E052F838164CD37D9A21173 2

named_curve TLS_EC_sect571k1 = return $ ECCurve (Just TLS_EC_sect571k1)
	(ECGroup (Char2Field $ Char2Pentanomial 521 10 5 2) -- X^521 + X^10 + X^5 + X^2 + 1
		0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
		0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001)
	(ECAffine
		0x026EB7A859923FBC82189631F8103FE4AC9CA2970012D5D46024804801841CA44370958493B205E647DA304DB4CEB08CBBD1BA39494776FB988B47174DCA88C7E2945283A01C8972
		0x0349DC807F4FBF374F4AEADE3BCA95314DD58CEC9F307A54FFC61EFC006D8A2C9D4979C0AC44AEA74FBEBBB9F772AEDCB620B01A7BA7AF1B320430C8591984F601CD4C143EF1C7A3)
	0x020000000000000000000000000000000000000000000000000000000000000000000000131850E1F19A63E4B391A8DB917F4138B630D84BE5D639381E91DEB45CFE778F637C1001 4

-- S = 2AA058F7 3A0E33AB 486B0F61 0410C53A 7F132310
named_curve TLS_EC_sect571r1 = return $ ECCurve (Just TLS_EC_sect571r1)
	(ECGroup (Char2Field $ Char2Pentanomial 521 10 5 2) -- X^521 + X^10 + X^5 + X^2 + 1
		0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001
		0x02F40E7E2221F295DE297117B7F3D62F5C6A97FFCB8CEFF1CD6BA8CE4A9A18AD84FFABBD8EFA59332BE7AD6756A66E294AFD185A78FF12AA520E4DE739BACA0C7FFEFF7F2955727A)
	(ECAffine
		0x0303001D34B856296C16C0D40D3CD7750A93D1D2955FA80AA5F40FC8DB7B2ABDBDE53950F4C0D293CDD711A35B67FB1499AE60038614F1394ABFA3B4C850D927E1E7769C8EEC2D19
		0x037BF27342DA639B6DCCFFFEB73D69D78C6C27A6009CBBCA1980F8533921E8A684423E43BAB08A576291AF8F461BB2A8B3531D2F0485C19B16E2F1516E23DD3C1A4827AF1B8AC15B)
	0x03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE661CE18FF55987308059B186823851EC7DD9CA1161DE93D5174D66E8382E9BB2FE84E47 2

-- deprecated curves
named_curve TLS_EC_secp160k1 = return $ ECCurve (Just TLS_EC_secp160k1)
	(ECGroup (PrimeField
		0X00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73)
		0X000000000000000000000000000000000000000000
		0X000000000000000000000000000000000000000007)
	(ECAffine
		0X003B4C382CE37AA192A4019E763036F4F5DD4D7EBB
		0X00938CF935318FDCED6BC28286531733C3F03C4FEE)
	0X0100000000000000000001B8FA16DFAB9ACA16B6B3 1

-- S = 1053CDE4 2C14D696 E6768756 1517533B F3F83345
named_curve TLS_EC_secp160r1 = return $ ECCurve (Just TLS_EC_secp160r1)
	(ECGroup (PrimeField
		0X00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF)
		0X00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC
		0X001C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45)
	(ECAffine
		0X004A96B5688EF573284664698968C38BB913CBFC82
		0X0023A628553168947D59DCC912042351377AC5FB32)
	0X0100000000000000000001F4C8F927AED3CA752257 1

-- S = B99B99B0 99B323E0 2709A4D6 96E67687 56151751
named_curve TLS_EC_secp160r2 = return $ ECCurve (Just TLS_EC_secp160r2)
	(ECGroup (PrimeField
		0X00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73)
		0X00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC70
		0X00B4E134D3FB59EB8BAB57274904664D5AF50388BA)
	(ECAffine
		0X0052DCB034293A117E1F4FF11B30F7199D3144CE6D
		0X00FEAFFEF2E331F296E071FA0DF9982CFEA7D43F2E)
	0X0100000000000000000000351EE786A818F3A1A16B 1

-- S = 103FAEC7 4D696E67 68756151 75777FC5 B191EF30
named_curve TLS_EC_sect193r1 = return $ ECCurve (Just TLS_EC_sect193r1)
	(ECGroup (Char2Field $ Char2Trinomial 193 15) -- X^193 + X^15 + 1
		0X0017858FEB7A98975169E171F77B4087DE098AC8A911DF7B01
		0X00FDFB49BFE6C3A89FACADAA7A1E5BBC7CC1C2E5D831478814)
	(ECAffine
		0X01F481BC5F0FF84A74AD6CDF6FDEF4BF6179625372D8C0C5E1
		0X0025E399F2903712CCF3EA9E3A1AD17FB0B3201B6AF7CE1B05)
	0X01000000000000000000000000C7F34A778F443ACC920EBA49 2

-- S = 10B7B4D6 96E67687 56151751 37C8A16F D0DA2211
named_curve TLS_EC_sect193r2 = return $ ECCurve (Just TLS_EC_sect193r2)
	(ECGroup (Char2Field $ Char2Trinomial 193 15) -- X^193 + X^15 + 1
		0X0163F35A5137C2CE3EA6ED8667190B0BC43ECD69977702709B
		0X00C9BB9E8927D4D64C377E2AB2856A5B16E3EFB7F61D4316AE)
	(ECAffine
		0X00D9B67D192E0367C803F39E1A7E82CA14A651350AAE617E8F
		0X01CE94335607C304AC29E7DEFBD9CA01F596F927224CDECF6C)
	0X010000000000000000000000015AAB561B005413CCD4EE99D5 2

-- http://tools.ietf.org/html/rfc5639
named_curve TLS_EC_brainpoolP256r1 = return $ ECCurve (Just TLS_EC_brainpoolP256r1)
	(ECGroup (PrimeField
		0XA9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377)
		0X7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9
		0X26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6)
	(ECAffine
		0X8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262
		0X547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997)
	0XA9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7 1

named_curve TLS_EC_brainpoolP384r1 = return $ ECCurve (Just TLS_EC_brainpoolP384r1)
	(ECGroup (PrimeField
		0X8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53)
		0X7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826
		0X04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11)
	(ECAffine
		0X1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E
		0X8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315)
	0X8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565 1


named_curve TLS_EC_brainpoolP512r1 = return $ ECCurve (Just TLS_EC_brainpoolP512r1)
	(ECGroup (PrimeField
		0XAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3)
		0X7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA
		0X3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723)
	(ECAffine
		0X81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822
		0X7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892)
	0XAADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069 1

named_curve n@TLS_EC_arbitrary_explicit_prime_curves = fail $ "curve class " ++ show n ++ " is not a curve"
named_curve n@TLS_EC_arbitrary_explicit_char2_curves = fail $ "curve class " ++ show n ++ " is not a curve"
named_curve n@(TLS_EllipticNameCurve_Raw _) = fail $ "unknown curve name " ++ show n

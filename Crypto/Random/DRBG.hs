{-# LANGUAGE EmptyDataDecls, FlexibleInstances, TypeSynonymInstances #-}
module Crypto.Random.DRBG
	( HMAC, HASH
	, GenXor(..)
	, GenAutoReseed(..)
	, module Crypto.Random
	) where

import qualified Crypto.Random.DRBG.HMAC as M
import qualified Crypto.Random.DRBG.Hash as H
import Crypto.Classes
import Crypto.Random
import Crypto.Hash.SHA512 (SHA512)
import Crypto.Hash.SHA384 (SHA384)
import Crypto.Hash.SHA256 (SHA256)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Tagged (Tagged(..))
import Data.Bits (xor)
import Control.Arrow (second)

instance H.SeedLength SHA512 where
	seedlen = Tagged 888

instance H.SeedLength SHA384 where
	seedlen = Tagged  888

instance H.SeedLength SHA256 where
	seedlen = Tagged 440

-- |An alias for an HMAC generator using SHA512
type HMAC = M.State SHA512

-- |An Alias for a HASH generators using SHA512
type HASH = H.State SHA512

newGenAutoReseed :: (CryptoRandomGen a, CryptoRandomGen b) => B.ByteString -> Int -> Either GenError (GenAutoReseed a b)
newGenAutoReseed bs rsInterval=
	let (b1,b2) = B.splitAt (genSeedLength `for` fromRight g1) bs
	    g1 = newGen b1
	    g2 = newGen b2
	    fromRight (Right x) = x
	in case (g1, g2) of
		(Right a, Right b) -> Right $ GenAutoReseed a b rsInterval 0
		(Left e, _) -> Left e
		(_, Left e) -> Left e

instance CryptoRandomGen HMAC where
	newGen bs = Right $ M.instantiate bs B.empty B.empty
	genSeedLength = Tagged (512 `div` 8)
	genBytes g req =
		let res = M.generate g (req * 8) B.empty
		in case res of
			Nothing -> Left NeedReseed
			Just (r,s) -> Right (B.concat . L.toChunks $ r, s)
	genBytesWithEntropy g req ai =
		let res = M.generate g (req * 8) ai
		in case res of
			Nothing -> Left NeedReseed
			Just (r,s) -> Right (B.concat . L.toChunks $ r, s)
	reseed g ent = Right $ M.reseed g ent B.empty

fmap' :: (b -> c) -> Either a b -> Either a c
fmap' _ (Left x) = Left x
fmap' f (Right g) = Right (f g)

instance CryptoRandomGen HASH where
	newGen bs = Right $ H.instantiate bs B.empty B.empty
	genSeedLength = Tagged $ 512 `div` 8
	genBytes g req = 
		let res = H.generate g (req * 8) B.empty
		in case res of
			Nothing -> Left NeedReseed
			Just (r,s) -> Right (B.concat . L.toChunks $ r, s)
	genBytesWithEntropy g req ai =
		let res = H.generate g (req * 8) ai
		in case res of
			Nothing -> Left NeedReseed
			Just (r,s) -> Right (B.concat . L.toChunks $ r, s)
	reseed g ent = Right $ H.reseed g ent B.empty

helper1 :: Tagged (GenAutoReseed a b) Int -> a
helper1 = const undefined

helper2 :: Tagged (GenAutoReseed a b) Int -> b
helper2 = const undefined

-- |@g :: GenAutoReseed a b@ is a generator of type a that gets
-- automatically reseeded by generator b upon every 32kB generated.
data GenAutoReseed a b = GenAutoReseed !a !b !Int !Int

instance (CryptoRandomGen a, CryptoRandomGen b) => CryptoRandomGen (GenAutoReseed a b) where
	newGen bs = newGenAutoReseed bs (2^15)
	genSeedLength =
		let a = helper1 res
		    b = helper2 res
		    res = Tagged $ genSeedLength `for` a + genSeedLength `for` b
		in res
	genBytes (GenAutoReseed a b rs cnt) req = do
		(res, aNew) <- genBytes a req
		gNew <- if (cnt + req) > rs
			  then do (ent,b') <- genBytes b (genSeedLength `for` a)
				  a'  <- reseed aNew ent
				  return (GenAutoReseed a' b' rs 0)
			  else return $ GenAutoReseed aNew b rs (cnt + req)
		return (res, gNew)
	genBytesWithEntropy (GenAutoReseed a b rs cnt) req entropy = do
		(res, aNew) <- genBytesWithEntropy a req entropy
		gNew <- if (cnt + req) > rs
			  then do (ent,b') <- genBytes b (genSeedLength `for` a)
				  a'  <- reseed aNew ent
				  return (GenAutoReseed a' b' rs 0)
			  else return $ GenAutoReseed aNew b rs (cnt + req)
		return (res, gNew)
	reseed (GenAutoReseed a b rs _) ent = do
		let (b1,b2) = B.splitAt (genSeedLength `for` a) ent
		a' <- reseed a b1
		b' <- reseed b b2
		return $ GenAutoReseed a' b' rs 0

-- |@g :: GenXor a b@ generates bytes with sub-generators a and b 
-- and exclusive-or's the outputs to produce the resulting bytes.
data GenXor a b = GenXor !a !b

helperXor1 :: Tagged (GenXor a b) c -> a
helperXor1 = const undefined
helperXor2 :: Tagged (GenXor a b) c -> b
helperXor2 = const undefined

instance (CryptoRandomGen a, CryptoRandomGen b) => CryptoRandomGen (GenXor a b) where
	newGen bs = do
		let g1 = newGen b1
		    g2 = newGen b2
		    (b1,b2) = B.splitAt (genSeedLength `for` fromRight g1) bs
		    fromRight (Right x) = x
		a <- g1
		b <- g2
		return (GenXor a b)
	genSeedLength =
		let a = helperXor1 res
		    b = helperXor2 res
		    res = Tagged $ (genSeedLength `for` a) + (genSeedLength `for` b)
		in res
	genBytes (GenXor a b) req = do
		(r1, a') <- genBytes a req
		(r2, b') <- genBytes b req
		return (zwp' r1 r2, GenXor a' b')
	genBytesWithEntropy (GenXor a b) req ent = do
		(r1, a') <- genBytesWithEntropy a req ent
		(r2, b') <- genBytesWithEntropy b req ent
		return (zwp' r1 r2, GenXor a' b')
	reseed (GenXor a b) ent = do
		let (b1, b2) = B.splitAt (genSeedLength `for` a) ent
		a' <- reseed a b1
		b' <- reseed b b2
		return (GenXor a' b')

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be optimized (at compile time) 
-- to use the bytestring libraries 'zipWith'' function.
zwp' a = B.pack . B.zipWith xor a

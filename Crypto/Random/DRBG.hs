{-# LANGUAGE EmptyDataDecls, FlexibleInstances, TypeSynonymInstances #-}
module Crypto.Random.DRBG
	( HMAC, HASH
	, GenXor(..)
	, GenAutoReseed(..)
	, GenBuffered
	, module Crypto.Random
	) where

import qualified Crypto.Random.DRBG.HMAC as M
import qualified Crypto.Random.DRBG.Hash as H
import Crypto.Classes
import Crypto.Random
import Crypto.Hash.SHA512 (SHA512)
import Crypto.Hash.SHA384 (SHA384)
import Crypto.Hash.SHA256 (SHA256)
import Crypto.Hash.SHA224 (SHA224)
import Crypto.Hash.SHA1 (SHA1)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Tagged
import Data.Bits (xor)
import Control.Parallel (par)

instance H.SeedLength SHA512 where
	seedlen = Tagged 888

instance H.SeedLength SHA384 where
	seedlen = Tagged  888

instance H.SeedLength SHA256 where
	seedlen = Tagged 440

instance H.SeedLength SHA224 where
	seedlen = Tagged 440

instance H.SeedLength SHA1 where
	seedlen = Tagged 440

-- |An alias for an HMAC generator using SHA512
type HMAC = M.State SHA512

-- |An Alias for a HASH generator using SHA512
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
--
-- @reseed g ent@ will reseed both the component generators by
-- breaking ent up into two parts determined by the genSeedLength of each generator.
--
-- @genBytes@ will generate the requested bytes with generator @a@ and reseed @a@
-- using generator @b@ if there has been 32KB of generated data since the last reseed.
-- Note a request for > 32KB of data will be filled in one request to generator @a@ before
-- @a@ is reseeded by @b@.
--
-- @genBytesWithEntropy@ will push the entropy into generator @a@, leaving generator
-- @b@ unchanged unless the count hits 32KB, in which case it is reseeds @a@ 
-- (for a second time) using @b@ as in normal operation via @genBytes@.
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

-- |@g :: GenBuffered a@ is a generator of type @a@ that attempts to
-- maintain a buffer of random values size > 1MB and < 5MB at any time.
--
-- Because of the way in which the buffer is computed (at idle times) and
-- information on the previous generator is lost, it basically is not possible
-- to reseed this generator after a GenError.
data GenBuffered g = GenBuffered (Either GenError (B.ByteString,g)) B.ByteString

proxyToGenBuffered :: Proxy g -> Proxy (Either GenError (GenBuffered g))
proxyToGenBuffered = const Proxy

bufferMinSize = 2^20
bufferMaxSize = 2^22

instance (CryptoRandomGen g) => CryptoRandomGen (GenBuffered g) where
	newGen bs = do
		g <- newGen bs
		(rs,g') <- genBytes g  bufferMinSize
		let new = genBytes g' bufferMinSize
		return (GenBuffered new rs)
	genSeedLength =
		let a = help res
		    res = Tagged $ genSeedLength `for` a
		in res
	  where
	  help :: Tagged (GenBuffered g) c -> g
	  help = const undefined
	genBytes gb@(GenBuffered g bs) req
		| B.length bs < bufferMinSize =
			case g of
				Left err  -> Left err
				Right g   -> Left (GenErrorOther "Buffering generator failed to buffer properly - unknown reason")
		| req > B.length bs = Left RequestedTooManyBytes
		| B.length bs - req < bufferMinSize =
			case g of
				Left err -> Left err -- We could satisfy _this_ request and fail after the buffer runs out, but why bother?
				Right (rnd, gen) ->
					let new = genBytes gen bufferMinSize
					in (eval new) `par` (genBytes (GenBuffered new (B.append bs rnd)) req)
		| otherwise = Right (B.take req bs, GenBuffered g (B.drop req bs))
	genBytesWithEntropy g req ent = reseed g ent >>= \gen -> genBytes gen req
	reseed (GenBuffered g bs) ent = do
		(rs, g') <- g
		g'' <- reseed g' ent
		let new = genBytes g'' bufferMinSize
		    bs' = B.take bufferMaxSize (B.append bs rs)
		return (GenBuffered new bs')

eval :: Either x (B.ByteString, g) -> Either x (B.ByteString, g)
eval (Left x) = Left x
eval (Right (g,bs)) = bs `seq` (g `seq` (Right (g, bs)))

-- |zipWith xor + Pack
-- As a result of rewrite rules, this should automatically be optimized (at compile time) 
-- to use the bytestring libraries 'zipWith'' function.
zwp' a = B.pack . B.zipWith xor a

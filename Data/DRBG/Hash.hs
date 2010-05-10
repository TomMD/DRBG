{-# LANGUAGE BangPatterns #-}
module Data.DRBG.Hash where
-- NIST SP 800-90 

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.DRBG
import Data.DRBG.HashDF
import Data.Crypto.Classes
import Data.Serialize (encode)
import qualified Data.Binary as Bin
import Data.Bits (shiftR, shiftL)

class SeedLength h where
  seedlen :: h -> Int

reseed_interval = 2^48

-- Section 10.1.1.1, pg 35
data State h = St
	{ value			:: B.ByteString -- seedlen bits
	, constant		:: B.ByteString -- seedlen bits
	, counter		:: Integer      -- Number of RBG requests since last reseed
	-- start admin info
	, securityStrength	:: Int
	, predictionResistant	:: Bool
	, hashAlg		:: h
	} deriving (Eq, Ord, Show)

-- step 9 from sectoin 9.1 (pg 26)
-- section 10.1.1.2 pg 36
instantiateAlgorithm :: (Hash h c d, SeedLength h) => h -> Entropy -> Nonce -> PersonalizationString -> State h
instantiateAlgorithm h entropyInput nonce perStr =
	let seedMaterial = B.concat [entropyInput, nonce, perStr]
	    seed = hash_df h seedMaterial (seedlen h) :: B.ByteString
	    v = seed
	    c = hash_df h (B.cons 0 v) (seedlen h)
	in St v c 1 256 True h

-- section 10.1.1.3 pg 37
reseedAlgorithm :: (SeedLength h, Hash h c d) => State h -> Entropy -> AdditionalInput -> State h
reseedAlgorithm st ent additionalInput =
	let seedMaterial = B.concat [B.pack [1], value st, ent, additionalInput]
	    seed = hash_df h seedMaterial (seedlen h)
	    v = seed
	    c = hash_df h (B.cons 0 v) (seedlen h)
	in St v c 1 (strength h) True h
  where h = hashAlg st

-- section 10.1.1.4 pg 38
-- Nothing indicates a need to reseed
generateAlgorithm :: (Hash h c d, SeedLength h) => State h -> BitLen -> AdditionalInput -> Maybe (RandomBits, State h)
generateAlgorithm st req additionalInput =
	if (counter st > reseed_interval)
		then Nothing
		else Just (retBits, st { value = v2, counter = cnt})
  where
  w = hash [B.singleton 2, value st, additionalInput]
  v1 = if B.length additionalInput == 0 then value st else i2bs slen (bs2i (value st) + bs2i w)
  retBits = hashGen hsh req v1
  h = hash [B.cons 3 v1]
  v2 = i2bs slen (sum $ counter st : map bs2i [v1, h, constant st])
  cnt = counter st + 1
  slen = seedlen hsh
  hsh = hashAlg st
  hash = encode . hashFunction hsh . L.fromChunks

-- 10.1.1.4, pg 39
hashGen :: (Hash h c d, SeedLength h) => h -> BitLen -> B.ByteString -> RandomBits
hashGen h r val = L.take (fromIntegral reqBytes) . head . drop m . map snd $ w
  where
  reqBytes = if r `mod` 8 == 0 then r `div` 8 else (r + 8) `div` 8
  m = if r `rem` outlen == 0 then r `div` outlen else (r + outlen) `div` outlen
  dat = val
  w = iterate (\(d,wOld) -> (i2bs slen (bs2i d + 1), L.append wOld (Bin.encode $ hash d))) (val, L.empty)
  slen = seedlen h
  outlen = outputLength h
  hash = hashFunction h . L.fromChunks . \b -> [b]

-- Appendix B
i2bs :: BitLen -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs

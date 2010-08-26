{-# LANGUAGE BangPatterns, MonomorphismRestriction #-}
module Data.DRBG.Hash
	( State(..)
	, reseedInterval
	, SeedLength (..)
	, instantiate
	, reseed
	, generate
	) where
-- NIST SP 800-90 

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.DRBG.Types
import Data.DRBG.HashDF
import Data.Crypto.Classes
import Data.Serialize (encode)
import qualified Data.Binary as Bin
import Data.Bits (shiftR, shiftL)
import Data.Tagged

class SeedLength h where
  seedlen :: Tagged h Int

reseedInterval = 2^48

-- Section 10.1.1.1, pg 35
data State d = St
	{ value			:: B.ByteString -- seedlen bits
	, constant		:: B.ByteString -- seedlen bits
	, counter		:: Integer      -- Number of RBG requests since last reseed
	-- start admin info
	-- , securityStrength	:: Int  IMPLICIT in "hsh" via the Hash class
	, predictionResistant	:: Bool
	, hsh			:: L.ByteString -> d
	}

-- section 10.1.1.2 pg 36
instantiate :: (Hash c d, SeedLength d) => Entropy -> Nonce -> PersonalizationString -> State d
instantiate entropyInput nonce perStr =
	let seedMaterial = B.concat [entropyInput, nonce, perStr]
	    slen = seedlen .::. d
	    seed = hash_df f seedMaterial slen
	    v = seed
	    c = hash_df f (B.cons 0 v) slen
	    f = hash
	    d = f undefined
	in St v c 1 True f

-- section 10.1.1.3 pg 37
reseed :: (SeedLength d, Hash c d) => State d -> Entropy -> AdditionalInput -> State d
reseed st ent additionalInput =
	let seedMaterial = B.concat [B.pack [1], value st, ent, additionalInput]
	    seed = hash_df f seedMaterial (seedlen `for` d)
	    v = seed
	    c = hash_df f (B.cons 0 v) (seedlen `for` d)
	    f = hash
	    d = f undefined
	in St v c 1 True f

-- section 10.1.1.4 pg 38
-- Nothing indicates a need to reseed
generate :: (Hash c d, SeedLength d) => State d -> BitLen -> AdditionalInput -> Maybe (RandomBits, State d)
generate st req additionalInput =
	if (counter st > reseedInterval)
		then Nothing
		else Just (retBits, st { value = v2, counter = cnt})
  where
  w = hash [B.singleton 2, value st, additionalInput]
  v1 = if B.length additionalInput == 0 then value st else i2bs slen (bs2i (value st) + bs2i w)
  retBits = hashGen d req v1
  h = hash [B.cons 3 v1]
  v2 = i2bs slen (sum $ counter st : map bs2i [v1, h, constant st])
  cnt = counter st + 1
  slen = seedlen `for` d
  hash = encode . hashF .  L.fromChunks
  d = hsh st undefined
  hashF = hsh st

-- 10.1.1.4, pg 39
hashGen :: (Hash c d, SeedLength d) => d -> BitLen -> B.ByteString -> RandomBits
hashGen d r val = L.take (fromIntegral reqBytes) . L.fromChunks $ getW val m
  where
  reqBytes = if r `mod` 8 == 0 then r `div` 8 else (r + 8) `div` 8
  m = if r `rem` outlen == 0 then r `div` outlen else (r + outlen) `div` outlen
  getW :: B.ByteString -> Int -> [B.ByteString]
  getW _ 0 = []
  getW dat i =
	let wi = encode (h dat)
	    dat' = i2bs slen (bs2i dat + 1)
	    rest = getW dat' (i-1)
	in wi : rest
  slen = seedlen `for` d
  outlen = outputLength `for` d
  h = hashFunc' d

-- Appendix B
i2bs :: BitLen -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs

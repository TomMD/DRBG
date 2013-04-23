{-# LANGUAGE BangPatterns, MonomorphismRestriction #-}
module Crypto.Random.DRBG.Hash
        ( State, counter
        , reseedInterval
        , SeedLength (..)
        , instantiate
        , reseed
        , generate
        ) where
-- NIST SP 800-90 

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Crypto.Random.DRBG.Types
import Crypto.Random.DRBG.HashDF
import Crypto.Classes
import Data.Serialize (encode)
import Data.Bits (shiftR, shiftL)
import Data.Tagged
import Data.Word (Word64)

class SeedLength h where
  seedlen :: Tagged h Int

reseedInterval :: Word64
reseedInterval = 2^48

-- Section 10.1.1.1, pg 35
data State d = St
        { counter               :: {-# UNPACK #-} !Word64       -- Number of RBG requests since last reseed
        -- start admin info
        , value                 :: B.ByteString -- seedlen bits
        , constant              :: B.ByteString -- seedlen bits
        , hsh                   :: L.ByteString -> d
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
        in St 1 v c f

-- section 10.1.1.3 pg 37
reseed :: (SeedLength d, Hash c d) => State d -> Entropy -> AdditionalInput -> State d
reseed st ent additionalInput =
        let seedMaterial = B.concat [B.pack [1], value st, ent, additionalInput]
            seed = hash_df f seedMaterial (seedlen `for` d)
            v = seed
            c = hash_df f (B.cons 0 v) (seedlen `for` d)
            f = hash
            d = f undefined
        in St 1 v c f

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
  -- TODO determine if Integer is needed here and move to Word64 if possible
  v2 = i2bs slen (sum $ fromIntegral (counter st) : map bs2i [v1, h, constant st])
  cnt = counter st + 1
  slen = seedlen `for` d
  hash = encode . hashF .  L.fromChunks
  d = hsh st undefined
  hashF = hsh st

-- 10.1.1.4, pg 39
hashGen :: (Hash c d, SeedLength d) => d -> BitLen -> B.ByteString -> RandomBits
hashGen d r val = B.take reqBytes . B.concat $ getW val m
  where
  reqBytes = (r + 7) `div` 8
  m = (r + (outlen - 1)) `div` outlen
  getW :: B.ByteString -> Int -> [B.ByteString]
  getW _ 0 = []
  getW dat i =
        let wi = encode (h dat)
            dat' = incBS dat
            rest = getW dat' (i-1)
        in wi : rest
  slen = seedlen `for` d
  outlen = outputLength `for` d
  h = hashFunc' d

{-# LANGUAGE BangPatterns #-}
{-# OPTIONS_GHC -Wall     #-}
module Crypto.Random.DRBG.HMAC
        ( State, counter
        , reseedInterval
        , instantiate
        , reseed
        , generate) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Tagged (proxy)
import Data.Word (Word64)
import Crypto.Classes
import Crypto.HMAC
import Crypto.Random.DRBG.Types

type Key = B.ByteString
type Value = B.ByteString

data State d = St
        { counter               :: {-# UNPACK #-} !Word64
        -- Start admin info
        , value                 :: !Value
        , key                   :: !Key
        }

-- This is available with the right type in the tagged package starting from
-- version 0.7, but ending with GHC version 7.8. Sigh.
asProxyTypeOf :: d -> state d -> d
asProxyTypeOf = const

reseedInterval :: Word64
reseedInterval = 2^(48::Int)

fc :: B.ByteString -> L.ByteString
fc = L.fromChunks . \s -> [s]

update :: (Hash c d) => State d -> L.ByteString -> State d
update st input = st { value = newV , key = newK }
  where
  hm x = hmac (MacKey x)
  k    = key st
  v    = value st
  k'   = encode $ (hm k (L.concat [fc v, L.singleton 0, input]) `asProxyTypeOf` st)
  v'   = encode $ (hm k' (fc v) `asProxyTypeOf` st)
  (newK, newV) =
    if L.length input == 0
      then (k',v')
      else let k'' = encode $ hm k' (L.concat [fc v', L.singleton 1, input]) `asProxyTypeOf` st
           in (k'', encode $ hm k'' (fc v') `asProxyTypeOf` st)

instantiate :: (Hash c d) => Entropy -> Nonce -> PersonalizationString -> State d
instantiate ent nonce perStr = st
  where
  seedMaterial = L.fromChunks [ent, nonce, perStr]
  k = B.replicate olen 0
  v = B.replicate olen 1
  st = update (St 1 v k) seedMaterial
  olen = (outputLength `proxy` st) `div` 8

reseed :: (Hash c d) => State d -> Entropy -> AdditionalInput -> State d
reseed st ent ai = (update st (L.fromChunks [ent, ai])) { counter = 1 }

generate :: (Hash c d) => State d -> BitLength -> AdditionalInput -> Maybe (RandomBits, State d)
generate st req additionalInput =
        if(counter st > reseedInterval)
                then Nothing
                else Just (randBitsFinal, stFinal { counter = 1 + counter st})
  where
  st' = if B.length additionalInput == 0
                then st
                else update st (fc additionalInput)
  reqBytes = (req+7) `div` 8
  iterations = (reqBytes + (outlen - 1)) `div` outlen

  -- getV is the main cost.  HMACing and storing 'iterations' bytestrings at
  -- ~64 bytes each is a real waste.  Some pre-allocation and unsafe functions
  -- exported from Crypto.HMAC could cut this down, but it really isn't worth
  -- giving CPR to such a bad idea as using ByteString for crypto computations
  getV :: Value -> Int -> (Value, [B.ByteString])
  getV !u 0 = (u, [])
  getV !u i = 
        let !vNew = hmac' (MacKey kFinal) u `asProxyTypeOf` st
            !encV = encode vNew
            (uFinal, rest) = getV encV (i - 1)
        in (uFinal, encV:rest)
  (vFinal, randBitsList) = getV (value st') iterations
  randBitsFinal = B.take reqBytes $ B.concat randBitsList
  kFinal = key st'
  stFinal = update (st' { key = kFinal, value = vFinal} `asTypeOf` st) (fc additionalInput)
  outlen = (outputLength `proxy` st) `div` 8

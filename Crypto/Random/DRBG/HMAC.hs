{-# LANGUAGE BangPatterns #-}
module Crypto.Random.DRBG.HMAC
	( State
	, reseedInterval
	, instantiate
	, reseed
	, generate) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize (encode, Serialize(..))
import Data.Serialize.Put
import Data.Serialize.Builder (toByteString)
import Crypto.Classes
import Crypto.HMAC
import Crypto.Types
import Crypto.Random.DRBG.Types

type Key = B.ByteString
type Value = B.ByteString

data State d = St
	{ value			:: !Value
	, key			:: !Key
	, counter		:: !Integer
	-- Start admin info
	, hashAlg		:: L.ByteString -> d
	}

reseedInterval = 2^48

fc = L.fromChunks . \s -> [s]

update :: (Hash c d) => State d -> L.ByteString -> State d
update st input = st { value = newV , key = newK }
  where
  hm k = hmac (MacKey k)
  d  = hashAlg st undefined
  k  = key st
  v  = value st
  k' = encode $ (hm k (L.concat [fc v, L.singleton 0, input]) `asTypeOf` d)
  v' = encode $ (hm k' (fc v) `asTypeOf` d)
  (newK, newV) =
    if L.length input == 0
      then (k',v')
      else let k'' = encode $ hm k' (L.concat [fc v', L.singleton 1, input]) `asTypeOf` d
           in (k'', encode $ hm k'' (fc v') `asTypeOf` d)

instantiate :: (Hash c d) => Entropy -> Nonce -> PersonalizationString -> State d
instantiate ent nonce perStr = st
  where
  seedMaterial = L.fromChunks [ent, nonce, perStr]
  k = B.replicate olen 0
  v = B.replicate olen 1
  st =  update (St v k 1 hash) seedMaterial
  d  = hashAlg st undefined
  olen = (outputLength .::. d) `div` 8

reseed :: (Hash c d) => State d -> Entropy -> AdditionalInput -> State d
reseed st ent ai = (update st (L.fromChunks [ent, ai])) { counter = 1 }

generate :: (Hash c d) => State d -> BitLength -> AdditionalInput -> Maybe (RandomBits, State d)
generate st req additionalInput =
	if(counter st > reseedInterval)
		then Nothing
		else Just (randBitsFinal, stFinal { counter = 1 + counter st})
  where
  d = hashAlg st undefined
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
	let !vNew = hmac' (MacKey kFinal) u `asTypeOf` d
	    !encV = encode vNew
	    (uFinal, rest) = getV encV (i - 1)
	in (uFinal, encV:rest)
  (vFinal, randBitsList) = getV (value st') iterations
  randBitsFinal = B.take reqBytes $ B.concat randBitsList
  kFinal = key st'
  stFinal = update (st' { key = kFinal, value = vFinal}) (fc additionalInput)
  outlen = outputLength .::. d `div` 8

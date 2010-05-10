module Data.DRBG.HMAC where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize (encode)
import Data.Crypto.Classes
import Data.RNG.DRBG


data State h = St
	{ value			:: !B.ByteString
	, key			:: !B.ByteString
	, counter		:: !Integer
	-- Start admin info
	, securityStrength	:: !Int
	, predictionResistant	:: !Bool
	, hashAlg		:: h
	} deriving (Eq, Ord)

reseed_interval = 2^48

update :: (Hash h d) => State h -> L.ByteString -> State H
update st input = st { value = newV , key = newK }
  where
  h  = hashAlg st
  k  = key st
  v  = value st
  k' = hmac h k (L.concat [L.fromChunks [v], L.singleton 0, input])
  v' = hmac h k' v
  (newK, newV) =
    if L.length input == 0
      then (k',v')
      else let k'' = hmac h k (L.concat [L.fromChunks [v'], L.singleton 1, input])
           in (k'', hmac h k'' v')

instantiate :: (Hash h d) => h -> Entropy -> Nonce -> PersonalizationString -> Stat h
instantiate h ent nonce perStr =
	let seedMaterial = B.concat [ent, nonce, perStr]
	    k = B.replicate (bitLength h) 0
	    v = B.replicate (bitLength h) 1
	in update (St v k 1 (strength h) True h)

reseed :: (Hash h d) => State h -> Entropy -> AdditionalInput -> State h
reseed st ent ai = (update st (B.append ent ai)) { counter = 1 }

generate :: (Hash h d) => State h -> BitLen -> AdditionalInput -> Maybe (RandomBits, State h)
generate st req additionalInput =
	if(counter st > reseed_interval)
		then Nothing
		else Just (L.take r wFinal, stFinal { counter = 1 + counter st})
  where
  st' = if B.length additionalInput == 0
		then 0
		else update st additionalInput
  reqBytes = r `div` 8
  m = if req `rem` outlen == 0 then req `div` outlen else (r + outlen) `div` outlen
  w = iterate (\((kI,vI),wOld) -> let vN = hmac h k v in ((kI, vN), L.append wOld vN)) ((key st', value st'), L.empty)
  ((kFinal, vFinal), wFinal) = head $ drop m w
  stFinal = update (st { key = kFinal, value = vFinal}) additionalInput
  outlen = outputLength h

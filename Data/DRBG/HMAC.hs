module Data.DRBG.HMAC
	( State(..)
	, reseedInterval
	, instantiate
	, reseed
	, generate) where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Serialize (encode)
import Data.Crypto.Classes
import Data.Crypto.HMAC
import Data.DRBG
import qualified Data.Binary as Bin

type Key = B.ByteString
type Value = B.ByteString

data State h = St
	{ value			:: !Value
	, key			:: !Key
	, counter		:: !Integer
	-- Start admin info
	, securityStrength	:: !Int
	, predictionResistant	:: !Bool
	, hashAlg		:: h
	} deriving (Eq, Ord)

reseedInterval = 2^48

fc = L.fromChunks . \s -> [s]

update :: (Hash h c d) => State h -> L.ByteString -> State h
update st input = st { value = newV , key = newK }
  where
  h  = hashAlg st
  k  = key st
  v  = value st
  k' = encode $ hmac h k (L.concat [fc v, L.singleton 0, input])
  v' = encode $ hmac h k' (fc v)
  (newK, newV) =
    if L.length input == 0
      then (k',v')
      else let k'' = encode $ hmac h k' (L.concat [fc v', L.singleton 1, input])
           in (k'', encode $ hmac h k'' (fc v'))

instantiate :: (Hash h c d) => h -> Entropy -> Nonce -> PersonalizationString -> State h
instantiate h ent nonce perStr =
	let seedMaterial = L.fromChunks [ent, nonce, perStr]
	    k = B.replicate (outputLength h `div` 8) 0
	    v = B.replicate (outputLength h `div` 8) 1
	in update (St v k 1 (strength h) True h) seedMaterial

reseed :: (Hash h c d) => State h -> Entropy -> AdditionalInput -> State h
reseed st ent ai = (update st (L.fromChunks [ent, ai])) { counter = 1 }

generate :: (Hash h c d) => State h -> BitLength -> AdditionalInput -> Maybe (RandomBits, State h)
generate st req additionalInput =
	if(counter st > reseedInterval)
		then Nothing
		else Just (L.take (fromIntegral reqBytes) randBitsFinal, stFinal { counter = 1 + counter st})
  where
  h = hashAlg st
  st' = if B.length additionalInput == 0
		then st
		else update st (fc additionalInput)
  reqBytes = req `div` 8 + (if req `rem` 8 ==0 then 0 else 1)
  getV :: Key -> Value -> L.ByteString -> (Value, L.ByteString)
  getV j u bs
     | L.length bs >= fromIntegral reqBytes = (u, bs)
     | otherwise               = let vNew = hmac h j (fc u) in (encode vNew, L.concat [bs, Bin.encode vNew])
  (vFinal, randBitsFinal) = getV (key st') (value st') L.empty
  kFinal = key st'
  stFinal = update (st' { key = kFinal, value = vFinal}) (fc additionalInput)
  outlen = outputLength h

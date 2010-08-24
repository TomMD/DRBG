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
import Data.Crypto.Types
import Data.DRBG.Types
import qualified Data.Binary as Bin

type Key = B.ByteString
type Value = B.ByteString

data State d = St
	{ value			:: !Value
	, key			:: !Key
	, counter		:: !Integer
	-- Start admin info
	-- , securityStrength	:: !Int -- See hashAlg for strength
	, predictionResistant	:: !Bool
	, hashAlg		:: L.ByteString -> d
	}

reseedInterval = 2^48

fc = L.fromChunks . \s -> [s]

update :: (Hash c d) => State d -> L.ByteString -> State d
update st input = st { value = newV , key = newK }
  where
  d  = hashAlg st undefined
  k  = key st
  v  = value st
  k' = encode $ (hmac k (L.concat [fc v, L.singleton 0, input]) `asTypeOf` d)
  v' = encode $ (hmac k' (fc v) `asTypeOf` d)
  (newK, newV) =
    if L.length input == 0
      then (k',v')
      else let k'' = encode $ hmac k' (L.concat [fc v', L.singleton 1, input]) `asTypeOf` d
           in (k'', encode $ hmac k'' (fc v') `asTypeOf` d)

instantiate :: (Hash c d) => Entropy -> Nonce -> PersonalizationString -> State d
instantiate ent nonce perStr = st
  where
  seedMaterial = L.fromChunks [ent, nonce, perStr]
  k = B.replicate olen 0
  v = B.replicate olen 1
  st =  update (St v k 1 True hash) seedMaterial
  d  = hashAlg st undefined
  olen = (outputLength .::. d) `div` 8

reseed :: (Hash c d) => State d -> Entropy -> AdditionalInput -> State d
reseed st ent ai = (update st (L.fromChunks [ent, ai])) { counter = 1 }

generate :: (Hash c d) => State d -> BitLength -> AdditionalInput -> Maybe (RandomBits, State d)
generate st req additionalInput =
	if(counter st > reseedInterval)
		then Nothing
		else Just (L.take (fromIntegral reqBytes) randBitsFinal, stFinal { counter = 1 + counter st})
  where
  d = hashAlg st undefined
  st' = if B.length additionalInput == 0
		then st
		else update st (fc additionalInput)
  reqBytes = req `div` 8 + (if req `rem` 8 ==0 then 0 else 1)
  getV :: Value -> L.ByteString -> (Value, L.ByteString)
  getV u bs
     | L.length bs >= fromIntegral reqBytes = (u, bs)
     | otherwise = let vNew = hmac' kFinal u `asTypeOf` d
		       encV = encode vNew
		   in getV encV (L.concat [bs, fc encV])
  (vFinal, randBitsFinal) = getV (value st') L.empty
  kFinal = key st'
  stFinal = update (st' { key = kFinal, value = vFinal}) (fc additionalInput)
  outlen = outputLength .::. d

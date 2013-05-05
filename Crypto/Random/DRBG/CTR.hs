module Crypto.Random.DRBG.CTR
    ( State
    , update
    , instantiate
    , reseed
    ) where

import Data.ByteString (ByteString)
import qualified Data.ByteString as B
import Crypto.Classes
import Crypto.Types
import Crypto.Random.DRBG.Types
import Data.Word (Word64)

data State a = St { counter     :: {-# UNPACK #-} !Word64
                  , value       :: !(IV a)
                  , key         :: a
                  }

update :: BlockCipher a => ByteString -> State a -> State a
update provided_data st
    | B.length provided_data < seedLen = error "DRBGG-CTR: Seed too small to update given cipher-CTR based DRBG"
    | otherwise =
        let (temp,_) = ctr (key st) (value st) (B.replicate seedLen 0)
            (keyBytes,valBytes) = B.splitAt (keyLengthBytes `for` key st) (zwp' temp provided_data)
            newValue = IV valBytes
            newKey   = maybe (error "DRBG-CTR: Could not construct new key") id (buildKey keyBytes)
        in St (counter st) newValue newKey
  where
    seedLen = (blockSizeBytes `for` key st) + (keyLengthBytes `for` key st)
{-# INLINEABLE update #-}

instantiate :: BlockCipher a => Entropy -> PersonalizationString -> State a
instantiate ent perStr = st
  where
  seedLen   = blockLen + keyLen
  blockLen  = (blockSizeBytes `for` key st)
  keyLen    = (keyLengthBytes `for` key st)
  temp      = B.take seedLen (B.append perStr (B.replicate seedLen 0))
  seedMat   = zwp' ent temp
  Just key0 = buildKey (B.replicate keyLen 0)
  v0        = IV (B.replicate blockLen 0)
  st        = update seedMat (St 1 v0 key0)
{-# INLINABLE instantiate #-}

reseed :: BlockCipher a => State a -> Entropy -> AdditionalInput -> State a
reseed st0 ent ai = st1 { counter = 1 }
  where
  seedLen = (blockSizeBytes `for` key st0) + (keyLengthBytes `for` key st0)
  newAI = (B.take seedLen (B.append ai (B.replicate seedLen 0)))
  seedMat = zwp' ent newAI
  st1 = update seedMat st0

generate :: BlockCipher a => State a -> ByteLength -> AdditionalInput -> Maybe (RandomBits, State a)
generate st0 len ai0
  | counter st0 > reseedInterval = Nothing
  | not (B.null ai0) =
      let aiNew = (B.take outLen (B.append ai0 (B.replicate outLen 0)))
      in go (update aiNew st0) aiNew
  | otherwise = go st0 ai0
  where
  outLen  = (blockSizeBytes `for` key st0)
  -- go :: BlockCipher a => State a -> AdditionalInput -> Maybe (RandomBits, State a)
  go st ai =
      let (temp,_) = ctr (key st) (value st) (B.replicate len 0)
          st1      = update ai st
      in Just (temp, st1 { counter = counter st1 + 1 })

reseedInterval :: Word64
reseedInterval = 2^48

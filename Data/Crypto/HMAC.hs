module Data.Crypto.HMAC where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Crypto.Classes
import Data.Serialize (encode)
import qualified Data.Binary as Bin
import Data.Bits (xor)

hmac :: (Hash h c d) => h -> B.ByteString -> L.ByteString -> d
hmac h k = hash . L.append ko . Bin.encode  . hash . L.append ki
  where
  hash = hashFunction h
  keylen = B.length k
  blen = blockLength h `div` 8
  k' = case compare keylen blen of
         GT -> encode . hash . fc $ k
         EQ -> k
         LT -> B.append k (B.replicate (blen - keylen) 0x00)
  ko = fc $ B.map (`xor` 0x5c) k'
  ki = fc $ B.map (`xor` 0x36) k'
  fc = L.fromChunks . \s -> [s]

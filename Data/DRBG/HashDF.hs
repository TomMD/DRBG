module Data.DRBG.HashDF where

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L
import Data.Crypto.Classes
import Data.Serialize (encode)
import Data.Serialize.Put (runPut, putWord32be)
import Data.Word (Word8, Word32)

type BitLen = Int

-- Section 10.4.1, pg 65
hash_df :: Hash h c d => h -> B.ByteString -> BitLen -> B.ByteString
hash_df h str reqBits = B.take reqBytes $ getT B.empty (1 :: Word8)
  where
  reqBytes = reqBits `div` 8  -- FIXME?
  outlen = outputLength h
  hash = encode . hashFunction h . L.fromChunks . \x -> [x]
  getT tmp cnt
	| B.length tmp >= reqBytes = tmp
        | otherwise = let new = hash (B.concat [B.singleton cnt, reqBitsBS, str]) in getT (B.append tmp new) (cnt + 1)
  len = (if reqBits `rem` outlen == 0 then reqBits `div` outlen else (reqBits + outlen) `div` outlen)
  reqBitsBS = runPut $ putWord32be (fromIntegral reqBits :: Word32)

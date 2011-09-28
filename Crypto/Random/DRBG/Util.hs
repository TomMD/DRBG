module Crypto.Random.DRBG.Util where

import qualified Data.ByteString as B
import Crypto.Random.DRBG.Types
import Data.Bits (shiftL, shiftR)

{-# INLINE incBS #-}
incBS :: B.ByteString -> B.ByteString
incBS bs = B.concat (go bs (B.length bs - 1))
  where
  go bs i
        | B.length bs == 0     = []
        | B.index bs i == 0xFF = (go (B.init bs) (i-1)) ++ [B.singleton 0]
        | otherwise            = [B.init bs] ++ [B.singleton $ (B.index bs i) + 1]

-- Appendix B
i2bs :: BitLen -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)
{-# INLINE i2bs #-}

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs
{-# INLINE bs2i #-}

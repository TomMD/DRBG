{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
module Data.Crypto.Classes where

import Data.Binary
import Data.Serialize
import Text.PrettyPrint.HughesPJClass
import Data.ByteString.Lazy
import qualified Data.ByteString as B

type BitLength = Int

class (Binary d, Serialize d, Pretty d) => Hash h d | h -> d where
  outputLength :: h -> BitLength
  hashFunction :: h -> ByteString -> d

-- class (Binary d, Serialize d, Pretty d) => Digest d h | h -> d where
--   hash :: L.ByteString -> d
  

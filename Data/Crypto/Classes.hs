{-# LANGUAGE MultiParamTypeClasses, FunctionalDependencies #-}
module Data.Crypto.Classes where

import Data.Binary
import Data.Serialize
import Text.PrettyPrint.HughesPJClass
import Data.ByteString.Lazy
import qualified Data.ByteString as B

type BitLength = Int

v v v v v v v
class (Binary d, Serialize d, Pretty d)
    => Hash h ctx d | h -> d, h -> ctx, ctx -> d where
  outputLength   :: h -> BitLength
  hashFunction   :: h -> ByteString -> d
  initialContext :: h -> ctx
  updateContext  :: h -> ctx -> ByteString -> ctx
  finalize       :: h -> ctx -> ByteString -> d
  strength       :: h -> Int
*************
class (Serialize d, Pretty d, Binary d) => Hash h d | h -> d, d -> h where
  outputLength :: h -> BitLength
  hashFunction :: h -> ByteString -> d
^ ^ ^ ^ ^ ^ ^

class Cipher c ct k | k -> c, c -> ct where
  blockSize       :: c -> BitLength
  cipher          :: k -> ByteString -> ct
  decipher        :: k -> ct -> ByteString
  buildKey        :: ByteString -> Maybe k
  keyLength       :: k -> BitLength




{- Example instances 
instance Hash SHA256 DigestSHA256 where
  outputLength _ = 256
  hashFunction = sha256

instance Cipher AES AESCT KeyAES where
  blockSize _ = 128
  cipherFunction = aesE
  decipherFunction = aesD
  buildKey = aesExpandKey
  keyLength = aesKeyLength

-}

-- class (Binary d, Serialize d, Pretty d) => Digest d h | h -> d where
--   hash :: L.ByteString -> d
  

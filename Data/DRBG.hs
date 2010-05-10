module Data.DRBG where

import Data.ByteString as B
import Data.ByteString.Lazy as L

type Entropy = B.ByteString
type PersonalizationString = B.ByteString
type Nonce = B.ByteString
type AdditionalInput = B.ByteString
type RandomBits = L.ByteString

{-# LANGUAGE EmptyDataDecls, MultiParamTypeClasses #-}
import qualified Data.DRBG.Hash as H
import qualified Data.DRBG.HMAC as M
import Data.Digest.Pure.SHA
import Data.ByteString as B
import Data.Crypto.Classes
import Data.Serialize
import Data.Serialize.Put as S
import Data.Binary
import Data.Binary.Put as P
import Text.PrettyPrint.HughesPJClass
import qualified Data.ByteString.Lazy.Char8 as L

data SHA256

instance Show SHA256 where
	show _ = "SHA256"

sha256desc = undefined :: SHA256

instance Hash SHA256 Int Digest where
  outputLength _ = 256
  hashFunction _ = sha256
  initialContext _ = 0
  updateContext = undefined
  finalize = undefined
  strength _ = 256

instance H.SeedLength SHA256 where
	seedlen _ = 440

instance Serialize Digest where
	get = undefined
	put d = S.putByteString (B.concat $ L.toChunks (bytestringDigest d))
instance Binary Digest where
	get = undefined
	put = P.putLazyByteString . bytestringDigest

instance Pretty Digest where
	pPrint = undefined

main = hmacMain >> hashMain

hmacMain = do
    let st = M.instantiate hsh entropy nonce personalStr
	Just (rb1, st') = M.generate st 256 B.empty
	Just (rb1Add, _) = M.generate st' 256 additional
	stNew = M.reseed st' entropy' personalStr
	Just (rb2,  _) = M.generate st' 128 B.empty
	Just (rb2st, _) = M.generate stNew 128 B.empty
	ls = [rb1, rb1Add, rb2, rb2st]
    print $ Prelude.map L.unpack ls
    print $ Prelude.map L.length ls
  where
  hsh = (undefined :: SHA256)
  entropy = (B.pack [1..64])
  nonce = (B.pack [65..128])
  personalStr = B.empty
  entropy' = (B.pack [129..192])
  additional = B.pack [31,66,54,27,90,200,201,177,2,13,113,44,95,67,18,59]


hashMain = do
    let st  = H.instantiate hsh entropy nonce personalStr
	st' = H.reseed st entropyPR personalStr
	Just (rb2st, _) = H.generate st' 256 entropyPR'
    print $ rb2st == res

  where
  hsh = (undefined :: SHA256) 
  entropy = (i2b  256 0xff2ca3fbd9dad8be4a00ab0a871dc20c2739ec3cfbf4170332cf95acacb98f8f)
  nonce = (i2b 128 0x2e496f38d3657bd06508f7d6f766f7fe)
  personalStr = B.empty
  additional = B.empty
  entropyPR = i2b 256 0x33483d444955b95a5e9331e0b824bf3132fc3717d9a4e634c8508aac43239415
  entropyPR' = i2b 256 0x9a47604c3549806934b1170ee7cbb29dfec192e503cb4bef19979d0df5fa911f
  res = i2b 256 0x2c9321de43e5bfc4ac4642aa71ca0bffd18f26b138741b13daa75a705d9d8eee

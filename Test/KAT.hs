{-# LANGUAGE EmptyDataDecls, MultiParamTypeClasses #-}
import qualified Data.DRBG.Hash as H
import qualified Data.DRBG.HMAC as M
import Data.CryptoHash.SHA256 as SHA
import qualified Data.ByteString as B
import Crypto.Classes
import Data.Serialize as Ser
import Data.Serialize.Put as S
import Data.Binary as Bin
import Data.Binary.Put as P
import Text.PrettyPrint.HughesPJClass
import qualified Data.ByteString.Lazy.Char8 as L
import qualified Data.ByteString.Lazy as LN
import Data.Bits (shiftR, shiftL)
import Crypto.HMAC
import Crypto.Types
import Data.Bits (xor)
import Data.Tagged
import Data.Maybe (maybeToList)
import Data.List (deleteBy)
import Test.Crypto
import Test.ParseNistKATs
import Paths_DRBG

newtype SHADigest = SHADigest B.ByteString
	deriving (Eq, Ord, Show)

instance Hash SHA.Ctx SHADigest where
  outputLength = Tagged 256
  initialCtx = SHA.init
  updateCtx = SHA.update
  finalize ctx = SHADigest . SHA.finalize . SHA.update ctx
  blockLength = Tagged 512

instance H.SeedLength SHADigest where
	seedlen = Tagged 440

instance Serialize SHADigest where
	get = undefined
	put (SHADigest d) = S.putByteString d

instance Binary SHADigest where
	get = undefined
	put (SHADigest d) = P.putByteString d

main = hmacMain >> hashMain

-- Test the SHA-256 HMACs (other hash implementations will be tested once crypthash uses the crypto-api classes)
nistTests_HMAC :: IO [Test]
nistTests_HMAC = do
	file <- getDataFileName "Test/HMAC_DRBG.txt"
	(Right cats) <- parseFromFile (many parseCategory) file
	return (concat $ concatMap (maybeToList . categoryToTest_HMAC) cats)

-- Currently run SHA-256 tests only
categoryToTest_HMAC :: TestCategory -> Maybe [Test]
categoryToTest_HMAC (props, ts) =
	if "SHA-256" `notElem` map fst props
		then Nothing
		else let s = unlines $ map showProp props 
			 h = hashFunc (undefined :: SHADigest)
			 tests = concatMap (maybeToList . buildKAT) ts
		     in Just tests
  where
  deleteF k lst = deleteBy (const $ (==) k . fst) undefined lst
  isPR = Just True == fmap read (lookup "PredictionResistance" props)
  showProp (p,"") = '[' : p ++ "]"
  showProp (p,v)  = '[' : p ++ " = " ++ v ++ "]"
  testName = fst (head props) ++ (if isPR then "_PR" else "")
--   buildKat :: [Record] -> Maybe (KAT (String, String, String, String, String, String, String) B.ByteString)
  buildKAT t
	| fmap read (lookup "PredictionResistance" props) == Just True = do
	cnt    <- lookup "COUNT" t
	let name = testName ++ "-" ++ cnt
	eIn    <- lookup "EntropyInput" t
	n      <- lookup "Nonce" t
	per    <- lookup "PersonalizationString" t
	aIn1   <- lookup "AdditionalInput" t
	eInPR1 <- lookup "EntropyInputPR" t
	let t' = deleteF "EntropyInputPR" (deleteF "AdditionalInput" t)
	aIn2   <- lookup "AdditionalInput" t'
	eInPR2 <- lookup "EntropyInputPR" t'
	ret    <- lookup "ReturnedBits" t'
	let f =
		let hx = hexStringToBS
		    st0 = M.instantiate (hx eIn) (hx n) (hx per) :: M.State SHADigest
		    st1 = M.reseed st0 (hx eInPR1) (hx aIn1)
		    Just (_,st2) = M.generate st1 256 B.empty
		    st3 = M.reseed st2 (hx eInPR2) (hx aIn2)
		    Just (r1,_) = M.generate st3 256 B.empty
		in r1
	return (TK (f == L.fromChunks [hexStringToBS ret]) name)
	| otherwise = do
	cnt <- lookup "COUNT" t
	let name = testName ++ "-" ++ cnt
	eIn   <- lookup "EntropyInput" t
	n     <- lookup "Nonce" t
	per   <- lookup "PersonalizationString" t
	aIn1  <- lookup "AdditionalInput" t
	eInRS <- lookup "EntropyInputReseed" t
	aInRS <- lookup "AdditionalInputReseed" t
	let t' = deleteF "AdditionalInput" t
	aIn2  <- lookup "AdditionalInput" t'
	ret   <- lookup "ReturnedBits" t
	let f =
		let hx = hexStringToBS
		    st0 = M.instantiate (hx eIn) (hx n) (hx per) :: M.State SHADigest
		    Just (_,st1) = M.generate st0 256 (hx aIn1)
		    st2 = M.reseed st1 (hx eInRS) (hx aInRS)
		    Just (r1, _) = M.generate st2 256 (hx aIn2)
		in r1
	return (TK (f == L.fromChunks [hexStringToBS ret]) name)

-- Test the HMAC DRBG functionallity
hmacMain = nistTests_HMAC >>= runTests

hashMain = nistTests_Hash >>= runTests

nistTests_Hash :: IO [Test]
nistTests_Hash = do
	file <- getDataFileName "Test/Hash_DRBG.txt"
	(Right cats) <- parseFromFile (many parseCategory) file
	return (concat $ concatMap (maybeToList . categoryToTest_Hash) cats)

categoryToTest_Hash :: TestCategory -> Maybe [Test]
categoryToTest_Hash (props, ts) =
	if "SHA-256" `notElem` map fst props
		then Nothing
		else let h = hashFunc (undefined :: SHADigest)
			 tests = concatMap (maybeToList . buildKAT) ts
		     in Just tests
  where
  deleteF k lst = deleteBy (const $ (==) k . fst) undefined lst
  isPR = Just True == fmap read (lookup "PredictionResistance" props)
  testName = fst (head props) ++ (if isPR then "_PR" else "")
  buildKAT t
	| isPR = do
	cnt <- lookup "COUNT" t
	let name = testName ++ "-" ++ cnt
	eIn <- lookup "EntropyInput" t
	n   <- lookup "Nonce" t
	per <- lookup "PersonalizationString" t
        aIn1   <- lookup "AdditionalInput" t
        eInPR1 <- lookup "EntropyInputPR" t
        let t' = deleteF "EntropyInputPR" (deleteF "AdditionalInput" t)
        aIn2   <- lookup "AdditionalInput" t'
        eInPR2 <- lookup "EntropyInputPR" t'
        ret    <- lookup "ReturnedBits" t'
        let f =
                let hx = hexStringToBS
                    st0 = H.instantiate (hx eIn) (hx n) (hx per) :: H.State SHADigest
                    st1 = H.reseed st0 (hx eInPR1) (hx aIn1)
                    Just (_,st2) = H.generate st1 256 B.empty
                    st3 = H.reseed st2 (hx eInPR2) (hx aIn2)
                    Just (r1,_) = H.generate st3 256 B.empty
                in r1
        return (TK (f == L.fromChunks [hexStringToBS ret]) name)
  buildKAT t
	| otherwise = do
        cnt <- lookup "COUNT" t
        let name = testName ++ "-" ++ cnt
        eIn   <- lookup "EntropyInput" t
        n     <- lookup "Nonce" t
        per   <- lookup "PersonalizationString" t
        aIn1  <- lookup "AdditionalInput" t
        eInRS <- lookup "EntropyInputReseed" t
        aInRS <- lookup "AdditionalInputReseed" t
        let t' = deleteF "AdditionalInput" t
        aIn2  <- lookup "AdditionalInput" t'
        ret   <- lookup "ReturnedBits" t
        let f =
                let hx = hexStringToBS
                    st0 = H.instantiate (hx eIn) (hx n) (hx per) :: H.State SHADigest
                    Just (_,st1) = H.generate st0 256 (hx aIn1)
                    st2 = H.reseed st1 (hx eInRS) (hx aInRS)
                    Just (r1, _) = H.generate st2 256 (hx aIn2)
                in r1
        return (TK (f == L.fromChunks [hexStringToBS ret]) name)

i2bs :: BitLength -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs


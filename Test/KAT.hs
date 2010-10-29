{-# LANGUAGE EmptyDataDecls, MultiParamTypeClasses #-}
import qualified Crypto.Random.DRBG.Hash as H
import qualified Crypto.Random.DRBG.HMAC as M
import Crypto.Random.DRBG
import Crypto.Hash.SHA1
import Crypto.Hash.SHA224
import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512
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
import Data.List (deleteBy, isPrefixOf)
import Test.Crypto
import Test.ParseNistKATs
import Paths_DRBG

main = hmacMain >> hashMain

-- Test the SHA-256 HMACs (other hash implementations will be tested once crypthash uses the crypto-api classes)
nistTests_HMAC :: IO [Test]
nistTests_HMAC = do
	contents <-  getDataFileName "Test/HMAC_DRBG.txt" >>= readFile
	let cats = parseCategories "COUNT" contents
	return (concat $ concatMap (maybeToList . categoryToTest_HMAC) cats)

-- Currently run SHA-256 tests only
categoryToTest_HMAC :: TestCategory -> Maybe [Test]
categoryToTest_HMAC (props, ts) =
	let p =
	      case shaNumber props of
		Just 1   -> let p = Proxy :: Proxy SHA1   in build p
		Just 224 -> let p = Proxy :: Proxy SHA224 in build p
		Just 256 -> let p = Proxy :: Proxy SHA256 in build p
		Just 384 -> let p = Proxy :: Proxy SHA384 in build p
		Just 512 -> let p = Proxy :: Proxy SHA512 in build p
		_ -> error $ "Unrecognized Hash when building HMAC tests" ++ (show props)
	in case p of
		Nothing -> Nothing
		Just b  ->
		     let s = unlines $ map showProp props 
			 h = hashFunc (undefined :: SHA256)
			 tests = concatMap (maybeToList . b) ts
		     in Just tests
  where
  deleteF k lst = deleteBy (const $ (==) k . fst) undefined lst
  isPR = Just True == fmap read (lookup "PredictionResistance" props)
  showProp (p,"") = '[' : p ++ "]"
  showProp (p,v)  = '[' : p ++ " = " ++ v ++ "]"
  testName = fst (head props) ++ (if isPR then "_PR" else "")
  build :: Hash c s => Proxy s -> Maybe ([Record] -> Maybe Test)
  build = Just . buildKAT . proxyToHMACState
  -- buildKAT :: Proxy (M.State a) -> [Record] -> Maybe Test
  buildKAT p t
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
		let olen = proxy outputLength (proxyUnwrapHMACState p)
		    hx = hexStringToBS
		    st0 = M.instantiate (hx eIn) (hx n) (hx per)
		    st1 = M.reseed st0 (hx eInPR1) (hx aIn1) `asProxyTypeOf` p
		    Just (_,st2) = M.generate st1 olen B.empty
		    st3 = M.reseed st2 (hx eInPR2) (hx aIn2)
		    Just (r1,_) = M.generate st3 olen B.empty
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
		let olen = proxy outputLength (proxyUnwrapHMACState p)
		    hx = hexStringToBS
		    st0 = M.instantiate (hx eIn) (hx n) (hx per) `asProxyTypeOf` p
		    Just (_,st1) = M.generate st0 olen (hx aIn1)
		    st2 = M.reseed st1 (hx eInRS) (hx aInRS)
		    Just (r1, _) = M.generate st2 olen (hx aIn2)
		in r1
	return (TK (f == L.fromChunks [hexStringToBS ret]) name)

-- Test the HMAC DRBG functionallity
hmacMain = nistTests_HMAC >>= runTests

hashMain = nistTests_Hash >>= runTests

nistTests_Hash :: IO [Test]
nistTests_Hash = do
	contents <- getDataFileName "Test/Hash_DRBG.txt" >>= readFile
	let cats = parseCategories "COUNT" contents
	return (concat $ concatMap (maybeToList . categoryToTest_Hash) cats)

categoryToTest_Hash :: TestCategory -> Maybe [Test]
categoryToTest_Hash (props, ts) =
	let p =
	      case shaNumber props of
		Just 1   -> let p = Proxy :: Proxy SHA1   in build p
		Just 224 -> let p = Proxy :: Proxy SHA224 in build p
		Just 256 -> let p = Proxy :: Proxy SHA256 in build p
		Just 384 -> let p = Proxy :: Proxy SHA384 in build p
		Just 512 -> let p = Proxy :: Proxy SHA512 in build p
		_ -> error $ "Unrecognized hash when building Hash DRBG test" ++ (show props)
	in case p of
		Nothing -> Nothing
		Just b  -> Just $ concatMap (maybeToList . b) ts
  where
  deleteF k lst = deleteBy (const $ (==) k . fst) undefined lst
  isPR = Just True == fmap read (lookup "PredictionResistance" props)
  testName = fst (head props) ++ (if isPR then "_PR" else "")
  build :: (Hash c s, H.SeedLength s) => Proxy s -> Maybe ([Record] -> Maybe Test)
  build = Just . buildKAT . proxyToHashState
  buildKAT p t
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
                let olen = proxy outputLength (proxyUnwrapHashState p)
		    hx = hexStringToBS
                    st0 = H.instantiate (hx eIn) (hx n) (hx per) `asProxyTypeOf` p
                    st1 = H.reseed st0 (hx eInPR1) (hx aIn1)
                    Just (_,st2) = H.generate st1 olen B.empty
                    st3 = H.reseed st2 (hx eInPR2) (hx aIn2)
                    Just (r1,_) = H.generate st3 olen B.empty
                in r1
        return (TK (f == L.fromChunks [hexStringToBS ret]) name)
  buildKAT p t
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
                let olen = proxy outputLength (proxyUnwrapHashState p)
		    hx = hexStringToBS
                    st0 = H.instantiate (hx eIn) (hx n) (hx per) `asProxyTypeOf` p
                    Just (_,st1) = H.generate st0 olen (hx aIn1)
                    st2 = H.reseed st1 (hx eInRS) (hx aInRS)
                    Just (r1, _) = H.generate st2 olen (hx aIn2)
                in r1
        return (TK (f == L.fromChunks [hexStringToBS ret]) name)

proxyUnwrapHashState :: Proxy (H.State a) -> Proxy a
proxyUnwrapHashState = const Proxy

proxyUnwrapHMACState :: Proxy (M.State a) -> Proxy a
proxyUnwrapHMACState = const Proxy

i2bs :: BitLength -> Integer -> B.ByteString
i2bs l i = B.unfoldr (\l' -> if l' < 0 then Nothing else Just (fromIntegral (i `shiftR` l'), l' - 8)) (l-8)

bs2i :: B.ByteString -> Integer
bs2i bs = B.foldl' (\i b -> (i `shiftL` 8) + fromIntegral b) 0 bs

proxyToHMACState :: Proxy a -> Proxy (M.State a)
proxyToHMACState _ = Proxy

proxyToHashState :: Proxy a -> Proxy (H.State a)
proxyToHashState _ = Proxy

shaNumber :: Properties -> Maybe Int
shaNumber ps =
	case filter ("SHA-" `isPrefixOf`) (map fst ps) of
		[s] -> Just $ read (drop 4 s)
		[]  -> Nothing

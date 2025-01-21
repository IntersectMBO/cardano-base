{-# LANGUAGE TypeApplications #-}

module Main where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal
import System.IO.Unsafe (unsafePerformIO)
import qualified Data.List.NonEmpty as NonEmpty

main :: IO ()
main = do
    let g1 = blsGenerator @Curve1
        pointsCurve1 = [g1,g1,g1,g1,g1]
        scalars = map (unsafePerformIO . scalarFromInteger) [0,1,2,3,5]
        poinsAndScalars = NonEmpty.fromList $ zip pointsCurve1 scalars
        res1 = blsMSM poinsAndScalars
    print $ blsCompress res1
    let res2 = blsMult g1 11
    print $ blsCompress res2
    if res1 == res2
        then putStrLn "Success"
        else putStrLn "Failure"
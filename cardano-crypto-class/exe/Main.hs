{-# LANGUAGE TypeApplications #-}

module Main where

import Cardano.Crypto.EllipticCurve.BLS12_381.Internal
import System.IO.Unsafe (unsafePerformIO)

main :: IO ()
main = do
    let g1 = blsGenerator @Curve1
        pointsCurve1 = [g1,g1,g1,g1]
        scalars = map (unsafePerformIO . scalarFromInteger) [0,1,2,3]
        res1 = blsMSM pointsCurve1 scalars
    case res1 of
        Left err -> putStrLn $ "Error: " ++ show err
        Right _point -> print "test "

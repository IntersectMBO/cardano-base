import Test.Tasty
import Test.Cardano.Slotting.EpochInfo (epochInfoTests)

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "EpochInfo" [epochInfoTests]

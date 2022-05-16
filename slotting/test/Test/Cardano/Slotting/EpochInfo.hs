module Test.Cardano.Slotting.EpochInfo where

import Cardano.Slotting.EpochInfo.API (EpochInfo (..))
import Cardano.Slotting.EpochInfo.Extend (unsafeLinearExtendEpochInfo)
import Cardano.Slotting.EpochInfo.Impl (fixedEpochInfo)
import Cardano.Slotting.Slot (EpochNo (EpochNo), EpochSize (EpochSize), SlotNo (SlotNo))
import Cardano.Slotting.Time (slotLengthFromSec)
import Data.Functor.Identity (Identity)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck as QC
  ( Arbitrary (arbitrary),
    choose,
    testProperty,
    (===),
  )

baseEpochInfo :: EpochInfo Identity
baseEpochInfo = fixedEpochInfo (EpochSize 10) (slotLengthFromSec 10)

-- An extended epoch info from a fixedEpochInfo should act as identity.
extendedEpochInfo :: SlotNo -> EpochInfo Identity
extendedEpochInfo sn = unsafeLinearExtendEpochInfo sn baseEpochInfo

newtype TestSlotNo = TestSlotNo SlotNo
  deriving (Eq, Show)

instance Arbitrary TestSlotNo where
  arbitrary = TestSlotNo . SlotNo <$> choose (1, 200)

newtype TestEpochNo = TestEpochNo EpochNo
  deriving (Eq, Show)

instance Arbitrary TestEpochNo where
  arbitrary = TestEpochNo . EpochNo <$> choose (0, 20)

epochInfoTests :: TestTree
epochInfoTests =
  testGroup
    "linearExtend"
    [ QC.testProperty "epochSize matches" $ \(TestSlotNo basisSlot, TestEpochNo sn) ->
        epochInfoSize_ baseEpochInfo sn === epochInfoSize_ (extendedEpochInfo basisSlot) sn,
      QC.testProperty "epochFirst matches" $ \(TestSlotNo basisSlot, TestEpochNo sn) ->
        epochInfoFirst_ baseEpochInfo sn === epochInfoFirst_ (extendedEpochInfo basisSlot) sn,
      QC.testProperty "epochEpoch matches" $ \(TestSlotNo basisSlot, TestSlotNo sn) ->
        epochInfoEpoch_ baseEpochInfo sn === epochInfoEpoch_ (extendedEpochInfo basisSlot) sn,
      QC.testProperty "epochTime matches" $ \(TestSlotNo basisSlot, TestSlotNo sn) ->
        epochInfoSlotToRelativeTime_ baseEpochInfo sn
          === epochInfoSlotToRelativeTime_ (extendedEpochInfo basisSlot) sn
    ]

# cardano-crypto-praos

## Overview

`cardano-crypto-praos` provides cryptographic primitives specifically designed for the Praos consensus protocol. It implements high-performance Verifiable Random Functions (VRF) through optimized FFI bindings to a specialized fork of libsodium, enabling the random leader election process that powers Cardano's proof-of-stake consensus.

## Core Functionality 

### Verifiable Random Functions (VRF)
VRFs are cryptographic functions that provide publicly verifiable randomness, essential for:
- **Slot leader selection** - Determining which stake pool produces the next block
- **Nonce generation** - Creating unpredictable randomness for protocol security
- **Lottery systems** - Fair, verifiable random selection processes

### Key Features
- **Praos-optimized VRF** - Implementation tuned for Cardano's specific consensus needs
- **Batch verification** - Efficient verification of multiple VRF proofs
- **Secure randomness** - Cryptographically secure random byte generation
- **FFI performance** - High-speed C implementations via foreign function interface

## Key Types and Usage

### Basic VRF Operations

```haskell
import Cardano.Crypto.VRF.Praos
import Cardano.Crypto.VRF.Class
import qualified Data.ByteString as BS

-- Generate a random seed for key generation
seed <- genSeed

-- Create a VRF key pair from seed
let (verKey, signKey) = keypairFromSeed seed

-- Message to create VRF proof for
let message = "epoch-123-slot-456" :: BS.ByteString

-- Generate VRF proof and output
let (vrfOutput, vrfProof) = prove signKey message

-- Verify the proof
case verify verKey message vrfProof of
  Just output | output == vrfOutput -> 
    putStrLn "VRF proof verified successfully!"
  Just output -> 
    putStrLn $ "Output mismatch: " ++ show (output, vrfOutput)
  Nothing -> 
    putStrLn "VRF proof verification failed"
```

### Working with VRF Types

```haskell
-- Convert keys and proofs to/from byte strings for storage
import Cardano.Crypto.VRF.Praos

-- Serialize verification key
let verKeyBytes = vkBytes verKey

-- Deserialize verification key
case vkFromBytes verKeyBytes of
  Just restoredKey -> putStrLn "Key restored successfully"
  Nothing -> putStrLn "Invalid key bytes"

-- Serialize signing key (be very careful with this!)
let signKeyBytes = skBytes signKey

-- Serialize proof
let proofBytes' = proofBytes vrfProof

-- Deserialize proof
case proofFromBytes proofBytes' of
  Just restoredProof -> putStrLn "Proof restored"
  Nothing -> putStrLn "Invalid proof bytes"

-- Get VRF output directly from proof
let outputFromProof' = outputFromProof vrfProof
let outputBytes' = outputBytes outputFromProof'
```

### Secure Random Bytes

```haskell
import Cardano.Crypto.RandomBytes
import Foreign.Marshal.Alloc
import Foreign.Ptr

-- Generate secure random bytes
generateRandomBytes :: Int -> IO BS.ByteString
generateRandomBytes n = do
  ptr <- mallocBytes n
  randombytes_buf ptr (fromIntegral n)
  bs <- BS.packCStringLen (castPtr ptr, n)
  free ptr
  return bs

-- Example usage
randomData <- generateRandomBytes 32
putStrLn $ "Generated " ++ show (BS.length randomData) ++ " random bytes"
```

### Type Class Integration

```haskell
-- cardano-crypto-praos implements VRFAlgorithm type class
import Cardano.Crypto.VRF.Class

-- Use generic VRF operations
exampleVRF :: (VRFAlgorithm alg, Signable alg a) => 
              SignKeyVRF alg -> a -> (OutputVRF alg, CertVRF alg)
exampleVRF sk msg = evalVRF () msg sk

-- Verify using generic interface  
verifyVRF :: (VRFAlgorithm alg, Signable alg a) =>
             VerKeyVRF alg -> a -> CertVRF alg -> Maybe (OutputVRF alg)
verifyVRF vk msg cert = verifyVRF () vk msg cert

-- Praos VRF can be used with these generic functions
type MyVRF = PraosVRF
```

## Advanced Usage

### Batch Verification (Optimized)

```haskell
import Cardano.Crypto.VRF.PraosBatchCompat

-- For high-throughput scenarios, use batch-compatible versions
batchVerify :: [VerKey] -> [BS.ByteString] -> [Proof] -> IO [Maybe Output]
batchVerify verKeys messages proofs = do
  -- Convert to batch-compatible format
  let batchKeys = map vkToBatchCompat verKeys
  
  -- Verify in batch (implementation details in C)
  results <- mapM (\(vk, msg, proof) -> 
    return $ verify vk msg proof) (zip3 verKeys messages proofs)
    
  return results
```

### Custom Seed Management

```haskell
-- Derive deterministic keys from custom entropy
import Cardano.Crypto.Seed

createDeterministicKey :: BS.ByteString -> (VerKey, SignKey)
createDeterministicKey entropy = 
  let seed = mkSeedFromBytes entropy  -- Ensure exactly 32 bytes
      (vk, sk) = keypairFromSeed seed
  in (vk, sk)

-- Example: Derive keys from passphrase (NOT recommended for production)
let passphrase = "my-secret-passphrase"
let hash256 = hash (BS.pack $ map (fromIntegral . fromEnum) passphrase)
let (testVK, testSK) = createDeterministicKey hash256
```

### Key Size Information

```haskell
-- Get key and proof sizes for storage planning
keyInfo :: IO ()
keyInfo = do
  putStrLn $ "VRF verification key size: " ++ show verKeySizeVRF ++ " bytes"
  putStrLn $ "VRF signing key size: " ++ show signKeySizeVRF ++ " bytes" 
  putStrLn $ "VRF proof size: " ++ show certSizeVRF ++ " bytes"
  putStrLn $ "VRF output size: " ++ show (outputBytes someOutput) ++ " bytes"
  
-- Typical sizes:
-- Verification key: 32 bytes
-- Signing key: 64 bytes (includes verification key)
-- Proof: 80 bytes
-- Output: 64 bytes
```

## Praos Consensus Integration

### Slot Leader Election

```haskell
-- Simplified slot leader election (actual implementation is more complex)
checkSlotLeadership :: SignKey -> Word64 -> Rational -> IO Bool
checkSlotLeadership vrfKey slotNum relativeStake = do
  -- Create slot-specific message
  let slotMsg = "slot-" ++ show slotNum
  
  -- Generate VRF proof
  let (vrfOutput, _proof) = prove vrfKey (BS.pack $ map (fromIntegral . fromEnum) slotMsg)
  
  -- Convert VRF output to probability
  let vrfBytes = outputBytes vrfOutput
  let vrfValue = bytesToProbability vrfBytes  -- Custom function
  
  -- Check if VRF value indicates leadership
  return $ vrfValue < relativeStake

bytesToProbability :: BS.ByteString -> Rational
bytesToProbability bs = 
  let value = foldl' (\acc b -> acc * 256 + fromIntegral b) 0 (BS.unpack bs)
  in value % (2 ^ (8 * BS.length bs))
```

### Nonce Evolution

```haskell
-- Epoch nonce calculation using VRF outputs
evolveNonce :: [Output] -> BS.ByteString -> BS.ByteString
evolveNonce vrfOutputs previousNonce = 
  let allOutputs = previousNonce : map outputBytes vrfOutputs
      combined = BS.concat allOutputs
  in hash combined  -- Using appropriate hash function
```

## Performance Considerations

- **FFI Overhead**: VRF operations use C implementations for maximum speed
- **Memory Management**: Foreign pointers are automatically managed with finalizers
- **Batch Operations**: Use batch-compatible versions for high-throughput scenarios
- **Key Storage**: Signing keys are sensitive - consider secure storage solutions

## Error Handling

```haskell
-- VRF operations can fail, always handle errors
safeVRFOperation :: SignKey -> BS.ByteString -> IO (Maybe (Output, Proof))
safeVRFOperation sk msg = do
  result <- try $ evaluate $ prove sk msg
  case result of
    Right (output, proof) -> return $ Just (output, proof)
    Left (e :: SomeException) -> do
      putStrLn $ "VRF operation failed: " ++ show e
      return Nothing
```

## Security Considerations

⚠️ **Critical Security Notes**:

1. **Signing Key Protection**: Never expose signing keys in logs or memory dumps
2. **Random Seed Quality**: Use cryptographically secure randomness for key generation  
3. **Side-Channel Attacks**: The C implementation includes protections, but be aware in constrained environments
4. **Proof Validation**: Always verify VRF proofs before trusting their outputs
5. **Key Lifecycle**: Implement proper key rotation and destruction procedures

## Installation and Dependencies

### Libsodium Dependency
This package requires a **custom fork** of libsodium with VRF support:

```bash
# Install custom libsodium (if not using Nix)
git clone https://github.com/input-output-hk/libsodium.git -b iquerejeta/vrf_batchverify
cd libsodium
./configure --prefix=/usr/local
make && make install
```

### Cabal Usage
```bash
# With external libsodium (default)
cabal build cardano-crypto-praos

# With bundled C code (if external libsodium unavailable)
cabal build cardano-crypto-praos -f-external-libsodium-vrf
```

### Nix Usage
```bash
# Full nix build
nix-build default.nix -A haskellPackages.cardano-crypto-praos

# Nix development shell
nix-shell --run "cabal build cardano-crypto-praos"
```

## Integration with Other Packages

### cardano-crypto-class
Provides the `VRFAlgorithm` type class that `PraosVRF` implements.

### cardano-binary  
VRF keys and proofs support CBOR serialization for blockchain storage.

### cardano-crypto-tests
Contains comprehensive test suites and benchmarks for VRF performance.

## Testing and Validation

All VRF operations should be thoroughly tested:

```haskell
-- Property: VRF proof verifies correctly
prop_vrfProofVerifies :: SignKey -> BS.ByteString -> Bool
prop_vrfProofVerifies sk msg = 
  let vk = skToVerKey sk
      (output, proof) = prove sk msg
  in verify vk msg proof == Just output

-- Property: Different messages produce different outputs  
prop_vrfUniqueness :: SignKey -> BS.ByteString -> BS.ByteString -> Bool
prop_vrfUniqueness sk msg1 msg2 = 
  msg1 /= msg2 ==> 
    let (out1, _) = prove sk msg1
        (out2, _) = prove sk msg2
    in out1 /= out2
```

## See Also

- [`cardano-crypto-class`](../cardano-crypto-class/README.md) - Cryptographic type classes and KES
- [`cardano-binary`](../cardano-binary/README.md) - CBOR serialization for blockchain data  
- [Praos Paper](https://eprint.iacr.org/2017/573.pdf) - The consensus protocol specification
- [VRF Specification](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-03) - IETF VRF standard

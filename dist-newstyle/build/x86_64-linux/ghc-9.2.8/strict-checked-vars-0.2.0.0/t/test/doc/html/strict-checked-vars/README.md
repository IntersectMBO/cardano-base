# Strict `MVar`s and `TVar`s with invariant checking

The `strict-checked-vars` package provides a strict interface to mutable
variables (`MVar`) and `TVar`s with invariant checking. It builds on top of
`strict-mvar`, `strict-stm` and `io-classes`, and thus it provides the interface
for `MVar`/`TVar` implementations for both
[IO](https://hackage.haskell.org/package/base-4.18.0.0/docs/Prelude.html#t:IO)
and [io-sim](https://hackage.haskell.org/package/io-sim).

## Checked and unchecked variants

There are currently two variant implementations of `StrictTVar`s.
* From `strict-stm`: `Control.Concurrent.Class.MonadSTM.Strict.TVar`
* From `strict-checked-vars`: `Control.Concurrent.Class.MonadSTM.Strict.TVar.Checked`

Similarly, there are currently two variant implementations of `StrictMVar`s.
* From `strict-mvar`: `Control.Concurrent.Class.MonadMVar.Strict`
* From `strict-checked-vars`: `Control.Concurrent.Class.MonadMVar.Strict.Checked`


The _unchecked_ modules provide the simplest implementation of strict variables:
a light wrapper around lazy variables that forces values to WHNF before they are
put inside the variable. The _checked_ module does the exact same thing, but it
has the additional feature that the user can provide an invariant that is
checked each time a new value is placed inside the variable. The checked modules
are drop-in replacements for the unchecked modules, though invariants will be
trivially true in that case. Non-trivial invariants can be set when creating a
new variable.

```haskell
newMVarWithInvariant :: MonadMVar m
                     => (a -> Maybe String)
                     -> a
                     -> m (StrictMVar m a)

newEmptyMVarWithInvariant :: MonadMVar m
                          => (a -> Maybe String)
                          -> m (StrictMVar m a)

newTVarWithInvariant :: (MonadSTM m, HasCallStack)
                     => (a -> Maybe String)
                     -> a
                     -> STM m (StrictTVar m a)

newTVarWithInvariantIO :: (MonadSTM m, HasCallStack)
                       => (a -> Maybe String)
                       -> a
                       -> m (StrictTVar m a)
```

**Note:** though the checked modules are drop-in replacements for the unchecked
modules, the `StrictMVar`/`StrictTVar` types are distinct. This means we can't
make mixed use of the checked and unchecked modules.

## Guarantees for invariant checking on `StrictMVar`s

Although all functions that modify a checked `StrictMVar` will check the
invariant, we do *not* guarantee that the value inside the `StrictMVar` always
satisfies the invariant. Instead, we *do* guarantee that if the `StrictMVar` is
updated with a value that does not satisfy the invariant, an exception is thrown
*after* the new value is written to the `StrictMVar`. The reason for this weaker
guarantee is that leaving an `MVar` empty can lead to very hard to debug
"blocked indefinitely" problems.
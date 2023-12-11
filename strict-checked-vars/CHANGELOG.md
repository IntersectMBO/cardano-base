# Revision history of strict-checked-vars

## 0.2.0.0

* Remove 'Switch' modules. From now on, instead of switching _imports_, this
  package switches the _representations_ of checked variables depending on the
  `checkmvarinvariants` and `checktvarinvariants` flags. This solves a problem
  where compiling projects that depend on `strict-checked-vars` might succeed
  with a flag turned on but fail when it is turned off (and vice versa).

* Add new `unsafeToUncheckedStrictMVar` and `unsafeToUncheckedStrictTVar`
  functions.

## 0.1.0.4

* Propagate HasCallStack constraints in the `Switch` module for checked strict
  MVars.

## 0.1.0.3

* Make `writeTVar` more strict.

## 0.1.0.2

* Make `newTVarWithInvariant`, `newTVarWithInvariantIO` and `newMVarWithInvariant` strict.

## 0.1.0.1

* Export `checkInvariant`.

## 0.1.0.0

* Initial version, not released on Hackage.

---
name: Release some packages
about: Use this template for tracking package releases.
title: "Release some packages"
---

### Release checklist

Once all the pending issues/pull-requests are integrated:

- [ ] Run the following script from [CHaP](https://github.com/IntersectMBO/cardano-haskell-packages) to open a pull-request for releases.
```shellsession
./scripts/add-from-github.sh "https://github.com/intersectmbo/cardano-base" <COMMIT_HASH> \
  base-deriving-via \
  cardano-binary \
  test/cardano-binary-test \
  cardano-crypto-class \
  cardano-crypto-praos \
  cardano-crypto-tests \
  cardano-git-rev \
  cardano-slotting \
  cardano-strict-containers \
  heapwords \
  measures \
  orphans-deriving-via
```
- [ ] List the pull-request made to [CHaP](https://github.com/IntersectMBO/cardano-haskell-packages) below.
- [ ] [Create Git tags](https://github.com/IntersectMBO/cardano-base/blob/master/RELEASING.md#release-to-chap) for the versions of packages released on the respective commit.
- [ ] Open a pull-request to [update the change-logs](https://github.com/IntersectMBO/cardano-ledger/blob/master/RELEASING.md#release-to-chap) with new sections as the "post-release process".
- [ ] If these releases are for a specific version release of `cardano-node`, mention this in the title.

-----

### CHaP PRs

To know the exact versions and packages released, check these pull-requests on [CHaP](https://github.com/IntersectMBO/cardano-haskell-packages). 

- [Link](#)

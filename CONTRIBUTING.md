# Contributing to the Cardano BAse

## Roles and responsibilities

Currently there are two core maintainers:

* [@lehins](https://github.com/lehins)
* [@tdammers](https://github.com/tdammers)

Anything crypto related should be directed at:

* [@iquerejeta](https://github.com/iquerejeta)

People who can help with issues regarding this repository's continuous integration and nix
infrastructure:

* [@angerman](https://github.com/angerman)
* [@hamishmack](https://github.com/hamishmack)

**For security related issues** please consult the security file in the
[Cardano engineering handbook](https://github.com/input-output-hk/cardano-engineering-handbook/blob/main/SECURITY.md).

## Development

We use trunk based developement. Normal development will branch off of master and be
merged back to master.

### Releasing and versioning

Packages from `cardano-base` are released to
[CHaP](https://github.com/input-output-hk/cardano-haskell-packages).

See documentation on the adopted [release and versioning processes](./RELEASING.md) for
more information.

Also see the CHaP README for [instructions](https://github.com/input-output-hk/cardano-haskell-packages#-from-github).

## Building

See the [Readme](https://github.com/input-output-hk/cardano-base#building) for
instructions on building.

## Updating dependencies

Our Haskell packages come from two package repositories:
- Hackage
- [CHaP](https://github.com/input-output-hk/cardano-haskell-packages) (which is
  another alternative Hackage from Cardano)

The `index-state` of each repository is pinned to a particular time in `cabal.project`.
This tells Cabal to treat the repository "as if" it was the specified time, ensuring
reproducibility.  If you want to use a package version from repository X which was added
after the pinned index state time, you need to bump the index state for X.  This is not a
big deal, since all it does is change what packages `cabal` considers to be available when
solving, but it will change what package versions cabal picks for the plan, and so
will likely result in significant recompilation, and potentially some breakage.  That
typically just means that we need to fix the breakage (and add a lower-bound on the
problematic package), or add an upper-bound on the problematic package.

Note that `cabal` itself keeps track of what index states it knows about, so when you bump
the pinned index state you may need to call `cabal update` in order for `cabal` to be happy.

The Nix code which builds our packages also cares about the index state.  This is
represented by inputs managed by `nix flake`: You can update these by running:
- `nix flake lock --update-input haskellNix/hackage` for Hackage
- `nix flake lock --update-input CHaP` for CHaP

If you fail to do this you may get an error like this from Nix:
```
error: Unknown index-state 2021-08-08T00:00:00Z, the latest index-state I know about is 2021-08-06T00:00:00Z. You may need to update to a newer hackage.nix.
```

### Use of `source-repository-package`s

We *can* use Cabal's `source-repository-package` mechanism to pull in un-released package
versions.  However, we should avoid this.  In particular, we cannot release
our packages to CHaP while we depend on a `source-repository-package`.

If we are stuck in a situation where we need a long-running fork of a package, we should
release it to CHaP instead (see the [CHaP
README](https://github.com/input-output-hk/cardano-haskell-packages) for more).

If you do add a `source-repository-package`, you need to provide a `--sha256` comment in `cabal.project` so that Nix knows the hash of the content.

## Warnings

While building most compilation warnings will be turned into an error due to
`-Werror` flag. However during development it might be a bit inconvenient thus
can be disabled on per project basis:

```shell
cabal configure <package-name> --ghc-options="-Wwarn"
cabal build <package-name>
```

### Additional documentation

You can find additional documentation on the nix infrastructure used in this
repo in the following places:

- [The haskell.nix user guide](https://github.com/input-output-hk/haskell.nix/blob/documentation/docs/user-guide.md)
- [The nix-tools repository](https://github.com/input-output-hk/nix-tools)
- [The iohk-nix repository](https://github.com/input-output-hk/iohk-nix)

Note that the user guide linked above is incomplete and does not correctly refer
to projects built using `iohk-nix`, as this one is. A certain amount of trial
and error may be required to make substantive changes!

## Working Conventions

### Code formatting

Very soon we will start using [`fourmolu`](https://github.com/fourmolu/fourmolu) for
formatting, but for now a rule of thumb is to follow whatever format is in a module that
is being modified.  There is a script
[here](https://github.com/input-output-hk/cardano-base/blob/master/scripts/fourmolize.sh)
which uses nix to format the appropriate directories.

### Compiler warnings

The CI builds Haskell code with `-Werror`, so will fail if there are any compiler warnings.

A particular warning can be turned off, if there is a compelling enough reason to do so,
but it should be done at the module level, rather than for a whole package.

### Commit messages

Summarize changes in around 72 characters or less.

Provide more detailed explanatory text, if necessary.  Wrap it to about 72 characters or
so.  In some contexts, the first line is treated as the subject of the commit and the rest
of the text as the body.  The blank line separating the summary from the body is critical
(unless you omit the body entirely); various tools like `log`, `shortlog` and `rebase` can
get confused if you run the two together.

Explain the problem that this commit is solving, and use one commit per conceptual change.
Focus on why you are making this change as opposed to how (the code explains that).  Are
there side effects or other unintuitive consequences of this change? Here's the place to
explain them.

If you use an issue tracker, put references to them at the bottom, like this:

Resolves: #123
See also: #456, #789

### Commit signing

Commits are required to be [signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

### Pull Requests

We require linear history in `master`, so every PR must be rebase on `master` before it
can be merged. There is a convenience button on a PR "Update branch", but make sure to
select "Update with Rebase" from the drop down.

Keep commits to a single logical change where possible.  The reviewer will be happier, and
you’ll be happier if you ever have to revert it.  If you can’t do this (say because you
have a huge mess), best to just have one commit with everything in it.

Keep your PRs to a single topic.  Including unrelated changes makes things harder for your
reviewers, slowing them down, and makes it harder to integrate new changes.

If you’re working on something that’s likely to conflict with someone else, talk to
them. It’s not a race.


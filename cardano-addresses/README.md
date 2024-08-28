# Cardano Addresses

This project has been moved from [this repo](https://github.com/IntersectMBO/cardano-addresses).

## Overview

This module provides mnemonic (backup phrase) creation, and conversion of a
mnemonic to seed for wallet restoration, and address derivation functionalities.

![](example.gif)

## Documentation

API documentation for each of the projects is available:
- [cardano-addresses](https://intersectmbo.github.io/cardano-base/cardano-addresses)
- [cardano-addresses-cli](https://intersectmbo.github.io/cardano-base/cardano-addresses-cli)
- [cardano-addresses-jsapi](https://intersectmbo.github.io/cardano-base/cardano-addresses-jsapi)

## Command-Line

`cardano-address` comes with a command-line interface for Linux. See how to compile it using `nix` in [compiling CLI using nix](#building-cli-with-nix) or [build a Docker image](#docker-image). The command-line is self explanatory by using `--help` on various commands and sub-commands.

> :bulb: Most commands read argument from the standard input. This prevent sensitive information from appearing into your shell history and, makes it easy to pipe commands!

<details>
  <summary>How to generate a recovery phrase (<strong>phrase.prv</strong>)</summary>

```console
$ cardano-address recovery-phrase generate --size 15 > phrase.prv
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
```
</details>

<details>
  <summary>How to generate a root private key (<strong>root.xsk</strong>)</summary>

```console
$ cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983

-- which is equivalent to empty passphrase
$ cardano-address key from-recovery-phrase Shelley --passphrase from-hex
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter hex-encoded passphrase:

root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983
```

> :information_source: Notice the `root_xsk` prefix to identify a root extended signing (private) key.
</details>

<details>
  <summary>How to generate a root private key with passphrase (<strong>root.xsk</strong>)</summary>

```console
$ cardano-address recovery-phrase generate --size 9 > sndfactor.prv
swing payment diagram happy chimney mammal flip become lyrics

$ cardano-address key from-recovery-phrase Shelley --passphrase from-mnemonic
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter a 9–12 word second factor:
swing payment diagram happy chimney mammal flip become lyrics
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

 cardano-address key from-recovery-phrase Shelley --passphrase from-mnemonic --sensitive
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
**********************************************************************************************************
Please enter a 9–12 word second factor:
*************************************************************
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ cardano-address key from-recovery-phrase Shelley --passphrase from-mnemonic --silent
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:

Please enter a 9–12 word second factor:

root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ cardano-address key from-recovery-phrase Shelley --passphrase from-mnemonic --from-file "./sndfactor.prv" < phrase.prv
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ cardano-address key from-recovery-phrase Shelley --passphrase from-hex
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter hex-encoded passphrase:
dc1434f3b472810d56409f85
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ echo "dc1434f3b472810d56409f85" > base16.prv
$ cardano-address key from-recovery-phrase Shelley --passphrase from-hex --from-file "./base16.prv" < phrase.prv
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ cardano-address key from-recovery-phrase Shelley --passphrase from-base64
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter base64-encoded passphrase:
3BQ087RygQ1WQJ+F
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ echo "3BQ087RygQ1WQJ+F" > base64.prv
$ cardano-address key from-recovery-phrase Shelley --passphrase from-base64 --from-file "./base64.prv" < phrase.prv
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ cardano-address key from-recovery-phrase Shelley --passphrase from-octets
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter passphrase in the form of octet array:
[220,20,52,243,180,114,129,13,86,64,159,133]
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ echo "[220,20,52,243,180,114,129,13,86,64,159,133]" > octets.prv
$ cardano-address key from-recovery-phrase Shelley --passphrase from-octets --from-file "./octets.prv" < phrase.prv
root_xsk1jqx0xpke7de69ceyk20tdl9rq7nsava7cfnyeu42yqum8usnpppwmsxn2qsfj0nn2ur2kuq0kmrll67ryvkdhd6pgpsls6s6qx7hlyv6uqt0907t73eflkpw3xz45lcg5fsh6dunfk56j08jslh6x6rttspfny8c

$ cardano-address key from-recovery-phrase Shelley --passphrase from-utf8
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter utf8-encoded passphrase:
my secret passphrase
root_xsk1aq5jduvnx7s6a4wl845jggvnhey5agqjv55dsexsx43np59pse0u4yfxpdfecz9h95jwecduqpt7zlk97j9mprmvjcfeyrcu9nyagpjq6k5cxpnwve5pj3cu24m9my94xtrqvzrlmu0893guffzazyk95cvprwzp

$ cardano-address key from-recovery-phrase Shelley --passphrase ""
Please enter a [9, 12, 15, 18, 21, 24] word mnemonic:
exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum
Please enter utf8-encoded passphrase:
my secret passphrase
root_xsk1aq5jduvnx7s6a4wl845jggvnhey5agqjv55dsexsx43np59pse0u4yfxpdfecz9h95jwecduqpt7zlk97j9mprmvjcfeyrcu9nyagpjq6k5cxpnwve5pj3cu24m9my94xtrqvzrlmu0893guffzazyk95cvprwzp

$ echo "my secret passphrase" > utf8.prv
$ cardano-address key from-recovery-phrase Shelley --passphrase from-utf8 --from-file "./utf8.prv" < phrase.prv
root_xsk1aq5jduvnx7s6a4wl845jggvnhey5agqjv55dsexsx43np59pse0u4yfxpdfecz9h95jwecduqpt7zlk97j9mprmvjcfeyrcu9nyagpjq6k5cxpnwve5pj3cu24m9my94xtrqvzrlmu0893guffzazyk95cvprwzp

-- NOTE:
--λ> let (Right m) = mkSomeMnemonic @'[ 9 ] ["swing", "payment", "diagram", "happy", "chimney", "mammal", "flip", "become", "lyrics"]
--λ> m
--SomeMnemonic (Mnemonic {mnemonicToEntropy = Entropy {entropyRaw = "\220\DC44\243\180r\129\rV@\159\133", entropyChecksum = Checksum 3}, mnemonicToSentence = MnemonicSentence {mnemonicSentenceToListN = [WordIndex {unWordIndex = Offset 1760},WordIndex {unWordIndex = Offset 1293},WordIndex {unWordIndex = Offset 487},WordIndex {unWordIndex = Offset 839},WordIndex {unWordIndex = Offset 320},WordIndex {unWordIndex = Offset 1077},WordIndex {unWordIndex = Offset 712},WordIndex {unWordIndex = Offset 159},WordIndex {unWordIndex = Offset 1067}]}})
--λ> let bytes = BA.convert $ someMnemonicToBytes m :: ByteString
--λ> bytes
--"\220\DC44\243\180r\129\rV@\159\133"
--λ> encode EBase16 bytes
--"dc1434f3b472810d56409f85"
--λ> decodeUtf8 $ convertToBase Base64 bytes
-- "3BQ087RygQ1WQJ+F"
--λ> BS.unpack bytes
-- [220,20,52,243,180,114,129,13,86,64,159,133]
```
> :information_source: Notice the `root_xsk` prefix to identify a root extended signing (private) key.
</details>


<details>
  <summary>How to generate a wallet id based on extended root or account keys (<strong>phrase.prv</strong>)</summary>

```console
$ cat root.xsk
root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983
$ cardano-address key walletid < root.xsk
163ea20ad0611e4815a61c44bb32c82a81538999

$ cardano-address key public --with-chain-code < root.xsk | cardano-address key walletid
163ea20ad0611e4815a61c44bb32c82a81538999

$ cardano-address key child 1852H/1815H/0H < root.xsk > acct.xsk
$ cat acct.xsk
acct_xsk15ztha8ws7qjze5vmdkwqh0ddzvtlgstkg79swazhc5lxns2849plr3msjx082mcmd9hc24ujczk2cjnjwrcz4tjaucw9jqf8h5yc7d84rac0zdckkuhazpam0kleg4sq52ph3e0wn98a64hr8g5cpmh9zqpwtrhy
$ cardano-address key walletid < acct.xsk
15fd6c2130b0758ec7995bf9771d2a6602417c39
$ cardano-address key public --with-chain-code < acct.xsk | cardano-address key walletid
15fd6c2130b0758ec7995bf9771d2a6602417c39
```
</details>

<details>
  <summary>How to generate a wallet id based on account keys of shared wallet (<strong>phrase.prv</strong>)</summary>

```console
$ cardano-address key from-recovery-phrase Shared < phrase.prv > root.shared_xsk
root_shared_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvzteqlc

$ cardano-address key child 1854H/1815H/0H < root.shared_xsk > acct.shared_xsk
acct_shared_xsk14zh0kh0geaz9qpxv6q0n5upq8ux4n97u2gyl69mnhan74w6849pa3hj2p40xg0nugw8tzqu5eynzjunay6tffru9wdjank0phsfuc7vngjsmtktel05g6mx555tw8nxr8rpn2gac6km5plu9mwqsz54rfyhwd7pd

$ cardano-address key walletid < acct.shared_xsk
user error (shared wallet needs to have at least spending script specified)

$ cardano-address key walletid --spending "cosigner#0" < acct.shared_xsk
185d3582fc4892c4528614210b13e9a775dd7d02

$ cardano-address key public --with-chain-code < acct.shared_xsk | cardano-address key walletid --spending "cosigner#0"
185d3582fc4892c4528614210b13e9a775dd7d02

$ cardano-address key walletid --spending "all [cosigner#0, active_until 1000]" < acct.shared_xsk
42ecb214586dcbcb593688fb081784fa0aebb2c0

$ cardano-address key walletid --spending "all [cosigner#0, active_until 1000]" --staking "cosigner#1" < acct.shared_xsk
12dc98557a4c5aa00575c5d1f0dbfa3837261e32
```
</details>


<details>
  <summary>How to generate a private policy key (<strong>policy.xsk</strong>), a public policy key (<strong>policy.vk</strong>) and its hash (<strong>policy.vkh</strong>)</summary>

```console
$ cardano-address key child 1855H/1815H/0H < root.xsk > policy.xsk
policy_xsk1hr47zvxgzeeutgq50r965ygwxys86cwp8wdjqftlhan8mw6849pus6vc50dznjs5vkyjcz9usl6964u6nha88slrh8hyex74xnlfehcrkp80cp8wgzkqh22dzy7c48ekhhvvf2zz8hqakjwgfzgrjq5lx538et75

$ cardano-address key child 1855H/1815H/0H < root.xsk | cardano-address key public --with-chain-code > policy.xvk
policy_xvk1e9ngmlhcwhszwyuxwc7anwk6tvzwndldz7j262rvfpd049tq74mq8vzwlszwus9vpw556yfa320nd0wccj5yy0wpmdyusjys8ypf7dgaauf0m

$ cardano-address key child 1855H/1815H/0H < root.xsk | cardano-address key public --without-chain-code > policy.vk
policy_vk1e9ngmlhcwhszwyuxwc7anwk6tvzwndldz7j262rvfpd049tq74mq0ylkrs

$ cardano-address key hash < policy.xvk
policy_vkh1qpc9xly4lc7yt98gcf59kdcqcss6dda4u9g72e775yxpxeypamc
$ cardano-address key hash < policy.vk
policy_vkh1qpc9xly4lc7yt98gcf59kdcqcss6dda4u9g72e775yxpxeypamc
$ cardano-address key hash --hex < policy.vk
0070537c95fe3c4594e8c2685b3700c421a6b7b5e151e567dea10c13
```

> :information_source: The last segment in the path is the key index and can be incremented up to `2^31-1` to derive more keys.
</details>


<details>
  <summary>How to generate a payment verification key (<strong>addr.xvk</strong>)</summary>

```console
$ cardano-address key child 1852H/1815H/0H/0/0 < root.xsk | cardano-address key public --with-chain-code > addr.xvk
addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc
```

> :information_source: The last segment in the path is the key index and can be incremented up to `2^31-1` to derive more keys.
</details>

<details>
  <summary>How to generate an extended stake verification key (<strong>stake.xvk</strong>)</summary>

```console
$ cardano-address key child 1852H/1815H/0H/2/0 < root.xsk | cardano-address key public --with-chain-code > stake.xvk
stake_xvk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7h9z4smmeqsvs67qhyqmc2lqa0vy36rf2la74ym8a5p93zp4qtpuq6ky3ve
```

> :information_source: The last segment in the path is the key index and can be incremented up to `2^31-1` to derive more keys.
</details>

<details>
  <summary>How to generate a non-extended stake verification key (<strong>stake.vk</strong>)</summary>

```console
$ cardano-address key child 1852H/1815H/0H/2/0 < root.xsk | cardano-address key public --without-chain-code > stake.vk
stake_vk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7sg87an2
```

> :information_source: The last segment in the path is the key index and can be incremented up to `2^31-1` to derive more keys.
</details>

<details>
  <summary>How to generate a hash for payment verification key (<strong>addr.xvk</strong>)</summary>

```console
$ cardano-address key child 1852H/1815H/0H/0/0 < root.xsk | cardano-address key public --with-chain-code > addr.xvk
addr_xvk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28v6wk22nfmru6xz0vl2s3y5xndyd57fu70hrt84c6zkvlwx6fdl7ct9j7yc
$ cardano-address key hash < addr.xvk
addr_vkh12j28hnmtwcp3n08vy58vyf0arnnrhtavu3lrfdztw0j0jng3d6v
$ cardano-address key hash --hex < addr.xvk
54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9
```

> :information_source: The hashing is available for both stake and payment verification keys. Additional flag '--hex' can be used.
</details>


<details>
  <summary>How to generate a payment address from an extended payment key (<strong>payment.addr</strong>)</summary>

```console
$ cardano-address address payment --network-tag testnet < addr.xvk > payment.addr
addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v
```
</details>


<details>
  <summary>How to generate a payment address from a non-extended payment key (<strong>payment.addr</strong>)</summary>

```console
$ cardano-address key child 1852H/1815H/0H/0/0 < root.xsk | cardano-address key public --without-chain-code > addr.vk
addr_vk1grvg8qzmkmw2n0dm4pd0h3j4dv6yglyammyp733eyj629dc3z28qwq4y73
$ cardano-address address payment --network-tag testnet < addr.vk > payment.addr
addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v
```
</details>


<details>
  <summary>How to generate a payment address from a payment key hash (<strong>payment.addr</strong>)</summary>

```console
$ cardano-address key hash < addr.xvk > addr.vkh
addr_vkh12j28hnmtwcp3n08vy58vyf0arnnrhtavu3lrfdztw0j0jng3d6v
$ cardano-address address payment --network-tag testnet < addr.vkh > payment.addr
addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v
```
</details>


<details>
  <summary>How to generate a delegated payment address, i.e. base address, from an extended stake key (<strong>base.addr</strong>)</summary>

```console
$ cardano-address address delegation $(cat stake.xvk) < payment.addr > base.addr
addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n
```
</details>

<details>
  <summary>How to generate a delegated payment address, i.e. base address, from a non-extended stake key (<strong>base.addr</strong>)</summary>

```console
$ cardano-address key child 1852H/1815H/0H/2/0 < root.xsk | cardano-address key public --without-chain-code > stake.vk
stake_vk1658atzttunamzn80204khrg0qfdk5nvmrutlmmpg7xlsyaggwa7sg87an2
$ cardano-address address delegation $(cat stake.vk) < payment.addr > base.addr
addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n
```
</details>

<details>
  <summary>How to generate a delegated payment address, i.e. base address, from a stake key hash (<strong>base.addr</strong>)</summary>

```console
$ cardano-address key hash < stake.xvk > stake.vkh
stake_vkh17mf09mecwve7zkh2jve7nkggu4azk5f7cmtk9zz0wzhz5efq2w6
$ cardano-address address delegation $(cat stake.vkh) < payment.addr > base.addr
addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n
```
</details>

<details>
  <summary>How to generate a stake address from an extended stake key (<strong>stake.addr</strong>)</summary>

```console
$ cardano-address address stake --network-tag testnet < stake.xvk > stake.addr
stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat
```
</details>

<details>
  <summary>How to generate a stake address from a non-extended stake key (<strong>stake.addr</strong>)</summary>

```console
$ cardano-address address stake --network-tag testnet < stake.vk > stake.addr
stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat
```
</details>

<details>
  <summary>How to generate a stake address from a stake key hash (<strong>stake.addr</strong>)</summary>

```console
$ cardano-address key hash < stake.xvk > stake.vkh
stake_vkh17mf09mecwve7zkh2jve7nkggu4azk5f7cmtk9zz0wzhz5efq2w6
$ cardano-address address stake --network-tag testnet < stake.vkh > stake.addr
stake_test1urmd9uh08pen8c26a2fn86weprjh52638mrdwc5gfac2u2s25zpat
```
</details>

<details>
  <summary>How to inspect address</summary>

```console
$ echo addr_test1vp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f7guscp6v | cardano-address address inspect
{
    "stake_reference": "none",
    "spending_key_hash_bech32": "addr_vkh12j28hnmtwcp3n08vy58vyf0arnnrhtavu3lrfdztw0j0jng3d6v",
    "address_style": "Shelley",
    "spending_key_hash": "54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9",
    "network_tag": 0,
    "address_type": 6
}

$ echo addr_test1qp2fg770ddmqxxduasjsas39l5wwvwa04nj8ud95fde7f70k6tew7wrnx0s4465nx05ajz890g44z0kx6a3gsnms4c4qq8ve0n | cardano-address address inspect
{
    "stake_reference": "by value",
    "stake_key_hash_bech32": "stake_vkh17mf09mecwve7zkh2jve7nkggu4azk5f7cmtk9zz0wzhz5efq2w6",
    "stake_key_hash": "f6d2f2ef387333e15aea9333e9d908e57a2b513ec6d762884f70ae2a",
    "spending_key_hash_bech32": "addr_vkh12j28hnmtwcp3n08vy58vyf0arnnrhtavu3lrfdztw0j0jng3d6v",
    "address_style": "Shelley",
    "spending_key_hash": "54947bcf6b760319bcec250ec225fd1ce63baface47e34b44b73e4f9",
    "network_tag": 0,
    "address_type": 0
}
```

Details about possible address types are following (refer also to [cddl](https://github.com/input-output-hk/cardano-ledger/blob/master/eras/alonzo/test-suite/cddl-files/alonzo.cddl) )
| address_type | binary prefix  |   Meaning                                                |
| ------------ |:--------------:|:--------------------------------------------------------:|
|      0       |  0000          |   base address: keyhash28,keyhash28                      |
|      1       |  0001          |   base address: scripthash28,keyhash28                   |
|      2       |  0010          |   base address: keyhash28,scripthash28                   |
|      3       |  0011          |   base address: scripthash28,scripthash28                |
|      4       |  0100          |   pointer address: keyhash28, 3 variable length uint     |
|      5       |  0101          |   pointer address: scripthash28, 3 variable length uint  |
|      6       |  0110          |   enterprise address: keyhash28                          |
|      7       |  0111          |   enterprise address: scripthash28                       |
|      8       |  1000          |   byron/icarus                                           |
|      14      |  1110          |   reward account: keyhash28                              |
|      15      |  1111          |   reward account: scripthash28                           |

</details>

<details>
  <summary>How to generate a payment verification key for shared wallet (<strong>addr_shared.vk</strong>, <strong>stake_shared.vk</strong>)</summary>

Let's generate extended root private key for shared style:

``` console
$ cardano-address key from-recovery-phrase Shared < phrase.prv > root_shared.xsk
root_shared_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvzteqlc
```

Now generate payment verification key (`role=0` is used). Please note that purpose `1854H` is used for multisig.

```console
$ cardano-address key child 1854H/1815H/0H/0/0 < root_shared.xsk | cardano-address key public --without-chain-code > addr_shared.vk
addr_shared_vk1a9h46rvjnqquxz02zyesh0ct29szh7vv9x7r2h87ttmnkgrfgguqhz0mtc
```

Generating delegation verification key is the similar (the only difference is role=2)

```console
$ cardano-address key child 1854H/1815H/0H/2/0 < root_shared.xsk | cardano-address key public --without-chain-code > stake_shared.vk
stake_shared_vk18a8z5dcrlwene88n84j6dm9yvj5rt296fjtresqnunmacetdcymquyq43z
```

> :information_source: The last segment in the path is the key index, which can be incremented to derive more keys. Up `2^31-1` keys are possible.
</details>

<details>
  <summary>How to construct a multisig script hash (<strong>script.hash</strong>)</summary>

We consider `addr_shared.1.vk` and `addr_shared.2.vk` obtained like `addr_shared.vk` but by replacing the final index by `1` and `2` respectively.

```console
$ cardano-address key child 1854H/1815H/0H/0/1 < root_shared.xsk | cardano-address key public --without-chain-code > addr_shared.1.vk
addr_shared_vk1wgj79fxw2vmxkp85g88nhwlflkxevd77t6wy0nsktn2f663wdcmqcd4fp3
$ cardano-address key child 1854H/1815H/0H/0/2 < root_shared.xsk | cardano-address key public --without-chain-code > addr_shared.2.vk
addr_shared_vk1jthguyss2vffmszq63xsmxlpc9elxnvdyaqk7susl4sppp2s9xqsuszh44
$ cardano-address script hash "all [$(cat addr_shared.1.vk), $(cat addr_shared.2.vk)]" > script.hash
script1gr69m385thgvkrtspk73zmkwk537wxyxuevs2u9cukglvtlkz4k
```

This script requires the signature from both signing keys corresponding to `shared_addr.1.vk` and `shared_addr.2.vk` (i.e., shared_addr.1.sk and shared_addr.2.sk) in order to be valid. Similarly, we could require only one of the two signatures:

We can also use extended verification, eiher payment or delegation, keys. They can be obtained as the non-extended ones by using `--with-chain-code` option rather than `--without-chain-option` as above. They will give rise to the same script hash as for verification keys chain code is stripped upon calculation.

```console
$ cardano-address key child 1854H/1815H/0H/0/1 < root_shared.xsk | cardano-address key public --with-chain-code > addr_shared.1.xvk
addr_shared_xvk1wgj79fxw2vmxkp85g88nhwlflkxevd77t6wy0nsktn2f663wdcmqhlfft3dn0qcn6q99dvlfl2ws5duy6w65zks5jgufe60fg839sysavl5pc
$ cardano-address key child 1854H/1815H/0H/0/2 < root_shared.xsk | cardano-address key public --with-chain-code > addr_shared.2.xvk
addr_shared_xvk1jthguyss2vffmszq63xsmxlpc9elxnvdyaqk7susl4sppp2s9xq3zegcxtslhpghmadrlvsphssfjqp3mxg9gca27e35wpu43lqjqnsmjvxuw
$ cardano-address script hash "all [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk)]"
script1gr69m385thgvkrtspk73zmkwk537wxyxuevs2u9cukglvtlkz4k
```

which is equivalent (functionally, but not in terms of hash value) to :

```console
$ cardano-address script hash "at_least 1 [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk)]"
script13uf3fz3ts5srpjc5zcfe977uvnyvp36wcvxuudryegz0zpjlx6a
```
</details>

<details>
  <summary>How to construct a multisig script hash with timelocks</summary>

```console
$  cardano-address script hash "all [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk), active_from 100, active_until 120]"
script1nugjzwfs2t9htl7s3dv9ajnd5us8pctpa8aj4ank8dnd6d6unul
```
</details>


<details>
  <summary>How to validate a script</summary>

```console
$  cardano-address script validate "at_least 1 [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk), $(cat addr_shared.2.xvk)]"
Validated.

$  cardano-address script validate --recommended  "at_least 1 [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk), $(cat addr_shared.2.xvk)]"
Not validated: The list inside a script has duplicate keys (which is not recommended)..
```
</details>

<details>
  <summary>How to get preimage for a script</summary>

```console
$ cardano-address script preimage "all [addr_shared_vkh1zxt0uvrza94h3hv4jpv0ttddgnwkvdgeyq8jf9w30mcs6y8w3nq, addr_shared_vkh1y3zl4nqgm96ankt96dsdhc86vd5geny0wr7hu8cpzdfcqskq2cp]"
008201828200581c1196fe3062e96b78dd959058f5adad44dd663519200f2495d17ef10d8200581c2445facc08d975d9d965d360dbe0fa63688ccc8f70fd7e1f01135380

$  cardano-address script preimage "all [addr_shared_vkh1zxt0uvrza94h3hv4jpv0ttddgnwkvdgeyq8jf9w30mcs6y8w3nq, active_from 100, active_until 150]"
008201838200581c1196fe3062e96b78dd959058f5adad44dd663519200f2495d17ef10d8204186482051896
```
</details>

<details>
  <summary>How to generate a payment script address from a script hash (<strong>script.addr</strong>)</summary>

```console
$ cardano-address address payment --network-tag testnet < script.hash > script.addr
addr_test1wpq0ghwy73wapjcdwqxm6ytwe66j8eccsmn9jptshrjerashp7y82
```
</details>

<details>
  <summary>How to generate a payment script address from a script (<strong>script.addr</strong>)</summary>

```console
$ cardano-address address payment --network-tag testnet "all [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk)]"  > script.addr
addr_test1wpq0ghwy73wapjcdwqxm6ytwe66j8eccsmn9jptshrjerashp7y82
```
</details>

<details>
  <summary>How to generate a delegated payment address, i.e. base address, from a script hash (<strong>base.addr</strong>)</summary>

```console
$ cardano-address script hash "all [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk), active_from 100, active_until 120]" > script.stake.hash
script1nugjzwfs2t9htl7s3dv9ajnd5us8pctpa8aj4ank8dnd6d6unul
$ cardano-address address delegation $(cat script.stake.hash) < script.addr > base.addr
addr_test1xpq0ghwy73wapjcdwqxm6ytwe66j8eccsmn9jptshrjera5lzysnjvzjed6ll5yttp0v5md8ypcwzc0flv40va3mvmwsl7grs3
```
</details>

<details>
  <summary>How to generate a delegated payment address, i.e. base address, from a script (<strong>base.addr</strong>)</summary>

```console
$ cardano-address address delegation "all [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk), active_from 100, active_until 120]" < script.addr > base.addr
addr_test1xpq0ghwy73wapjcdwqxm6ytwe66j8eccsmn9jptshrjera5lzysnjvzjed6ll5yttp0v5md8ypcwzc0flv40va3mvmwsl7grs3
```
</details>

<details>
  <summary>How to generate a stake address from a script hash (<strong>stake.addr</strong>)</summary>

```console
$ cardano-address address stake --network-tag testnet < script.stake.hash > stake.addr
stake_test17z03zgfexpfvka0l6z94shk2dknjqu8pv85lk2hkwcakdhgx52yaj
```
</details>

<details>
  <summary>How to generate a stake address from a script (<strong>stake.addr</strong>)</summary>

```console
$ cardano-address address stake --network-tag testnet "all [$(cat addr_shared.1.xvk), $(cat addr_shared.2.xvk), active_from 100, active_until 120]" > stake.addr
stake_test17z03zgfexpfvka0l6z94shk2dknjqu8pv85lk2hkwcakdhgx52yaj
```
</details>

<details>
  <summary>How to generate drep keys (<strong>drep</strong>)</summary>

```console
$ cat ../tests/root.xsk
root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983

$ cardano-address key child 1852H/1815H/0H/3/0 < root.xsk > drep.xsk
drep_xsk1vpdsm49smzmdwhd4kjmm2mdyljjysm746rafjr7r8kgfanj849psw8pfm305g59wng0akw3qzppmfh6k5z7gx66h2vppu022m4eqaj26rh6d7en9tf9fu52hmysjzuacaxfmfya65h8jmddrclwf3kxl8snfs3eg

$ cardano-address key public --with-chain-code < drep.xsk > drep.xvk
drep_xvk1mg7xae48d7z4nntd35tey0jmclxaavwmk3kw2lkkt07p3s3x3yy45805manx2kj2neg40kfpy9em36vnkjfm4fw09k66837unrvd70qq8ewzf

$ cardano-address key hash < drep.xvk > drep
drep1sp5xhvmj0asztqfsjyta3cwvq7jppc2rwmfcsggp62va538nup0
```
</details>


<details>
  <summary>How to generate cold committee keys (<strong>cc_cold</strong>)</summary>

```console
$ cat root.xsk
root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983

$ cardano-address key child 1852H/1815H/0H/4/0 < root.xsk > cold.xsk
cc_cold_xsk1fp4megtpn4vu4cug2lmsyhg4xvnnar55q6k8wp5e6f2h8jz849ph8v8jhm0qffw8v6ut7x8wqvr07m9ccaspezrkexcafu284w6gpqexspqujj8glw0d70rwuemk0924zjhscgcfnevy29zr0fc57tvjmg7jvvqh

$ cardano-address key public --with-chain-code < cold.xsk > cold.xvk
cc_cold_xvk1dg8d5du0v4ukqkfgset50xncudhwlfzz2p6epv096x0ndl8jsgzzdqzpe9yw37u7mu7xaenhv7242990ps3sn8jcg52yx7n3fuke9kst5t2py

$ cardano-address key hash < cold.xvk > cold
cc_cold1d7yw362prvnae5fc8063xdeapws9ptzdgjkqd4dk3qddccyzfjm
```
</details>

<details>
  <summary>How to generate hot committee keys (<strong>cc_hot</strong>)</summary>

```console
$ cat root.xsk
root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983

$ cardano-address key child 1852H/1815H/0H/5/0 < root.xsk > hot.xsk
cc_hot_xsk14z9ktfggpsm8sqd5ecepv9f4estxkukfualezuxrfry0mjj849puxsq7ch3tw67d7rfr4smvaa2u3tkfu675mxw85zlpafp6llfex7re88wh22s8f83ehn6uejgfrm74x8y98xlwdmgy64ufctwernp64umnr5uk

$ cardano-address key public --with-chain-code < hot.xsk > hot.xvk
cc_hot_xvk1a5q4r34xzm0r6y728d4gmrl7jvrfuh7r022k7wh5mzwmyg7d7l3hjwwaw54qwj0rn084enysj8ha2vwg2wd7umksf4tcnskaj8xr4tcempwly

$ cardano-address key hash < hot.xvk > hot
cc_hot1xk94yxqufrm5sjfv535hlnky8cf9fzg5kvp3r4qz9d5ezua5p8v
```
</details>

<details>
  <summary>How to generate script validation, preimage and script hash from script composed of drep (<strong>drep_script</strong>)</summary>

```console
$ cat drep
drep1sp5xhvmj0asztqfsjyta3cwvq7jppc2rwmfcsggp62va538nup0

$ cardano-address script validate "all [$(cat drep),active_from 5001]"
Validated.

$ cardano-address script validate "all [$(cat drep),$(cat hot)]"
Not validated: All keys of a script must have the same role: payment, delegation, policy, representative, committee cold or committee hot.

$ cardano-address script preimage "all [$(cat drep),active_from 5001]"
008201828200581c80686bb3727f602581309117d8e1cc07a410e14376d3882101d299da8204191389

$ cardano-address script hash "all [$(cat drep),active_from 5001]"
drep_script1608hfeauc3hvfpvdcqwfdhyd2cfm6j42rp62ckqrskazy57w2zt
```
</details>


<details>
  <summary>Correspondence between keys in cardano-addresses and cardano-cli (<strong>key.xsk key.xvk key.vk key.hash</strong>)</summary>

```console
Let's assume we have mnemonic
$ cat recovery-phrase.prv
nothing heart matrix fly sleep slogan tomato pulse what roof rail since plastic false enlist

Construct root extended private key
$ cardano-address key from-recovery-phrase Shelley < recovery-phrase.prv > root.xprv
root_xsk1apjwjs3ksgm5mnnk0cc5v5emgv0hmafmmy8tffay5s2ffk69830whwznr46672ruucdzwwtv9upv72e4ylrypyz5m6cyh0p00t7n3u3agt20lv32j4kxcqlkzu78nzjx0ysxxlc2ghfz9prxfmrds802xsuhh404~

Construct extended private key for account ix=0H, role=0 and address ix=0
$ cardano-address key child 1852H/1815H/0H/0/0 < root.xprv > key.xsk
addr_xsk1kzl5vgev0u843tfnxqcwg0lmaf7zhdhczddaqhas6dp6m6z98302e3avp8mhu94kxkpj2gss064f74km3rrptafh4fsztekz8k5c469shcvx35wrdmus3xemp984lcwhs0jdtl4pfcsrfspe00h9pej6rg8drvcv

Create extended signing key using cardano-cli
$ cardano-cli key convert-cardano-address-key --shelley-payment-key --signing-key-file key.xsk --out-file key.skey
{
    "type": "PaymentExtendedSigningKeyShelley_ed25519_bip32",
    "description": "",
    "cborHex": "5880b0bf46232c7f0f58ad333030e43ffbea7c2bb6f8135bd05fb0d343ade8453c5eacc7ac09f77e16b635832522107eaa9f56db88c615f537aa6025e6c23da98ae8fbbbf6410e24532f35e9279febb085d2cc05b3b2ada1df77ea1951eb694f3834b0be1868d1c36ef9089b3b094f5fe1d783e4d5fea14e2034c0397bee50e65a1a"
}

The cborhex here contains of 4 parts:
1. prefix 5880 - bytestring of 128 bytes
2. signing key (64 bytes) - b0bf46232c7f0f58ad333030e43ffbea7c2bb6f8135bd05fb0d343ade8453c5eacc7ac09f77e16b635832522107eaa9f56db88c615f537aa6025e6c23da98ae8
3. verification key (32 bytes) - fbbbf6410e24532f35e9279febb085d2cc05b3b2ada1df77ea1951eb694f3834
4. chain code (32 bytes) - b0be1868d1c36ef9089b3b094f5fe1d783e4d5fea14e2034c0397bee50e65a1a

Create corresponding verification key using cardano-cli
$ cardano-cli key verification-key --signing-key-file key.skey --verification-key-file key.vkey
{
    "type": "PaymentExtendedVerificationKeyShelley_ed25519_bip32",
    "description": "",
    "cborHex": "5840fbbbf6410e24532f35e9279febb085d2cc05b3b2ada1df77ea1951eb694f3834b0be1868d1c36ef9089b3b094f5fe1d783e4d5fea14e2034c0397bee50e65a1a"
}
The cborhex here contains of 3 parts:
1. prefix 5840 - bytestring of 64 bytes
2. verification key (32 bytes) - fbbbf6410e24532f35e9279febb085d2cc05b3b2ada1df77ea1951eb694f3834
3. chain code (32 bytes) - b0be1868d1c36ef9089b3b094f5fe1d783e4d5fea14e2034c0397bee50e65a1a

Rule for prefixes:
  - CBOR-encoded bytestring (which is what the 58 identifies)
  - size (80 means 128 bytes, whereas 40 means 64 bytes, 20 means 32 bytes)

Create verification key hash using cardano-cli
$ cardano-cli address key-hash --payment-verification-key-file key.vkey > key.hash
0185545935760c5e370d01e6f4fedbb89b7fd79e115f2837cfab9ea8

Alternatively, we can create non-extended key
$ cardano-address key public --without-chain-code < key.xsk > key.vk
addr_vk1lwalvsgwy3fj7d0fy707hvy96txqtvaj4ksa7al2r9g7k6208q6qmrv9k3

Also, take notice that signing key can be translated to cborhex:
$ cat key.xsk | bech32
b0bf46232c7f0f58ad333030e43ffbea7c2bb6f8135bd05fb0d343ade8453c5eacc7ac09f77e16b635832522107eaa9f56db88c615f537aa6025e6c23da98ae8b0be1868d1c36ef9089b3b094f5fe1d783e4d5fea14e2034c0397bee50e65a1a
(signing key and chain code appended)

Moreover, basing on key.vk one can get hash
$ cardano-cli address key-hash --payment-verification-key $(cat key.vk) > key1.hash
0185545935760c5e370d01e6f4fedbb89b7fd79e115f2837cfab9ea8

Within cardano-addresses one can get cborhex of verification key (with chain code)
$ cardano-address key public --with-chain-code < key.xsk | bech32
fbbbf6410e24532f35e9279febb085d2cc05b3b2ada1df77ea1951eb694f3834b0be1868d1c36ef9089b3b094f5fe1d783e4d5fea14e2034c0397bee50e65a1a
(verification key and chain code appended)

Within cardano-addresses one can get cborhex of verification key (without chain code)
$ cardano-address key public --without-chain-code < key.xsk | bech32
fbbbf6410e24532f35e9279febb085d2cc05b3b2ada1df77ea1951eb694f3834
(verification key without chain code)

Then, we can get compute hash (but here we need to use without chain code):
$ cardano-address key public --without-chain-code < key.xsk | cardano-address key hash | bech32
0185545935760c5e370d01e6f4fedbb89b7fd79e115f2837cfab9ea8

```
</details>

## Building CLI with nix

Building the cardano-address command-line interface with `nix` is straightforward. For example,
from linux, it can be done by running the following command from the root of this repository:

```console
$ nix build .#cardano-addresses-cli:exe:cardano-address 
```

After building, the executable can be found in `result/bin/cardano-address`, and it can be run like this:

```console
$ ./result/bin/cardano-address --help
```

Alternatively, the executable can be run directly from `nix` by writing `run` instead of `build`:

```console
$ nix run .#cardano-addresses-cli:exe:cardano-address
```

While running in this way, it is possible to give parameters to the `cardano-address` CLI by
preceeding the list of commands with two dashes. For example:

```console
$ nix run .#cardano-addresses-cli:exe:cardano-address -- script --help
```

## Docker Image

Building a docker image using `nix` is also very easy. For example, from linux,
a docker image containing the binary for the `cardano-address` CLI can be built by
running the following command from the root of the repository:

```console
$ docker load < $(nix build --print-out-paths .#docker.x86_64-linux.cardano-address)
```

### Run

After building and loading the docker image, we can run the `cardano-address` CLI
by using docker's run command. For example:

```console
$ docker run --rm cardano-address:latest cardano-address recovery-phrase generate --size 15
dismiss grit bacon glare napkin satisfy tribe proud carpet bench fantasy rich history face north
```

We use the auto-remove flag `--rm` when running commands to get rid of the
containers created in the process.

Also, we use the interactive flag `-i` when piping stdin:

```console
$ echo "addr1gqtnpvdhqrtpd4g424fcaq7k0ufuzyadt7djygf8qdyzevuph3wczvf2dwyx5u" | docker run --rm -i cardano-address:latest cardano-address address inspect
{
    "address_style": "Shelley",
    "stake_reference": "by pointer",
    "spending_key_hash": "1730b1b700d616d51555538e83d67f13c113ad5f9b22212703482cb3",
    "pointer": {
        "slot_num": 24157,
        "output_index": 42,
        "transaction_index": 177
    },
    "network_tag": 0
}
```

## NPM Package

There is an experimental NPM module for JavaScript and TypeScript
available, which works in both NodeJS and the browser.

Here is a code sample showing how it can be used:

```javascript
var cardanoAddresses = require('cardano-addresses')
var addr = 'addr1gqtnpvdhqrtpd4g424fcaq7k0ufuzyadt7djygf8qdyzevuph3wczvf2dwyx5u'

cardanoAddresses.inspectAddress(addr)
  .then(info => console.log(info)
```

- [NPM Package](https://www.npmjs.com/package/cardano-addresses)
- [API Documentation](https://IntersectMBO.github.io/cardano-addresses/typescript/)
- [Web Demo](https://IntersectMBO.github.io/cardano-addresses/demo/)

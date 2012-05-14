hsslcaps is a ssl/tls debug program/library

* it doesn't do any real encryption, so it only understands the plaintext handshake.
* it can check which ciphersuites/extensions a server supports
* it can extract the certificate chain provided by a server
* example binary traces the plaintext handshake to a server on port 443

### Dependencies ###

* haskell: ghc
* cabal
* cabal will tell you further details :)
* probably all libs apart from [asn1-data](http://hackage.haskell.org/package/asn1-data "asn1-data") will come with ghc

### Build / Run ###

    git clone git://github.com/stbuehler/hsslcaps.git
    cd hsslcaps
    cabal configure
    cabal build
    dist/build/hsslcaps/hsslcaps
    dist/build/hsslcaps/hsslcaps github.com

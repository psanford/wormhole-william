# Go SPAKE2 Implementation #

## Warning! ##

> This code has not been formally audited by a cryptographer. It therefore should
> not be considered safe or correct. Use it at your own risk! However it does
> interoperate with *python-spake2* which was the main purpose of writing this
> library.

Implementation of SPAKE2 key exchange protocol which interoperates with *Rust*
*Haskell* and *Python* versions.

This package defines the behavior of group and its element as package *groups*.
It also implements 2 groups *ed25519* and *multiplicative group over integer* as
2 packages. SPAKE2 calculation uses *ed25519* as default group and
allows user to switch to group of his choice.

## Ed25519 Group ##

This package implements Ed25519 group operations and confirms to the *Group* and
*Element* interface defined by *salsa.debian.org/vasudev/gospake2/groups*
package.

This package is based on reference implementation of *Ed25519* group in
[*python-spake2*](https://github.com/warner/python-spake2/raw/master/src/spake2/ed25519_basic.py).

Note that this package is not optimized for speed and relies on big numbers from
Go standard library (math/big).

Package implements operation on *Extended Co-ordinates* of *Twisted Edwards
Curve* it also has methods to convert the *Extended Co-ordinates* to *Affine
Co-ordinate*.

For operations like *Double* *Add* it uses algorithms defined in
[hyperelliptic.org](http://www.hyperelliptic.org/EFD/g1p/auto-twisted-extended-1.html).
Scalar Multiplication algorithm used by this package is referenced from [Haskell
Implementation by Jonathan
Lange](https://github.com/jml/haskell-spake2/raw/master/src/Crypto/Spake2/Groups/Ed25519.hs).


## Integer Group ##

This package implements multiplicative integer group which confirms to the
*Group* and *Element*interfaces defined in package
`salsa.debian.org/vasudev/gospake2/groups`.

A cyclic abelian group, in mathematical sense, is a collection of *elements* and
a (binary) operation that takes two element and produces a third. A group should
have following properties

* There is an *identity* element such that X+Identity = X
* There is a generator element G
* Adding G `n` times is called scalar multiplication: Y=n*G
* Addition loops around after *q* times called *order* of subgroup
  This means (n+k*q)*X = n*X
* scalar multiplication is associative n*(X+Y) = n*X + n*Y
* *scalar division* is multiplying by *q-n`*

A *scalar* is an integer in [0,q-1] inclusive. Scalars can be added to each
other, multiplied or inverted. You can go from scalar to Element of group but
its hard (in cryptographic sense) to do the reverse.

## Status ##

Interoperates with *Python* implementation and expected to interoperate with
*Rust* and *Haskell* implementations as they already interoperate with *Python*
version.

### Interoperability with Python ###

Requires the [LeastAuthority interoperability
harness](https://github.com/leastauthority/spake2-interop-test). Also make sure
you have ed25519group package available in `GOPATH`. Our entry point code is in
`cmd/interop-entry.go` file. Compile it using `go build cmd/interop-entry.go`.

Clone the interoperability harness to your machine and copy resulting binary of
above command into the same folder and now run the harness using following
command

``` shell
runhaskell TestInterop.hs ./interop-entry A abc -- ./python-interop-entrypoint.py B abc
```

Below paragraph confirms that gospake2 interoperates with python-spake2 using
all groups (Ed25519, I1024, I2048 and I3072)

    $ runhaskell.exe TestInterop.hs python python-spake2-interop-entrypoint.py A abc -- ./interop-entry.exe B abc
    ["python","python-spake2-interop-entrypoint.py","A","abc"]
    ["./interop-entry.exe","B","abc"**
    Read bytes length: 33
    A's key: 601d84b5ceb7bdaf0ed361e4e40e775cc37d19ae96d76bb9e568c242858af8a5
    B's key: 601d84b5ceb7bdaf0ed361e4e40e775cc37d19ae96d76bb9e568c242858af8a5
    Session keys match.

    $ runhaskell TestInterop.hs python3 python-spake2-interop-entrypoint.py A abc I1024 -- ~/go/src/salsa.debian.org/vasudev/gospake2/interop-entry  B abc I1024
    ["python3","python-spake2-interop-entrypoint.py","A","abc","I1024"]
    ["/home/vasudev/go/src/salsa.debian.org/vasudev/gospake2/interop-entry","B","abc","I1024"]
    A's key: 6851b6526c3d1fd818bb67ae30e0d52cbbce5263d0e60d32a97af54841eb4540
    B's key: 6851b6526c3d1fd818bb67ae30e0d52cbbce5263d0e60d32a97af54841eb4540
    Session keys match.

    runhaskell TestInterop.hs python3 python-spake2-interop-entrypoint.py A abc I2048 -- ~/go/src/salsa.debian.org/vasudev/gospake2/interop-entry  B abc I2048
    ["python3","python-spake2-interop-entrypoint.py","A","abc","I2048"]
    ["/home/vasudev/go/src/salsa.debian.org/vasudev/gospake2/interop-entry","B","abc","I2048"]
    A's key: a4126dfd89fcb1a8a802d52126b745e0b2a16d01a95ba51f5038a2024db67013
    B's key: a4126dfd89fcb1a8a802d52126b745e0b2a16d01a95ba51f5038a2024db67013
    Session keys match.

    runhaskell TestInterop.hs python3 python-spake2-interop-entrypoint.py A abc I3072 -- ~/go/src/salsa.debian.org/vasudev/gospake2/interop-entry  B abc I3072
    ["python3","python-spake2-interop-entrypoint.py","A","abc","I3072"]
    ["/home/vasudev/go/src/salsa.debian.org/vasudev/gospake2/interop-entry","B","abc","I3072"]
    A's key: ffe3346997f6be05979d5a10a9226263ce91656a0b3aee5f42bb997c3d559e04
    B's key: ffe3346997f6be05979d5a10a9226263ce91656a0b3aee5f42bb997c3d559e04
    Session keys match.


## Benchmark of SPAKE2 with Integer Group and Ed25519 Group ##

You can run the benchmark using following command

```shell
go test -run xxx -bench .
```

Since test command always runs test we use -run xxx making sure no test is run
and only benchmark is run.

Following is benchmark output on my Thinkpad E470 with i5-core 7th Gen and 4GB
RAM.

    goos: linux
    goarch: amd64
    pkg: salsa.debian.org/vasudev/gospake2
    BenchmarkSPAKE2Ed25519Asymmetric-4            50          25214168 ns/op
    BenchmarkSPAKE21024Asymmetric-4              200           6648779 ns/op
    BenchmarkSPAKE22048Asymmetric-4               50          36183123 ns/op
    BenchmarkSPAKE23072Asymmetric-4               20          99544815 ns/op
    BenchmarkSPAKE2Ed25519Symmetric-4             50          25477101 ns/op
    BenchmarkSPAKE21024Symmetric-4               200           6658501 ns/op
    BenchmarkSPAKE22048Symmetric-4                50          36181414 ns/op
    BenchmarkSPAKE23072Symmetric-4                20          99507167 ns/op
    PASS
    ok      salsa.debian.org/vasudev/gospake2       14.474s

Integer group with 1024 bit seems to be faster than Ed25519 group, this may be
because ed25519group code is not optimized for speed and built using big
numbers. Integer groups with 2048 and 3072 bit is slower but more secure.


## TODO ##
 None for now

## License ##
Copyright: 2021, Vasudev Kamath <vasudev@copyninja.info>

This library is free software; you can redistribute it and/or modify it under
the terms of the MIT License or the GNU General Public License as published
by the Free Software Foundation; either version 3 of the License, or (at your
option) any later version.

This library is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the LICENSE file for more details.

You should have received a copy of the GNU Library General Public License along
with this library; if not, write to the Free Software Foundation, Inc., 51
Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

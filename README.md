# mutiny-node

[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/utxostack/mutiny-node/blob/master/LICENSE)
[![npm version](https://badge.fury.io/js/@nervina-labs%2Fmutiny-wasm.svg)](https://badge.fury.io/js/@nervina-labs%2Fmutiny-wasm)

The mutiny node that powers the mutiny web frontend.

## Importing

The web front end imports the NPM package that this project
creates [here](https://www.npmjs.com/package/@nervina-labs/mutiny-wasm).

## Development

### Nixos

A `flake.nix` file has been added for easier nix development and testing. Pretty much all cargo / wasm commands work,
though right now optimized for `aarch64-unknown-linux-gnu` and `wasm32-unknown-unknown` compilation in the nix shell.

To start:

```
nix develop
```

Then the following `just` examples that work:

```
just clippy-nix
just test-nix
just pack
just release
```

### Building on the mac

See the discussion here:
https://github.com/rust-bitcoin/rust-secp256k1/issues/283

You may have to either prefix some environment variables or set them in your env or shell file:

```
AR=/opt/homebrew/opt/llvm/bin/llvm-ar CC=/opt/homebrew/opt/llvm/bin/clang
```

### Dependencies

- [rust](https://www.rust-lang.org/) (specifically, nightly: `rustup toolchain install nightly-2024-09-19`
  and `rustup target add wasm32-unknown-unknown --toolchain nightly`)

- [node](https://nodejs.org/en/)

- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/#)

```
cargo install wasm-pack
```

- [just](https://github.com/casey/just)

- [chromedriver](https://chromedriver.chromium.org/)

```
brew install chromedriver
```

### Build

Get all the dependencies above first.

Build the rust wasm stuff:

```
just pack
```

### Testing

To run the local tests you can simply use

```
just test
```


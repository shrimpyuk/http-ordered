# http-ordered

Fork of [http](https://github.com/hyperium/http) that supports header ordering.

Disregarding for performance, it replaces HeaderMap robinhood hashing implementation with [indexmap](https://github.com/bluss/indexmap).

Almost all of the public API's of HeaderMap are the same, except the IntoHeaderName type, which has been removed. It should be mostly compatible with any library that uses upstream http.

## Features
* HeaderMap keeps the order of insertion
* HeaderMap.sort_by function that allows you to sort headers by key and value

## Patching [reqwest](https://github.com/seanmonstar/reqwest)
Due to some borrow checker inconsistencies (PRs are welcome), you won't be able to compile reqwest right of the bat, however only one function needs to be changed, and an example implementation can be viewed [here](https://github.com/ignassew/reqwestplus/commit/314a180fb57571767ad698b38300f5b504bf1409).

Once you have fixed that issue, you will need to insert this in your `Cargo.toml`:
```toml
[patch.crates-io]
http = { git = "https://github.com/ignassew/http-ordered" }
```

If you don't want to patch the library yourself, check out [reqwestplus](#reqwestplus)

## reqwestplus
This fork is a part of a larger project - [reqwestplus](https://github.com/ignassew/reqwestplus), which is itself a fork of reqwest that has additional features that help with matching browser's fingerprint.

## Original README

A general purpose library of common HTTP types

[![CI](https://github.com/hyperium/http/workflows/CI/badge.svg)](https://github.com/hyperium/http/actions?query=workflow%3ACI)
[![Crates.io](https://img.shields.io/crates/v/http.svg)](https://crates.io/crates/http)
[![Documentation](https://docs.rs/http/badge.svg)][dox]

More information about this crate can be found in the [crate
documentation][dox].

[dox]: https://docs.rs/http

## Usage

To use `http`, first add this to your `Cargo.toml`:

```toml
[dependencies]
http = "0.2"
```

Next, add this to your crate:

```rust
use http::{Request, Response};

fn main() {
    // ...
}
```

## Examples

Create an HTTP request:

```rust
use http::Request;

fn main() {
    let request = Request::builder()
      .uri("https://www.rust-lang.org/")
      .header("User-Agent", "awesome/1.0")
      .body(())
      .unwrap();
}
```

Create an HTTP response:

```rust
use http::{Response, StatusCode};

fn main() {
    let response = Response::builder()
      .status(StatusCode::MOVED_PERMANENTLY)
      .header("Location", "https://www.rust-lang.org/install.html")
      .body(())
      .unwrap();
}
```

# Supported Rust Versions

This project follows the [Tokio MSRV][msrv] and is currently set to `1.49`.

[msrv]: https://github.com/tokio-rs/tokio/#supported-rust-versions

# License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)

# Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

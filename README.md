# puny-tls - no-std/no-alloc TLS 1.3 client

This is an improvement over [tiny-tls-rs](https://github.com/bjoernQ/tiny-tls-rs) to make it more useable.

However the only reason this exists is to replace it's usage some day with e.g. [embedded-tls](https://crates.io/crates/embedded-tls) or something similar.

Other than `embedded-tls` this only supports blocking mode.

In general this shouldn't be used for production.

However it is able to connect to some real worls TLS1.3 servers like
- www.google.com:443
- tls13.akamai.io:443
- io.adafruit.com:8883
- aws.amazon.com:443
- www.cloudflare.com:443
- www.microsoft.com:443

# This is a very limited implementation

- it doesn't check the server certificate 
- it only supports one cipher suite

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
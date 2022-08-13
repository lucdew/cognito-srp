# cognito_srp [![][crate-image]][crate-link] [![][docs-image]][docs-link]

Pure Rust implementation of AWS cognito SRP password authenticated key-exchange algorithm.

The library is a port of Python [warrant] library's cryptography with a different interface.

The library is not production ready.


## Security Warning

The code has not been audited for security risks and the implementation might not be correct.

USE AT YOUR OWN RISK!

## Minimum Supported Rust Version

Rust **1.56** or higher.

## License

Crate is licensed under

 * [MIT license](http://opensource.org/licenses/MIT)


## Usage

Instantiate a `SrpClient`, use `get_auth_params` function for the SDK cognito idp `initiate_auth` challenge response flow initiate step

Use `process_challenge` to generate the response to the server challenge.

```rust
    let srp_client = SrpClient::new();

    let srp_client = SrpClient::new(
        "COGNITO_USERNAME",
        "COGNITO_PASSWORD",
        "COGNITO_POOL_ID",
        "COGNITO_CLIENT_ID",
        None,
    );

    let auth_init_res = cognito_client
        .initiate_auth()
        .auth_flow(AuthFlowType::UserSrpAuth)
        .client_id("cognito client id".to_string())
        .set_auth_parameters(Some(srp_client.get_auth_params().unwrap()))
        .send()
        .await;

    let auth_init_out = auth_init_res.unwrap();

    let challenge_params =
        auth_init_out
            .challenge_parameters
            .unwrap();
    let challenge_responses =
        srp_client.process_challenge(challenge_params).unwrap();

    let password_challenge_result = cognito_client
        .respond_to_auth_challenge()
        .set_challenge_responses(Some(challenge_responses))
        .client_id("cognito client id".to_string())
        .challenge_name(ChallengeNameType::PasswordVerifier)
        .send()
        .await;

    let password_challenge_response = password_challenge_result.unwrap();

```

A comprehensive example is available here: https://github.com/lucdew/cognito-srp-auth

## Tests

Only tested manually without any client secret.


[//]: # (badges)
[crate-image]: https://img.shields.io/crates/v/cognito_srp.svg
[crate-link]: https://crates.io/crates/cognito_srp
[docs-image]: https://img.shields.io/badge/rust-documentation-blue.svg
[docs-link]: https://docs.rs/cognito_srp/


[//]: # (general links)

[warrant]: https://github.com/capless/warrant

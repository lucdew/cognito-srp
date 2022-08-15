use crate::error::CognitoSrpError;

use base64;
use chrono::prelude::*;
use digest::{Digest, Output};
use hex;
use hmac::{Hmac, Mac};
use num_bigint::{BigInt, BigUint, Sign};
use rand::prelude::*;
use regex::Regex;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

lazy_static! {
    static ref G_2048_G:BigUint = BigUint::from_bytes_be(&[2]);
    static ref G_2048_N:BigUint =  BigUint::from_bytes_be(&hex::decode("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF").unwrap());
    static ref DERIVE_KEY_INFO:String = String::from("Caldera Derived Key");
    static ref ZERO_LEFT_PAD_DIGIT_REGEX:Regex = Regex::new(r" 0(\d) ").unwrap();
}

fn compute_pub_a(a: &[u8]) -> Vec<u8> {
    G_2048_G
        .modpow(&BigUint::from_bytes_be(a), &G_2048_N)
        .to_bytes_be()
}

fn compute_u<D: Digest>(a_pub: &[u8], b_pub: &[u8]) -> BigUint {
    let mut u = D::new();
    u.update(zero_pad(a_pub));
    u.update(zero_pad(b_pub));
    BigUint::from_bytes_be(&u.finalize())
}

// x = H(<salt> | H(<pool_id><username> | ":" | <raw password>))
fn compute_x<D: Digest>(identity_hash: &[u8], salt: &[u8]) -> BigUint {
    let mut x = D::new();
    x.update(zero_pad(salt).as_slice());
    x.update(identity_hash);
    BigUint::from_bytes_be(&x.finalize())
}

fn zero_pad(data: &[u8]) -> Vec<u8> {
    if data.len() == 0 {
        return vec![];
    } else if data[0] < 128 {
        //return data.to_vec();
        return data.to_vec();
    } else {
        let mut v8: Vec<u8> = vec![];
        v8.extend_from_slice(&[0]);
        v8.extend_from_slice(data);
        return v8;
    }
}

fn compute_secret_hash(
    username: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, CognitoSrpError> {
    let mut hmac_obj = HmacSha256::new_from_slice(client_secret.as_bytes())?;
    hmac_obj.update(username.as_bytes());
    hmac_obj.update(client_id.as_bytes());
    Ok(base64::encode(hmac_obj.finalize().into_bytes()))
}

fn compute_identity_hash<D: Digest>(pool_name: &str, username: &str, password: &str) -> Output<D> {
    let mut d = D::new();
    d.update(pool_name.as_bytes());
    d.update(username.as_bytes());
    d.update(b":");
    d.update(password.as_bytes());
    d.finalize()
}

fn compute_k<D: Digest>() -> BigUint {
    let n = G_2048_N.to_bytes_be();
    let g_bytes = G_2048_G.to_bytes_be();

    let mut d = D::new();
    d.update(&[0]);
    d.update(&n);
    d.update(&g_bytes);
    BigUint::from_bytes_be(d.finalize().as_slice())
}

fn get_password_authentication_key(
    a: &[u8],
    username: &str,
    password: &str,
    pool_name: &str,
    salt: &[u8],
    srp_b: &[u8],
) -> Result<Vec<u8>, CognitoSrpError> {
    let a_pub = compute_pub_a(a);
    let b_pub = BigUint::from_bytes_be(srp_b);
    let u = compute_u::<Sha256>(&a_pub[..], &b_pub.to_bytes_be());
    let identity_hash = compute_identity_hash::<Sha256>(pool_name, username, password);
    let x = compute_x::<Sha256>(identity_hash.as_slice(), salt);
    let k = compute_k::<Sha256>();
    let g_mod_pow_xn = G_2048_G.modpow(&x, &G_2048_N);
    let int_value2 = BigInt::from_bytes_be(Sign::Plus, srp_b)
        - BigInt::from_biguint(Sign::Plus, k * g_mod_pow_xn);
    let s_value = int_value2.modpow(
        &BigInt::from_biguint(Sign::Plus, BigUint::from_bytes_be(&a) + (&u * x)),
        &BigInt::from_bytes_be(Sign::Plus, &G_2048_N.to_bytes_be()),
    );

    let mut hkdf = HmacSha256::new_from_slice(&zero_pad(&u.to_bytes_be()))?;
    hkdf.update(&zero_pad(&s_value.to_bytes_be().1));
    let prk = hkdf.finalize().into_bytes();

    let mut key_derive_data: Vec<u8> = vec![];
    key_derive_data.extend_from_slice(DERIVE_KEY_INFO.as_bytes());
    key_derive_data.extend_from_slice(&[1]);

    hkdf = HmacSha256::new_from_slice(&prk)?;
    hkdf.update(&key_derive_data);

    let ak = &(hkdf.finalize().into_bytes())[..16];

    Ok(ak.to_vec())
}

/// Prefix with 0 an hexa string if it has an odd number of chars and decode it
fn safe_hex_decode(hex_str: &str) -> Result<Vec<u8>, hex::FromHexError> {
    // len() returns bytes size not chars but ok for ascii
    if hex_str.len() % 2 != 0 {
        hex::decode(format!("0{}", hex_str))
    } else {
        hex::decode(hex_str)
    }
}

fn get_mandatory_challenge_params<const N: usize>(
    challenge_params: &HashMap<String, String>,
    param_names: [&str; N],
) -> Result<[String; N], CognitoSrpError> {
    let mut param_vals = vec![];
    for param_name in param_names {
        let param_val = challenge_params
            .get(param_name)
            .map(|x| x.to_owned())
            .ok_or(CognitoSrpError::IllegalArgument(format!(
                "Missing {0} in challenge parameters",
                param_name.to_string()
            )))?;
        param_vals.push(param_val);
    }
    Ok(param_vals
        .try_into()
        .expect("unexpected size difference in vec to array conversion for challenge params"))
}

/// Cognito SRP client, stores the client a secret ephemeral value, cognito pool, user and client
/// parameters
pub struct SrpClient<'a> {
    a: Vec<u8>,
    username: &'a str,
    password: &'a str,
    pool_id: &'a str,
    client_id: &'a str,
    client_secret: Option<&'a str>,
}

impl<'a> SrpClient<'a> {
    /// Instantiate a new SrpClient
    ///
    /// * `username` - cognito username
    /// * `password` - cognito password
    /// * `pool_id` - cognito pool id
    /// * `client_id` - cognito client secret
    /// * `client_secret` - Option with cognito client secret
    pub fn new(
        username: &'a str,
        password: &'a str,
        pool_id: &'a str,
        client_id: &'a str,
        client_secret: Option<&'a str>,
    ) -> Self {
        let mut rng = rand::thread_rng();
        let mut a = [0u8; 128];
        rng.fill_bytes(&mut a);
        Self {
            a: a.to_vec(),
            username,
            password,
            pool_id,
            client_id,
            client_secret,
        }
    }

    /// Generate parameters to use in challenge initialization with cognitor idp initiate_auth
    /// It generates a SRP public ephemeral value for the client
    pub fn get_auth_params(&self) -> Result<HashMap<String, String>, CognitoSrpError> {
        let a_pub = compute_pub_a(&self.a);

        let mut auth_params: HashMap<String, String> = HashMap::new();
        auth_params.insert(String::from("USERNAME"), self.username.into());
        auth_params.insert(String::from("SRP_A"), hex::encode(a_pub));
        if let Some(client_secret) = self.client_secret {
            auth_params.insert(
                String::from("SECRET_HASH"),
                compute_secret_hash(self.username, self.client_id, client_secret)?,
            );
        }
        Ok(auth_params)
    }

    /// Compute client response of the server challenge returned by cognito idp initiate_auth
    pub fn process_challenge(
        &self,
        challenge_params: HashMap<String, String>,
    ) -> Result<HashMap<String, String>, CognitoSrpError> {
        let [secret_block_b64, user_id, salt_hex, srp_b_hex] = get_mandatory_challenge_params(
            &challenge_params,
            ["SECRET_BLOCK", "USER_ID_FOR_SRP", "SALT", "SRP_B"],
        )?;

        let pool_name = self
            .pool_id
            .split("_")
            .nth(1)
            .ok_or(CognitoSrpError::IllegalArgument(
                "Invalid pool_id must be in the form <pool_name>_<region>".to_string(),
            ))?;

        let secret_block = base64::decode(secret_block_b64.clone()).map_err(|err| {
            CognitoSrpError::IllegalArgument(format!(
                "Invalid base64 SECRET_BLOCK in challenge parameters, got {}",
                err.to_string()
            ))
        })?;

        let auth_key = get_password_authentication_key(
            &self.a,
            &user_id,
            &self.password,
            pool_name,
            &safe_hex_decode(&salt_hex).map_err(|err| {
                CognitoSrpError::IllegalArgument(format!(
                    "Invalid hexa SALT in challenge parameters, got {}",
                    err.to_string()
                ))
            })?,
            &safe_hex_decode(&srp_b_hex).map_err(|err| {
                CognitoSrpError::IllegalArgument(format!(
                    "Invalid hexa SRP_P in challenge parameters, got {}",
                    err.to_string()
                ))
            })?,
        )?;
        let pool_name = self.pool_id.split("_").nth(1).unwrap();
        let timestamp = ZERO_LEFT_PAD_DIGIT_REGEX
            .replace_all(
                &Utc::now().format("%a %b %d %H:%M:%S UTC %Y").to_string(),
                " $1 ",
            )
            .to_string();

        let mut msg: Vec<u8> = vec![];
        msg.extend_from_slice(pool_name.as_bytes());
        msg.extend_from_slice(user_id.as_bytes());
        msg.extend_from_slice(&secret_block);
        msg.extend_from_slice(timestamp.as_bytes());

        let mut h256mac = HmacSha256::new_from_slice(&auth_key)?;
        h256mac.update(&msg);
        let signature = h256mac.finalize().into_bytes();
        let mut challenge_res: HashMap<String, String> = HashMap::new();
        challenge_res.insert(String::from("TIMESTAMP"), timestamp);
        challenge_res.insert(String::from("USERNAME"), user_id.into());
        challenge_res.insert(
            String::from("PASSWORD_CLAIM_SECRET_BLOCK"),
            secret_block_b64.into(),
        );
        if let Some(client_secret) = self.client_secret {
            challenge_res.insert(
                String::from("SECRET_HASH"),
                compute_secret_hash(self.username, self.client_id, client_secret)?,
            );
        }
        let signature_string = base64::encode(signature);

        challenge_res.insert(String::from("PASSWORD_CLAIM_SIGNATURE"), signature_string);

        Ok(challenge_res)
    }
}
#[cfg(test)]
mod tests {

    use crate::client::compute_k;
    use sha2::Sha256;

    #[test]
    fn test_k() {
        let k = compute_k::<Sha256>().to_bytes_be();
        println!("{}", hex::encode(k));
    }
}

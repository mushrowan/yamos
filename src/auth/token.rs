use super::traits::{Claims, TokenIssuer, TokenResponse, TokenType, TokenValidator};
use anyhow::{Result, anyhow};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use uuid::Uuid;

pub struct JwtTokenIssuer {
    encoding_key: EncodingKey,
    default_expiration: Option<std::time::Duration>,
}

impl JwtTokenIssuer {
    pub fn new(secret: String, default_expiration: Option<std::time::Duration>) -> Self {
        Self {
            encoding_key: EncodingKey::from_secret(secret.as_bytes()),
            default_expiration,
        }
    }
}

impl TokenIssuer for JwtTokenIssuer {
    fn issue_token(
        &self,
        client_id: &str,
        custom_duration: Option<std::time::Duration>,
    ) -> Result<TokenResponse> {
        let now = Utc::now();
        let duration = custom_duration.or(self.default_expiration);

        let claims = Claims {
            sub: client_id.to_string(),
            iat: now.timestamp(),
            exp: duration.map(|d| {
                (now + Duration::from_std(d).expect("token expiration duration out of range"))
                    .timestamp()
            }),
            jti: Uuid::new_v4().to_string(),
            iss: "yamos".to_string(),
        };

        let token = encode(&Header::default(), &claims, &self.encoding_key)
            .map_err(|e| anyhow!("Failed to encode JWT: {}", e))?;

        Ok(TokenResponse {
            access_token: token,
            token_type: TokenType::Bearer,
            expires_in: duration.map(|d| d.as_secs()),
            refresh_token: None, // set by handlers after storing in RefreshTokenStore
        })
    }
}

pub struct JwtTokenValidator {
    decoding_key: DecodingKey,
    validation: Validation,
}

impl JwtTokenValidator {
    pub fn new(secret: String) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&["yamos"]);
        validation.validate_exp = true; // Will validate if exp claim exists
        validation.required_spec_claims = vec!["sub".to_string(), "iat".to_string()]
            .into_iter()
            .collect();

        Self {
            decoding_key: DecodingKey::from_secret(secret.as_bytes()),
            validation,
        }
    }
}

impl TokenValidator for JwtTokenValidator {
    fn validate_token(&self, token: &str) -> Result<Claims> {
        let token_data = decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map_err(|e| anyhow!("Invalid JWT: {}", e))?;

        Ok(token_data.claims)
    }
}

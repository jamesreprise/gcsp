use anyhow::Context;
use regex::Regex;

const AWSV4_AUTHORIZATION_HEADER_REGEX_PATTERN: &str = r"^AWS4-HMAC-SHA256 Credential=(\S+)\/(\S+)\/(\S+)\/(\S+)\/(\S+), SignedHeaders=(\S+), Signature=(\S+)$";

#[allow(dead_code)]
pub(crate) struct AWSV4AuthHeaderCredential {
    pub(crate) hmac_access_key: String,
    pub(crate) date_stamp: String,
    pub(crate) region: String,
    pub(crate) service: String,
}

#[allow(dead_code)]
pub(crate) struct AWSV4AuthHeader {
    pub(crate) credential: AWSV4AuthHeaderCredential,
    pub(crate) signed_headers: String,
    pub(crate) signature: String,
}

impl AWSV4AuthHeader {
    pub(crate) fn from_header(auth_header_value: &str) -> anyhow::Result<Self> {
        let regex = Regex::new(AWSV4_AUTHORIZATION_HEADER_REGEX_PATTERN)?;
        let captures = regex
            .captures(auth_header_value)
            .context("Couldn't regex AWSV4 signature header from client request")?;

        let hmac_access_key = captures[1].to_string();
        let date_stamp = captures[2].to_string();
        let region = captures[3].to_string();
        let service = captures[4].to_string();
        anyhow::ensure!(captures[5] == *"aws4_request");
        let signed_headers = captures[6].to_string();
        let signature = captures[7].to_string();

        Ok(AWSV4AuthHeader {
            credential: AWSV4AuthHeaderCredential {
                hmac_access_key,
                date_stamp,
                region,
                service,
            },
            signed_headers,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    #[test]
    fn parse_auth_header_from_string() -> Result<()> {
        let auth_header = AWSV4AuthHeader::from_header("AWS4-HMAC-SHA256 Credential=GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA/19700101/europe-west6/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=004ed2b779ff4a08dee5d97269297463c92f57492b4a43146406f5e29533eb1a")?;

        assert_eq!(
            auth_header.credential.hmac_access_key,
            "GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA".to_string()
        );
        assert_eq!(auth_header.credential.date_stamp, "19700101".to_string());
        assert_eq!(auth_header.credential.region, "europe-west6".to_string());
        assert_eq!(auth_header.credential.service, "s3".to_string());
        assert_eq!(
            auth_header.signature,
            "004ed2b779ff4a08dee5d97269297463c92f57492b4a43146406f5e29533eb1a"
        );
        assert_eq!(
            auth_header.signed_headers,
            "host;x-amz-content-sha256;x-amz-date"
        );
        Ok(())
    }

    #[test]
    fn error_on_bad_signature_algorithm_prefix() -> Result<()> {
        let auth_header = AWSV4AuthHeader::from_header("AZURE4-HMAC-SHA256 Credential=GOOGTS7C7FUP3AIRVJTE2BCDKINBTES3HC2GY5CBFJDCQ2SYHV6A6XXVTJFSA/19700101/europe-west6/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=004ed2b779ff4a08dee5d97269297463c92f57492b4a43146406f5e29533eb1a");

        assert!(auth_header.is_err());
        Ok(())
    }
}

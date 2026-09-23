use hickory_proto::op::Message;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use std::time::Duration;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct DohResolver {
    pub url: String,
    pub name: String,
    client: reqwest::Client,
}

impl DohResolver {
    pub fn new(url: String) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/dns-message"),
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/dns-message"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap_or_default();

        Self {
            name: format!("doh:{url}"),
            url,
            client,
        }
    }

    pub async fn resolve(&self, query: &Message, query_timeout: Duration) -> Result<Message, String> {
        let bytes = query
            .to_vec()
            .map_err(|e| format!("Failed to serialize query: {e}"))?;

        timeout(query_timeout, async {
            let res = self
                .client
                .post(&self.url)
                .body(bytes)
                .send()
                .await
                .map_err(|e| format!("DoH HTTP request to {} failed: {e}", self.url))?;

            if !res.status().is_success() {
                return Err(format!(
                    "DoH server {} returned HTTP status: {}",
                    self.url,
                    res.status()
                ));
            }

            let body_bytes = res
                .bytes()
                .await
                .map_err(|e| format!("Failed to read DoH response body: {e}"))?;

            let mut resp = Message::from_vec(&body_bytes)
                .map_err(|e| format!("Failed to parse DoH DNS response: {e}"))?;

            // In DoH, ID may sometimes be set to 0 by resolvers; fix it to match query if needed
            if resp.metadata.id != query.metadata.id {
                resp.metadata.id = query.metadata.id;
            }

            Ok(resp)
        })
        .await
        .map_err(|_| format!("DoH query to {} timed out after {:?}", self.url, query_timeout))?
    }
}

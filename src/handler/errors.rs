use axum::{
    http,
    response::{IntoResponse, Response},
};

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError(error) => write!(f, "{}", error),
        }
    }
}

pub(crate) struct ProxyError(pub(crate) anyhow::Error);

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        (
            http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("ERROR: {}", self.0),
        )
            .into_response()
    }
}

impl<E> From<E> for ProxyError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

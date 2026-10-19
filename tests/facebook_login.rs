//! Runs the Facebook client against a local stand-in for the Graph API.

use std::collections::HashMap;

use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use openidconnect::{reqwest, url::Url};
use serde_json::json;
use shortlink::{
    auth::{error::AuthError, facebook::FacebookClient},
    config::FacebookConfig,
};

const APP_SECRET: &str = "app-secret";
const GOOD_CODE: &str = "good-code";
const TOKEN: &str = "user-token";
// printf 'user-token' | openssl dgst -sha256 -hmac 'app-secret'
const TOKEN_PROOF: &str = "b5a94d985eb7b68467d28ca5375162d12b9ca8fe238615acc927c8a9c08d2e95";

async fn exchange(Query(query): Query<HashMap<String, String>>) -> Response {
    let valid = query.get("code").map(String::as_str) == Some(GOOD_CODE)
        && query.get("client_secret").map(String::as_str) == Some(APP_SECRET)
        && query.get("redirect_uri").map(String::as_str)
            == Some("http://localhost:3100/auth/facebook/callback");

    if valid {
        Json(json!({ "access_token": TOKEN, "token_type": "bearer" })).into_response()
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": { "message": "bad code" } })),
        )
            .into_response()
    }
}

async fn me(Query(query): Query<HashMap<String, String>>) -> Response {
    let valid = query.get("access_token").map(String::as_str) == Some(TOKEN)
        && query.get("appsecret_proof").map(String::as_str) == Some(TOKEN_PROOF);

    if valid {
        Json(json!({
            "id": "10001",
            "name": "Ann Lee",
            "email": "ann@example.com",
            "picture": { "data": {
                "url": "https://platform-lookaside.fbsbx.com/platform/profilepic/?asid=10001",
                "is_silhouette": false
            } }
        }))
        .into_response()
    } else {
        StatusCode::FORBIDDEN.into_response()
    }
}

async fn client() -> FacebookClient {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let graph_url = format!("http://{}/v26.0/", listener.local_addr().unwrap());
    let graph = Router::new()
        .route("/v26.0/oauth/access_token", get(exchange))
        .route("/v26.0/me", get(me));
    tokio::spawn(async move { axum::serve(listener, graph).await.unwrap() });

    FacebookClient::new(
        reqwest::Client::new(),
        FacebookConfig {
            client_id: "app-id".to_owned(),
            client_secret: APP_SECRET.to_owned(),
            dialog_url: Url::parse("https://www.facebook.com/v26.0/dialog/oauth").unwrap(),
            graph_url: Url::parse(&graph_url).unwrap(),
        },
        &Url::parse("http://localhost:3100").unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn a_good_code_gives_the_profile_with_an_unverified_email() {
    let identity = client().await.finish(GOOD_CODE.to_owned()).await.unwrap();

    assert_eq!(identity.subject, "10001");
    assert_eq!(identity.display_name.as_deref(), Some("Ann Lee"));
    let email = identity.email.unwrap();
    assert_eq!(email.address, "ann@example.com");
    assert!(!email.verified);
    assert!(identity.picture.is_some());
}

#[tokio::test]
async fn a_bad_code_is_a_provider_failure() {
    let error = client()
        .await
        .finish("stolen-code".to_owned())
        .await
        .unwrap_err();

    assert!(matches!(error, AuthError::Provider(_)), "{error:?}");
}

#[tokio::test]
async fn the_dialog_asks_for_email_and_carries_the_state() {
    let (url, pending) = client().await.begin();
    let query: HashMap<_, _> = url.query_pairs().into_owned().collect();

    assert_eq!(url.host_str(), Some("www.facebook.com"));
    assert_eq!(query["client_id"], "app-id");
    assert_eq!(query["scope"], "email,public_profile");
    assert_eq!(query["state"], pending.state);
    assert_eq!(
        query["redirect_uri"],
        "http://localhost:3100/auth/facebook/callback"
    );
}

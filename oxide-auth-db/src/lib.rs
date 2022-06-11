pub mod db_service;
pub mod primitives;

#[cfg(test)]
fn requires_redis_and_should_skip() -> bool {
    match std::env::var("OXIDE_AUTH_SKIP_REDIS") {
        Err(_) => false,
        Ok(st) => match st.as_str() {
            "1" | "yes" => true,
            _ => false,
        },
    }
}

pub trait AccessLike {
    fn token_type() -> &'static str;
}

pub struct BearerToken {
    content: String
}

impl AccessLike for BearerToken {
    fn token_type() -> &'static str {
        return "Bearer"
    }
}

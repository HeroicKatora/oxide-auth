use crate::code_grant;

#[test]
fn require_futures_have_send_bounds() {
    fn require_send<T: Send, A, B, F: FnOnce(A, B) -> T>(_: F) {}

    require_send(code_grant::access_token::access_token);
    require_send(code_grant::authorization::authorization_code);
    require_send(|pending, handler| {
        code_grant::authorization::Pending::authorize(pending, handler, "".into())
    });
    require_send(code_grant::refresh::refresh);
    require_send(code_grant::resource::protect);
}

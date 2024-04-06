// Should this return a whole authentication response instead?
fn post_auth (authn, authz, mech, backend) {
    if authn == "jwilbur" {
        return false;
    }
    true
}
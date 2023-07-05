use super::structs::{Context, Decision, UserAttributes};

pub fn evaluate_policy(attributes: &UserAttributes, context: &Context) -> Decision {
    // Global admins can do anything
    if attributes.global_admin {
        return Decision::Allow(Vec::new());
    }
    if attributes.service_account && context.is_personal() {
        return Decision::Deny;
    }

    let token_perms = attributes.tokens


    match context.

    Decision::Deny
}

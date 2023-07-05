use super::{
    policy_evaluator::evaluate_policy,
    structs::{Context, Decision, TokenPermissions, UserAttributes},
};
use anyhow::{anyhow, Result};
use diesel_ulid::DieselUlid;
use std::collections::HashMap;

pub struct AttributeCache {
    user_policies: HashMap<DieselUlid, UserAttributes>,
}

impl AttributeCache {
    pub fn new(user_policies: HashMap<DieselUlid, UserAttributes>) -> Self {
        AttributeCache { user_policies }
    }

    pub fn update_attribute(&mut self, user_id: DieselUlid, attr: UserAttributes) {
        self.user_policies.insert(user_id, attr);
    }

    pub fn add_user_token(
        &mut self,
        user_id: DieselUlid,
        token_id: DieselUlid,
        token_perms: TokenPermissions,
    ) -> Result<()> {
        if let Some(p) = self.user_policies.get_mut(&user_id) {
            p.tokens.insert(token_id, token_perms);
            Ok(())
        } else {
            Err(anyhow!("User not found"))
        }
    }

    pub fn remove_user_token(&mut self, user_id: &DieselUlid, token_id: &DieselUlid) -> Result<()> {
        if let Some(p) = self.user_policies.get_mut(user_id) {
            p.tokens.remove(token_id);
            Ok(())
        } else {
            Err(anyhow!("User not found"))
        }
    }

    pub fn check_permissions(&self, context: &Context) -> Decision {
        if let Some(attributes) = self.user_policies.get(&context.subject.user_id) {
            evaluate_policy(attributes, context)
        } else {
            Decision::Deny
        }
    }
}

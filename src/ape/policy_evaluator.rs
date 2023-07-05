use diesel_ulid::DieselUlid;

use super::structs::{
    Constraint, Context, Decision, PermissionLevel, ResourceTarget::Project, ResourceTarget::*,
    TokenPermissions, TokenSubject, UserAttributes,
};

macro_rules! unwrap_or_deny {
    ($e:expr, Option) => {
        match $e {
            Some(x) => x,
            None => return Decision::Deny,
        }
    };
    ($e:expr, Result) => {
        match $e {
            Ok(x) => x,
            Err(_) => return Decision::Deny,
        }
    };
}

pub fn evaluate_policy(attributes: &UserAttributes, context: &Context) -> Decision {
    let TokenSubject { token_id, .. } = context.subject;

    if attributes.service_account && context.is_personal() {
        return Decision::Deny;
    }

    let token_perms = unwrap_or_deny!(attributes.tokens.get(&token_id), Option);

    // Decide based on token permissions
    match token_perms {
        TokenPermissions::Project((project_id, permlevel)) => {
            evaluate_project_scoped_token(context, permlevel, project_id)
        }
        TokenPermissions::Collection((collection_id, permlevel)) => {
            evaluate_collection_scoped_token(context, permlevel, collection_id)
        }
        TokenPermissions::Personal => evaluate_personal_token(context, attributes),
    }
}

pub fn evaluate_personal_token(context: &Context, attributes: &UserAttributes) -> Decision {
    let mut possible_constraints = Vec::new();

    if attributes.global_admin {
        return Decision::Allow(Vec::new());
    }

    match context.target {
        Project(project_id) => return attributes.project_decision(&project_id, &context.operation),
        Object(object_id) => {
            if let Some(d) = attributes.object_decision(&object_id, &context.operation) {
                return d;
            }
        }
        Collection(collection_id) => {
            if let Some(d) = attributes.collection_decision(&collection_id, &context.operation) {
                return d;
            }
        }

        GlobalAdmin => {
            if attributes.global_admin {
                return Decision::Allow(Vec::new());
            } else {
                return Decision::Deny;
            }
        }
        Personal(user_id) => {
            if context.subject.user_id == user_id {
                return Decision::Allow(Vec::new());
            } else {
                return Decision::Deny;
            }
        }
    }
    possible_constraints.extend(attributes.collections_into_constraints(context.operation));
    possible_constraints.extend(attributes.projects_into_constraints(context.operation));

    if possible_constraints.is_empty() {
        Decision::Deny
    } else {
        Decision::Allow(possible_constraints)
    }
}

pub fn evaluate_project_scoped_token(
    context: &Context,
    permlevel: &PermissionLevel,
    project_id: &DieselUlid,
) -> Decision {
    // Check that the operation permlevel is <= the existing permlevel
    if context.operation <= *permlevel {
        // Check the target
        match context.target {
            // If the target is a project
            Project(context_pid) => {
                // Check if ids match
                if context_pid == *project_id {
                    return Decision::Allow(Vec::new());
                // Otherwise deny
                } else {
                    return Decision::Deny;
                }
            }
            // Globaladmin or personal decisions are NOT allowed for scoped tokens
            GlobalAdmin | Personal(_) => return Decision::Deny,
            // If the target is not a project -> Allow under constraint target is in project
            _ => return Decision::Allow(vec![Constraint::InProject(*project_id)]),
        }
    }
    Decision::Deny
}

pub fn evaluate_collection_scoped_token(
    context: &Context,
    permlevel: &PermissionLevel,
    collection_id: &DieselUlid,
) -> Decision {
    // Check that the operation permlevel is <= the existing permlevel
    if context.operation <= *permlevel {
        // Check the target
        match context.target {
            // If the target is a project
            Collection(context_pid) => {
                // Check if ids match
                if context_pid == *collection_id {
                    return Decision::Allow(Vec::new());
                // Otherwise deny
                } else {
                    return Decision::Deny;
                }
            }
            // Deny, global, personal, projects for collection scoped tokens
            GlobalAdmin | Personal(_) | Project(_) => return Decision::Deny,
            super::structs::ResourceTarget::Object(_) => {
                return Decision::Allow(vec![Constraint::InCollection(*collection_id)])
            }
        }
    }
    Decision::Deny
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use diesel_ulid::DieselUlid;

    use crate::ape::{
        policy_evaluator::evaluate_policy,
        structs::{
            Constraint, Context, Decision, DenieablePerms, PermissionLevel, ResourceTarget,
            TokenPermissions, TokenSubject, UserAttributes,
        },
    };

    pub fn create_populated_user_attributes(
        global_admin: bool,
        service_account: bool,
    ) -> UserAttributes {
        let mut project_perms = HashMap::new();
        let mut collection_allow = HashMap::new();
        let mut object_allow = HashMap::new();

        let mut tokens = HashMap::new();
        tokens.insert(DieselUlid::generate(), TokenPermissions::Personal);

        for x in 0..5 {
            let col_id = DieselUlid::generate();
            let proj_id = DieselUlid::generate();
            project_perms.insert(proj_id, PermissionLevel::from(x));
            collection_allow.insert(col_id, PermissionLevel::from(x));
            object_allow.insert(DieselUlid::generate(), PermissionLevel::from(x));
            tokens.insert(
                DieselUlid::generate(),
                TokenPermissions::Collection((col_id, PermissionLevel::from(x))),
            );
            tokens.insert(
                DieselUlid::generate(),
                TokenPermissions::Project((proj_id, PermissionLevel::from(x))),
            );
        }

        UserAttributes {
            global_admin,
            service_account,
            projects: project_perms,
            collections: DenieablePerms {
                allow: collection_allow,
                deny: vec![DieselUlid::generate()],
            },
            objects: DenieablePerms {
                allow: object_allow,
                deny: vec![DieselUlid::generate()],
            },
            tokens,
        }
    }

    #[test]
    fn admin_test() {
        let mut attributes = UserAttributes::default();
        let mut context = Context {
            subject: TokenSubject {
                user_id: diesel_ulid::DieselUlid::generate(),
                token_id: diesel_ulid::DieselUlid::generate(),
            },
            operation: PermissionLevel::ADMIN,
            target: ResourceTarget::GlobalAdmin,
        };
        // Default levels should be denied
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);
        // If global admin is true, this should not work without a "correct token"
        attributes.global_admin = true;
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);

        attributes = create_populated_user_attributes(false, false);

        context.subject.token_id = *attributes.get_personal_tokens().first().unwrap();
        // Default levels should be denied
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);
        attributes = create_populated_user_attributes(true, false);
        context.subject.token_id = *attributes.get_personal_tokens().first().unwrap();
        assert_eq!(
            evaluate_policy(&attributes, &context),
            Decision::Allow(Vec::new())
        );
    }

    #[test]
    fn object_test() {
        let mut attributes = UserAttributes::default();
        let mut context = Context {
            subject: TokenSubject {
                user_id: diesel_ulid::DieselUlid::generate(),
                token_id: diesel_ulid::DieselUlid::generate(),
            },
            operation: PermissionLevel::WRITE,
            target: ResourceTarget::Object(DieselUlid::generate()),
        };
        // Default levels should be denied
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);
        // If global admin is true, this should not work without a "correct token"
        attributes.global_admin = true;
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);

        attributes = create_populated_user_attributes(false, false);

        context.subject.token_id = *attributes.get_personal_tokens().first().unwrap();
        // Default levels should be denied
        match evaluate_policy(&attributes, &context) {
            // Two projects & Collections, One Denied collection
            Decision::Allow(a) => assert_eq!(a.len(), 5),
            _ => panic!(),
        }

        // Global admins should be allowed without exceptions
        attributes = create_populated_user_attributes(true, false);
        context.subject.token_id = *attributes.get_personal_tokens().first().unwrap();
        assert_eq!(
            evaluate_policy(&attributes, &context),
            Decision::Allow(Vec::new())
        );

        // Is on deny list -> Should be denied
        attributes = create_populated_user_attributes(false, false);
        context.target = ResourceTarget::Object(*attributes.objects.deny.first().unwrap());
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);

        // Check explicit allowed permission for personal tokens
        attributes = create_populated_user_attributes(false, false);
        context.subject.token_id = *attributes.get_personal_tokens().first().unwrap();
        for (k, v) in attributes.objects.allow.iter() {
            context.target = ResourceTarget::Object(*k);
            if *v < PermissionLevel::WRITE {
                assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);
            } else {
                assert_eq!(
                    evaluate_policy(&attributes, &context),
                    Decision::Allow(Vec::new()),
                    "{:#?},{:#?}",
                    &attributes,
                    &context
                );
            }
        }

        // Check all explicit tokens for their perms
        attributes = create_populated_user_attributes(false, false);
        context.target = ResourceTarget::Object(DieselUlid::generate());
        for (k, v) in attributes.tokens.iter() {
            context.subject.token_id = *k;

            match v {
                TokenPermissions::Project((id, perm)) => {
                    if *perm < PermissionLevel::WRITE {
                        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny)
                    } else {
                        assert_eq!(
                            evaluate_policy(&attributes, &context),
                            Decision::Allow(vec![Constraint::InProject(*id)])
                        )
                    }
                }
                TokenPermissions::Collection((id, perm)) => {
                    if *perm < PermissionLevel::WRITE {
                        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny)
                    } else {
                        assert_eq!(
                            evaluate_policy(&attributes, &context),
                            Decision::Allow(vec![Constraint::InCollection(*id)])
                        )
                    }
                }
                TokenPermissions::Personal => (),
            }
        }
    }

    #[test]
    fn service_account_test() {
        let attributes = create_populated_user_attributes(false, true);
        let mut context = Context {
            subject: TokenSubject {
                user_id: diesel_ulid::DieselUlid::generate(),
                token_id: diesel_ulid::DieselUlid::generate(),
            },
            operation: PermissionLevel::WRITE,
            target: ResourceTarget::Object(DieselUlid::generate()),
        };
        // Default levels should be denied
        context.subject.token_id = *attributes.get_personal_tokens().first().unwrap();

        match evaluate_policy(&attributes, &context) {
            // Two projects & Collections, One Denied collection
            Decision::Allow(a) => assert_eq!(a.len(), 5),
            _ => panic!(),
        }

        context.target = ResourceTarget::Personal(DieselUlid::generate());
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);

        context.target = ResourceTarget::Personal(context.subject.user_id);
        assert_eq!(evaluate_policy(&attributes, &context), Decision::Deny);
    }
}

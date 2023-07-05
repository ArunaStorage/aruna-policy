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

    // Global admins can do anything
    if attributes.global_admin {
        return Decision::Allow(Vec::new());
    }
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

    match context.target {
        Project(project_id) => return attributes.project_decision(&project_id, &context.operation),
        Object(object_id) => match attributes.object_decision(&object_id, &context.operation) {
            Some(d) => return d,
            _ => (),
        },
        Collection(collection_id) => {
            match attributes.collection_decision(&collection_id, &context.operation) {
                Some(d) => return d,
                _ => (),
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
        return Decision::Deny;
    } else {
        return Decision::Allow(possible_constraints);
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

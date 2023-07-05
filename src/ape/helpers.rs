use diesel_ulid::DieselUlid;

use super::structs::{
    Constraint, Context, Decision, DenieablePerms, PermissionLevel, UserAttributes,
};

impl Context {
    pub fn is_personal(&self) -> bool {
        match self.target {
            super::structs::ResourceTarget::Personal(_) => true,
            _ => false,
        }
    }
}

impl UserAttributes {
    pub fn projects_into_constraints(&self, permlvel: PermissionLevel) -> Vec<Constraint> {
        let mut returnvec = Vec::with_capacity(self.projects.len());
        for (k, v) in self.projects.iter() {
            if *v >= permlvel {
                returnvec.push(Constraint::InProject(*k))
            }
        }
        returnvec
    }

    pub fn collections_into_constraints(&self, req_permlevel: PermissionLevel) -> Vec<Constraint> {
        let mut returnvec =
            Vec::with_capacity(self.collections.allow.len() + self.collections.deny.len());
        for (k, v) in self.collections.allow.iter() {
            if *v >= req_permlevel {
                returnvec.push(Constraint::InCollection(*k))
            }
        }
        for k in self.collections.deny.iter() {
            returnvec.push(Constraint::NotInCollection(*k))
        }
        returnvec
    }

    pub fn object_decision(
        &self,
        object_id: &DieselUlid,
        req_permlevel: &PermissionLevel,
    ) -> Option<Decision> {
        let DenieablePerms { allow, deny } = &self.objects;
        if deny.contains(&object_id) {
            return Some(Decision::Deny);
        }

        if let Some(found) = allow.get(object_id) {
            if *found >= *req_permlevel {
                return Some(Decision::Allow(Vec::new()));
            } else {
                return Some(Decision::Deny);
            }
        }

        None
    }

    pub fn collection_decision(
        &self,
        collection_id: &DieselUlid,
        req_permlevel: &PermissionLevel,
    ) -> Option<Decision> {
        let DenieablePerms { allow, deny } = &self.collections;
        if deny.contains(&collection_id) {
            return Some(Decision::Deny);
        }

        if let Some(found) = allow.get(collection_id) {
            if *found >= *req_permlevel {
                return Some(Decision::Allow(Vec::new()));
            } else {
                return Some(Decision::Deny);
            }
        }
        None
    }

    pub fn project_decision(
        &self,
        project_id: &DieselUlid,
        req_permlevel: &PermissionLevel,
    ) -> Decision {
        if let Some(found) = self.projects.get(project_id) {
            if *found >= *req_permlevel {
                return Decision::Allow(Vec::new());
            }
        }
        Decision::Deny
    }
}

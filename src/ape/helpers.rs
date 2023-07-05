use super::structs::Context;

impl Context {
    pub fn is_personal(&self) -> bool {
        match self.target {
            super::structs::ResourceTarget::Personal => true,
            _ => false,
        }
    }
}

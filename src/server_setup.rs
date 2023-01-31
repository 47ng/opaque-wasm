use crate::hash_methods::Default;
use rand::rngs::OsRng;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug)]
pub struct ServerSetup {
    internal: opaque_ke::ServerSetup<Default>,
}

#[wasm_bindgen]
impl ServerSetup {
    #[wasm_bindgen(constructor)]
    pub fn new() -> ServerSetup {
        let mut rng = OsRng;
        let internal = opaque_ke::ServerSetup::new(&mut rng);

        ServerSetup { internal }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.internal.serialize().to_vec()
    }

    pub fn deserialize(input: Vec<u8>) -> Result<ServerSetup, JsValue> {
        let internal = match opaque_ke::ServerSetup::deserialize(&input) {
            Ok(val) => val,
            Err(_) => return Err("Failed to load serialized ServerSetup".into()),
        };
        Ok(ServerSetup { internal })
    }

    pub(crate) fn internal<'a>(&'a self) -> &'a opaque_ke::ServerSetup<Default> {
        &self.internal
    }
}

// --

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_setup_serde() {
        let setup1 = ServerSetup::new();
        let serialized = setup1.serialize();
        assert_eq!(serialized.len(), 128);
        let setup2 = ServerSetup::deserialize(serialized).unwrap();
        assert_eq!(setup1, setup2);
    }
}

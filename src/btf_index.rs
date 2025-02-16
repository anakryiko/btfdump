use std::collections::HashMap;

use crate::types::*;

#[derive(Debug)]
pub struct BtfIndex<'a> {
    name_index: HashMap<&'a str, Vec<u32>>,
}

const EMPTY_ID_SLICE: &[u32] = &[];

impl<'a> BtfIndex<'a> {
    pub fn new(btf: &'a Btf<'a>) -> BtfIndex<'a> {
        let mut index = BtfIndex {
            name_index: HashMap::new(),
        };
        for (i, t) in btf.types().iter().enumerate() {
            let e = index.name_index.entry(t.name()).or_default();
            e.push(i as u32);
        }
        index
    }

    pub fn get_by_name(&self, name: &str) -> &[u32] {
        self.name_index
            .get(name)
            .map(|x| &x[..])
            .unwrap_or_else(|| EMPTY_ID_SLICE)
    }
}

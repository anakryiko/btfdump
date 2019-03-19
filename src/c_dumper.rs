use crate::btf::BtfType;
use crate::BtfResult;

pub struct CDumper {}

impl CDumper {
    pub fn new() -> CDumper {
        CDumper {}
    }

    pub fn dump(&mut self, t: &BtfType) -> BtfResult<()> {
        Ok(())
    }
}

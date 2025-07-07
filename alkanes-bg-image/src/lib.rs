use anyhow::{anyhow, Result};
use metashrew_support::compat::to_arraybuffer_layout;

use alkanes_runtime::{
    declare_alkane, message::MessageDispatch,
    runtime::AlkaneResponder,
};

use alkanes_support::{
    response::CallResponse
};

use include_dir::{include_dir, Dir};
static TRAITS_DIR: Dir = include_dir!("src/traits");

#[derive(Default)]
pub struct OrbitalInstance(());

impl AlkaneResponder for OrbitalInstance {}

#[derive(MessageDispatch)]
enum OrbitalInstanceMessage {
    #[opcode(0)]
    Initialize,

    #[opcode(1001)]
    #[returns(Vec<u8>)]
    GetBg {
        name_part1: u128,
        name_part2: u128,
    },
}

pub fn trim(v: u128) -> String {
    String::from_utf8(
        v.to_le_bytes()
            .into_iter()
            .fold(Vec::<u8>::new(), |mut r, v| {
                if v != 0 {
                    r.push(v)
                }
                r
            }),
    ).unwrap()
}

impl OrbitalInstance {
    /// Initialize the NFT instance with a given index
    /// Opcode: 0
    fn initialize(&self) -> Result<CallResponse> {
        let context = self.context()?;
        let response = CallResponse::forward(&context.incoming_alkanes);

        self.observe_initialization()?;

        Ok(response)
    }

    fn get_bg(&self, name_part1: u128, name_part2: u128) -> Result<CallResponse> {
        let context = self.context()?;
        let mut response = CallResponse::forward(&context.incoming_alkanes);
        let name = format!("{}{}", trim(name_part1), trim(name_part2));
        let image_path = format!("{}/{}.png", "Background", name);
        if let Some(file) = TRAITS_DIR.get_file(&image_path) {
            let trait_img = image::load_from_memory(file.contents())?;
            let trait_rgba = trait_img.to_rgba8();
            response.data = trait_rgba.into_vec();
        } else {
            return Err(anyhow!("Trait image not found: {}", image_path));
        }
        Ok(response)
    }
}

declare_alkane! {
  impl AlkaneResponder for OrbitalInstance {
    type Message = OrbitalInstanceMessage;
  }
}

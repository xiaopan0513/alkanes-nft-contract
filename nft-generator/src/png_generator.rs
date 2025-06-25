use anyhow::{anyhow, Result};
use hex;
use image::{imageops, DynamicImage, ImageBuffer, Rgba, RgbaImage};
use include_dir::{include_dir, Dir};
use serde_json::Value;
static TRAITS_DIR: Dir = include_dir!("src/traits");

const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");

pub struct PngGenerator;

impl PngGenerator {
    pub fn get_encoded_traits() -> Value {
        serde_json::from_str(ENCODED_TRAITS_JSON).unwrap()
    }

    /// Decode traits for a specific NFT index
    pub fn decode_traits(index: u128) -> Result<(String, String, String, String, String, String)> {
        let encoded_traits = Self::get_encoded_traits();
        let format = &encoded_traits["format"];
        let indices = &encoded_traits["indices"];
        let items = encoded_traits["items"]
            .as_array()
            .ok_or_else(|| anyhow!("Invalid items array"))?;
        let encoded = items
            .get(index as usize)
            .ok_or_else(|| anyhow!("Invalid trait index: {}", index))?
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid trait format"))?;

        let get_code = |key: &str| -> Option<usize> {
            let shift = format.get(key)?.get("shift")?.as_u64()?;
            let mask_str = format
                .get(key)?
                .get("mask")?
                .as_str()?
                .trim_start_matches("0x");
            let mask = u64::from_str_radix(mask_str, 16).ok()?;
            Some(((encoded >> shift) & mask) as usize)
        };
        let get_index_str = |cat: &str, code: Option<usize>| -> String {
            if let (Some(arr), Some(idx)) = (indices.get(cat).and_then(|v| v.as_array()), code) {
                arr.get(idx)
                    .and_then(|v| v.as_str())
                    .unwrap_or("None")
                    .to_string()
            } else {
                "None".to_string()
            }
        };

        let background = get_index_str("Background", get_code("Background"));
        let back = get_index_str("Back", get_code("Back"));
        let body = get_index_str("Body", get_code("Body"));
        let head = get_index_str("Head", get_code("Head"));
        let hat = get_index_str("Hat", get_code("Hat"));
        let hand = get_index_str("Hand", get_code("Hand"));

        Ok((background, back, body, head, hat, hand))
    }

    // 删除旧的generate_png实现，保留如下新实现：
    pub fn generate_png(index: u128) -> Result<Vec<u8>> {
        let (background, back, body, head, hat, hand) = Self::decode_traits(index)?;

        let mut base_image: RgbaImage = ImageBuffer::new(420, 420);

        for pixel in base_image.pixels_mut() {
            *pixel = Rgba([0, 0, 0, 0]); // transparent
        }

        // 加载背景图片
        if background != "None" {
            let bg_image_path = format!("Background/{}.png", background);
            if let Some(file) = TRAITS_DIR.get_file(&bg_image_path) {
                let bg_img = image::load_from_memory(file.contents())?;
                let bg_rgba = bg_img.to_rgba8();
                imageops::overlay(&mut base_image, &bg_rgba, 0, 0);
            }
        }

        let traits = [
            ("Back", &back),
            ("Body", &body),
            ("Head", &head),
            ("Hat", &hat),
            ("Hand", &hand),
        ];

        for (layer, trait_value) in traits.iter() {
            if trait_value != &"None" {
                let image_path = format!("{}/{}.png", layer, trait_value);
                if let Some(file) = TRAITS_DIR.get_file(&image_path) {
                    let trait_img = image::load_from_memory(file.contents())?;
                    let trait_rgba = trait_img.to_rgba8();
                    imageops::overlay(&mut base_image, &trait_rgba, 0, 0);
                } else {
                    return Err(anyhow!("Trait image not found: {}", image_path));
                }
            }
        }

        let dynamic_img = DynamicImage::ImageRgba8(base_image);
        let mut buf = Vec::new();
        dynamic_img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)?;
        Ok(buf)
    }

    /// Get attributes for a specific NFT index
    ///
    /// # Arguments
    /// * `index` - The index of the NFT
    ///
    /// # Returns
    /// * `Result<String>` - JSON string containing NFT attributes
    pub fn get_attributes(index: u128) -> Result<String> {
        let (background, back, body, head, hat, hand) = Self::decode_traits(index)?;
        let attributes = serde_json::json!([
            {
                "trait_type": "Background",
                "value": background
            },
            {
                "trait_type": "Back",
                "value": back
            },
            {
                "trait_type": "Body",
                "value": body
            },
            {
                "trait_type": "Head",
                "value": head
            },
            {
                "trait_type": "Hat",
                "value": hat
            },
            {
                "trait_type": "Hand",
                "value": hand
            }
        ]);
        Ok(attributes.to_string())
    }
}

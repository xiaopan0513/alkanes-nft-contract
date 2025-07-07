use anyhow::{anyhow, Result};
use hex;
use image::{imageops, DynamicImage, ImageBuffer, Rgba, RgbaImage};
use include_dir::{include_dir, Dir};
use serde_json::Value;
static TRAITS_DIR: Dir = include_dir!("src/generation/traits");

const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");

pub struct PngGenerator;

impl PngGenerator {
    pub fn get_encoded_traits() -> Value {
        serde_json::from_str(ENCODED_TRAITS_JSON).unwrap()
    }

    /// Decode traits for a specific NFT index
    pub fn decode_traits(index: u128) -> Result<(String, String, String, String, String, String, String, String, String)> {
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

        let one_of_one = get_index_str("1of1", get_code("1of1"));
        let background = get_index_str("Background", get_code("Background"));
        let body = get_index_str("Body", get_code("Body"));
        let eyes = get_index_str("Eyes", get_code("Eyes"));
        let hair = get_index_str("Hair", get_code("Hair"));
        let wear = get_index_str("Wear", get_code("Wear"));
        let accessories = get_index_str("Accessories", get_code("Accessories"));
        let head = get_index_str("Head", get_code("Head"));
        let lips = get_index_str("Lips", get_code("Lips"));

        Ok((one_of_one, background, body, eyes, hair, wear, accessories, head, lips))
    }
    
    
    pub fn generate_png(index: u128, bg_data: Vec<u8>, one_of_one_data: Vec<u8>) -> Result<Vec<u8>> {
        let (one_of_one, background, body
            , eyes, hair, wear
            , accessories, head, lips) = Self::decode_traits(index)?;

        let mut base_image: RgbaImage = ImageBuffer::new(512, 512);

        for pixel in base_image.pixels_mut() {
            *pixel = Rgba([0, 0, 0, 0]); // 透明
        }

        if one_of_one != "None" {
            let one_of_one_bytes = if one_of_one_data.starts_with(b"0x") || one_of_one_data.starts_with(b"b") {
                let hex_str = String::from_utf8_lossy(&one_of_one_data);
                Self::hex_to_bytes(&hex_str)?
            } else {
                one_of_one_data
            };

            if one_of_one_bytes.is_empty() {
                return Err(anyhow!("1of1 data is empty"));
            }

            let one_of_one_image = match ImageBuffer::from_raw(512, 512, one_of_one_bytes) {
                Some(img) => img,
                None => return Err(anyhow!("Failed to create image from raw data")),
            };

            imageops::overlay(&mut base_image, &one_of_one_image, 0, 0);

            let dynamic_img = DynamicImage::ImageRgba8(base_image);
            let mut buf = Vec::new();
            dynamic_img.write_to(&mut std::io::Cursor::new(&mut buf), image::ImageFormat::Png)?;
            return Ok(buf)
        }

        let bg_bytes = if bg_data.starts_with(b"0x") || bg_data.starts_with(b"b") {
            let hex_str = String::from_utf8_lossy(&bg_data);
            Self::hex_to_bytes(&hex_str)?
        } else {
            bg_data
        };

        if bg_bytes.is_empty() {
            return Err(anyhow!("Background data is empty"));
        }

        let bg_image = match ImageBuffer::from_raw(512, 512, bg_bytes) {
            Some(img) => img,
            None => return Err(anyhow!("Failed to create image from raw data")),
        };

        imageops::overlay(&mut base_image, &bg_image, 0, 0);

        let traits = [
            ("Background", &background),
            ("Body", &body),
            ("Eyes", &eyes),
            ("Hair", &hair),
            ("Wear", &wear),
            ("Accessories", &accessories),
            ("Head", &head),
            ("Lips", &lips)
        ];

        for (layer, trait_value) in traits.iter() {
            if trait_value != &"none" {
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

    /// 将十六进制字符串转换为字节数组
    fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>> {
        // 移除可能的前缀
        let hex_str = hex_str.trim_start_matches("0x");
        // 移除可能的前导b
        let hex_str = hex_str.trim_start_matches('b');

        match hex::decode(hex_str) {
            Ok(bytes) => Ok(bytes),
            Err(e) => Err(anyhow!("Failed to decode hex string: {}", e)),
        }
    }

    /// Get attributes for a specific NFT index
    ///
    /// # Arguments
    /// * `index` - The index of the NFT
    ///
    /// # Returns
    /// * `Result<String>` - JSON string containing NFT attributes
    pub fn get_attributes(index: u128) -> Result<String> {
        let (one_of_one, background, body
            , eyes, hair, wear
            , accessories, head, lips) = Self::decode_traits(index)?;
        let attributes = serde_json::json!([
           {
            "trait_type": "1of1",
            "value": one_of_one,
          },
          {
            "trait_type": "accessories",
            "value": accessories,
          },
          {
            "trait_type": "background",
            "value": background,
          },
          {
            "trait_type": "body",
            "value": body,
          },
          {
            "trait_type": "eyes",
            "value": eyes,
          },
          {
            "trait_type": "hair",
            "value": hair,
          },
          {
            "trait_type": "head",
            "value": head,
          },
          {
            "trait_type": "lips",
            "value": lips,
          },
          {
            "trait_type": "wear",
            "value": wear,
          }
        ]);
        Ok(attributes.to_string())
    }
}

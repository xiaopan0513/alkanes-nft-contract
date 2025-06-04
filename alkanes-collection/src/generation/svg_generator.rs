use anyhow::{anyhow, Result};
use image::{imageops, ImageBuffer, RgbaImage, Rgba, DynamicImage};
use include_dir::{include_dir, Dir};
use serde_json::Value;
use hex;
static TRAITS_DIR: Dir = include_dir!("src/generation/traits");

const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");

/// SVG Generator for NFT images
/// This struct handles the generation of SVG images for NFTs based on encoded traits
pub struct SvgGenerator;

impl SvgGenerator {
    /// Get the encoded traits from JSON file
    ///
    /// # Returns
    /// * `Value` - JSON value containing encoded traits
    pub fn get_encoded_traits() -> Value {
        serde_json::from_str(ENCODED_TRAITS_JSON).unwrap()
    }

    /// Decode traits for a specific NFT index
    pub fn decode_traits(index: u128) -> Result<(String, String, String, String, String, String)> {
        let encoded_traits = Self::get_encoded_traits();
        let format = &encoded_traits["format"];
        let indices = &encoded_traits["indices"];
        let items = encoded_traits["items"].as_array().ok_or_else(|| anyhow!("Invalid items array"))?;
        let encoded = items.get(index as usize)
            .ok_or_else(|| anyhow!("Invalid trait index"))?
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid trait format"))?;

        // 解码顺序: backgrounds, misc, visors, suits
        let mut pre_bits = 0u64;
        let mut get_code = |key: &str| -> anyhow::Result<usize> {
            let bits = format[key]["bits"].as_u64().unwrap();
            let code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
            pre_bits += bits;
            Ok(code)
        };
        let background_code = get_code("Background")?;
        let facility_code = get_code("Facility")?;
        let body_code = get_code("Body")?;
        let clothes_code = get_code("Clothes")?;
        let eyes_code = get_code("Eyes")?;
        let head_code = get_code("Head")?;

        let background = indices["Background"][background_code].as_str().unwrap().to_string();
        let facility = indices["Facility"][facility_code].as_str().unwrap().to_string();
        let body = indices["Body"][body_code].as_str().unwrap().to_string();
        let clothes = indices["Clothes"][clothes_code].as_str().unwrap().to_string();
        let eyes = indices["Eyes"][eyes_code].as_str().unwrap().to_string();
        let head = indices["Head"][head_code].as_str().unwrap().to_string();

        Ok((background, facility, body, clothes, eyes, head))
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

    /// Generate PNG image for a specific NFT index by composing trait images
    ///
    /// # Arguments
    /// * `index` - The index of the NFT
    ///
    /// # Returns
    /// * `Result<Vec<u8>>` - PNG image data as byte array
    pub fn generate_png(index: u128, bg: Vec<u8>) -> Result<Vec<u8>> {
        let (_background, facility, body, clothes, eyes, head) = Self::decode_traits(index)?;

        let mut base_image: RgbaImage = ImageBuffer::new(512, 512);

        for pixel in base_image.pixels_mut() {
            *pixel = Rgba([0, 0, 0, 0]); // 透明
        }

        let bg_bytes = if bg.starts_with(b"0x") || bg.starts_with(b"b") {
            let hex_str = String::from_utf8_lossy(&bg);
            Self::hex_to_bytes(&hex_str)?
        } else {
            bg
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
            ("Facility", &facility),
            ("Body", &body),
            ("Clothes", &clothes),
            ("Eyes", &eyes),
            ("Head", &head),
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

    /// Get attributes for a specific NFT index
    ///
    /// # Arguments
    /// * `index` - The index of the NFT
    ///
    /// # Returns
    /// * `Result<String>` - JSON string containing NFT attributes
    pub fn get_attributes(index: u128) -> Result<String> {
        let (background, facility, body, clothes, eyes, head) = Self::decode_traits(index)?;
        let attributes = serde_json::json!([
            {
                "trait_type": "Background",
                "value": background
            },
            {
                "trait_type": "Facility",
                "value": facility
            },
            {
                "trait_type": "Body",
                "value": body
            },
            {
                "trait_type": "Clothes",
                "value": clothes
            },
            {
                "trait_type": "Eyes",
                "value": eyes
            },
            {
                "trait_type": "Head",
                "value": head
            }
        ]);
        Ok(attributes.to_string())
    }
} 
use serde_json::{Value};
use anyhow::{anyhow, Result};

const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");
const SVG_TEMPLATES_JSON: &str = include_str!("svg_templates.json");

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

    /// Get the SVG templates from JSON file
    /// 
    /// # Returns
    /// * `Value` - JSON value containing SVG templates
    fn get_svg_templates() -> Value {
        serde_json::from_str(SVG_TEMPLATES_JSON).unwrap()
    }

    /// Decode traits for a specific NFT index
    /// 返回 (background, misc, visors, suits)
    pub fn decode_traits(index: u128) -> Result<(String, String, String, String)> {
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
        let bg_code = get_code("backgrounds")?;
        let misc_code = get_code("misc")?;
        let visors_code = get_code("visors")?;
        let suits_code = get_code("suits")?;

        let bg = indices["backgrounds"][bg_code].as_str().unwrap().to_string();
        let misc = indices["misc"][misc_code].as_str().unwrap().to_string();
        let visors = indices["visors"][visors_code].as_str().unwrap().to_string();
        let suits = indices["suits"][suits_code].as_str().unwrap().to_string();

        Ok((bg, misc, visors, suits))
    }

    /// Generate SVG image for a specific NFT index
    /// 
    /// # Arguments
    /// * `index` - The index of the NFT
    /// 
    /// # Returns
    /// * `Result<String>` - SVG image data as string
    pub fn generate_svg(index: u128) -> Result<String> {
        let (background, misc, visors, suits) = Self::decode_traits(index)?;
        let svg_templates = Self::get_svg_templates();

        let mut svg = String::from("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" viewBox=\"0 0 200 200\">\n");

        // Add background
        if background != "none" {
            let bg_template = svg_templates.get(&background)
                .ok_or_else(|| anyhow!("Background template not found: {}", background))?;
            svg.push_str(bg_template.as_str().unwrap());
            svg.push('\n');
        }
        // Add misc
        if misc != "none" {
            let misc_template = svg_templates.get(&misc)
                .ok_or_else(|| anyhow!("Misc template not found: {}", misc))?;
            svg.push_str(misc_template.as_str().unwrap());
            svg.push('\n');
        }
        // Add visors
        if visors != "none" {
            let visors_template = svg_templates.get(&visors)
                .ok_or_else(|| anyhow!("Visors template not found: {}", visors))?;
            svg.push_str(visors_template.as_str().unwrap());
            svg.push('\n');
        }
        // Add suits
        if suits != "none" {
            let suits_template = svg_templates.get(&suits)
                .ok_or_else(|| anyhow!("Suits template not found: {}", suits))?;
            svg.push_str(suits_template.as_str().unwrap());
            svg.push('\n');
        }

        svg.push_str("</svg>");
        Ok(svg)
    }

    /// Get attributes for a specific NFT index
    /// 
    /// # Arguments
    /// * `index` - The index of the NFT
    /// 
    /// # Returns
    /// * `Result<String>` - JSON string containing NFT attributes
    pub fn get_attributes(index: u128) -> Result<String> {
        let (background, misc, visors, suits) = Self::decode_traits(index)?;
        let attributes = serde_json::json!([
            {
                "trait_type": "Background",
                "value": background
            },
            {
                "trait_type": "Misc",
                "value": misc
            },
            {
                "trait_type": "Visors",
                "value": visors
            },
            {
                "trait_type": "Suits",
                "value": suits
            }
        ]);
        Ok(attributes.to_string())
    }
} 
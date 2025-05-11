use serde_json::{Value};
use anyhow::{anyhow, Result};

const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");
const SVG_TEMPLATES_JSON: &str = include_str!("svg_template.json");

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
    /// 
    /// # Arguments
    /// * `index` - The index of the NFT
    /// 
    /// # Returns
    /// * `Result<(String, String, String, String, String, String, u64)>` - Tuple containing:
    ///   - background trait
    ///   - base trait
    ///   - body trait
    ///   - eyes trait
    ///   - head trait
    ///   - mouth trait
    ///   - rank
    pub fn decode_traits(index: u128) -> Result<(String, String, String, String, String, String, u64)> {
        let encoded_traits = Self::get_encoded_traits();
        let traits_array = encoded_traits["traits"].as_array()
            .ok_or_else(|| anyhow!("Invalid traits array"))?;
        let encoded = traits_array.get(index as usize)
            .ok_or_else(|| anyhow!("Invalid trait index"))?
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid trait format"))?;

        let components = &encoded_traits["components"];
        let mut pre_bits = 0u64;
        let mut bits = components["background"]["bits"].as_u64().unwrap();
        let background_code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
        pre_bits += bits;

        bits = components["base"]["bits"].as_u64().unwrap();
        let base_code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
        pre_bits += bits;

        bits = components["body"]["bits"].as_u64().unwrap();
        let body_code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
        pre_bits += bits;

        bits = components["eyes"]["bits"].as_u64().unwrap();
        let eyes_code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
        pre_bits += bits;

        bits = components["head"]["bits"].as_u64().unwrap();
        let head_code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
        pre_bits += bits;

        bits = components["mouth"]["bits"].as_u64().unwrap();
        let mouth_code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
        pre_bits += bits;

        let background = components["background"]["values"][background_code].as_str().unwrap().to_string();
        let base = components["base"]["values"][base_code].as_str().unwrap().to_string();
        let body = components["body"]["values"][body_code].as_str().unwrap().to_string();
        let eyes = components["eyes"]["values"][eyes_code].as_str().unwrap().to_string();
        let head = components["head"]["values"][head_code].as_str().unwrap().to_string();
        let mouth = components["mouth"]["values"][mouth_code].as_str().unwrap().to_string();
        let rank = encoded >> pre_bits;
        Ok((background, base, body, eyes, head, mouth, rank))
    }

    /// Generate SVG image for a specific NFT index
    /// 
    /// # Arguments
    /// * `index` - The index of the NFT
    /// 
    /// # Returns
    /// * `Result<String>` - SVG image data as string
    pub fn generate_svg(index: u128) -> Result<String> {
        let (background, base, body, eyes, head, mouth, _) = Self::decode_traits(index)?;
        let svg_templates = Self::get_svg_templates();

        let mut svg = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\" shape-rendering=\"crispEdges\" viewBox=\"0 0 32 32\">\n");

        // Add background
        let bg_template = svg_templates["bg"].get(&background)
            .ok_or_else(|| anyhow!("Background template not found: {}", background))?;
        svg.push_str(&format!("\t{}\n", bg_template.as_str().unwrap()));

        // Add base
        let base_template = svg_templates["base"].get(&base)
            .ok_or_else(|| anyhow!("Base template not found: {}", base))?;
        svg.push_str(&format!("\t{}\n", base_template.as_str().unwrap()));

        // Add body if not none
        if body != "none" {
            let body_template = svg_templates["body"].get(&body)
                .ok_or_else(|| anyhow!("Body template not found: {}", body))?;
            svg.push_str(&format!("\t{}\n", body_template.as_str().unwrap()));
        }

        // Add head if not none
        if head != "none" {
            // Handle hornsPNG naming compatibility
            let head_key = if head == "horns" { "horns" } else { &head };
            let head_template = svg_templates["head"].get(head_key)
                .ok_or_else(|| anyhow!("Head template not found: {}", head_key))?;
            svg.push_str(&format!("\t{}\n", head_template.as_str().unwrap()));
        }

        // Add eyes
        let eyes_template = svg_templates["eyes"].get(&eyes)
            .ok_or_else(|| anyhow!("Eyes template not found: {}", eyes))?;
        svg.push_str(&format!("\t{}\n", eyes_template.as_str().unwrap()));

        // Add mouth
        let mouth_template = svg_templates["mouth"].get(&mouth)
            .ok_or_else(|| anyhow!("Mouth template not found: {}", mouth))?;
        svg.push_str(&format!("\t{}\n", mouth_template.as_str().unwrap()));

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
        let (background, base, body, eyes, head, mouth, rank) = Self::decode_traits(index)?;
        
        let attributes = serde_json::json!([
                {
                    "trait_type": "Background",
                    "value": background
                },
                {
                    "trait_type": "Base",
                    "value": base
                },
                {
                    "trait_type": "Body",
                    "value": body
                },
                {
                    "trait_type": "Eyes",
                    "value": eyes
                },
                {
                    "trait_type": "Head",
                    "value": head
                },
                {
                    "trait_type": "Mouth",
                    "value": mouth
                },
                {
                    "trait_type": "Rank",
                    "value": rank
                }
            ]);

        Ok(attributes.to_string())
    }
} 
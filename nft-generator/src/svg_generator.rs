use serde_json::Value;
use anyhow::{anyhow, Result};

// JSON files containing encoded traits and SVG templates
const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");
const SVG_TEMPLATES_JSON: &str = include_str!("svg_template.json");

/// SvgGenerator handles the generation of SVG images based on encoded traits
pub struct SvgGenerator;

impl SvgGenerator {
    /// Returns the encoded traits from the JSON file
    pub fn get_encoded_traits() -> Value {
        serde_json::from_str(ENCODED_TRAITS_JSON).unwrap()
    }

    /// Returns the SVG templates from the JSON file
    fn get_svg_templates() -> Value {
        serde_json::from_str(SVG_TEMPLATES_JSON).unwrap()
    }

    /// Decodes the traits from a given index
    /// Returns a tuple containing (background, base, body, eyes, head, mouth, rank)
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

        // Get component values
        let background = components["background"]["values"][background_code].as_str().unwrap().to_string();
        let base = components["base"]["values"][base_code].as_str().unwrap().to_string();
        let body = components["body"]["values"][body_code].as_str().unwrap().to_string();
        let eyes = components["eyes"]["values"][eyes_code].as_str().unwrap().to_string();
        let head = components["head"]["values"][head_code].as_str().unwrap().to_string();
        let mouth = components["mouth"]["values"][mouth_code].as_str().unwrap().to_string();
        let rank = encoded >> pre_bits;
        Ok((background, base, body, eyes, head, mouth, rank))
    }

    /// Generates an SVG image based on the given index
    /// Returns a Result containing the SVG string if successful
    pub fn generate_svg(index: u128) -> Result<String> {
        let (background, base, body, eyes, head, mouth, _rank) = Self::decode_traits(index)?;
        println!("Decoded traits: background={}, base={}, body={}, eyes={}, head={}, mouth={}",
            background, base, body, eyes, head, mouth);

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
} 
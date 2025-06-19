use serde_json::{Value};
use anyhow::{anyhow, Result};

const ENCODED_TRAITS_JSON: &str = include_str!("encoded_traits.json");
const SVG_TEMPLATES_JSON: &str = include_str!("svg_templates.json");

/// SVG Generator for NFT images
/// This struct handles the generation of SVG images for NFTs based on encoded traits
pub struct SvgGenerator;

impl SvgGenerator {
    pub fn get_encoded_traits() -> Value {
        serde_json::from_str(ENCODED_TRAITS_JSON).unwrap()
    }

    fn get_svg_templates() -> Value {
        serde_json::from_str(SVG_TEMPLATES_JSON).unwrap()
    }

    pub fn decode_traits(index: u128) -> Result<(String, String, String, String, String, String, String)> {
        let encoded_traits = Self::get_encoded_traits();
        let format = &encoded_traits["format"];
        let indices = &encoded_traits["indices"];
        let items = encoded_traits["items"].as_array().ok_or_else(|| anyhow!("Invalid items array"))?;
        let encoded = items.get(index as usize)
            .ok_or_else(|| anyhow!("Invalid trait index"))?
            .as_u64()
            .ok_or_else(|| anyhow!("Invalid trait format"))?;

        let mut pre_bits = 0u64;
        let mut get_code = |key: &str| -> anyhow::Result<usize> {
            let bits = format[key]["bits"].as_u64().unwrap();
            let code = ((encoded >> pre_bits) & ((1u64 << bits) - 1)) as usize;
            pre_bits += bits;
            Ok(code)
        };

        let bg_code = get_code("bg")?;
        let body_code = get_code("body")?;
        let cloth_code = get_code("cloth")?;
        let mouth_code = get_code("mouth")?;
        let eyes_code = get_code("eyes")?;
        let acc_code = get_code("head_acc")?;
        let eniv_code = get_code("eniv")?;

        let bg = indices["bg"][bg_code].as_str().unwrap().to_string();
        let body = indices["body"][body_code].as_str().unwrap().to_string();
        let cloth = indices["cloth"][cloth_code].as_str().unwrap().to_string();
        let mouth = indices["mouth"][mouth_code].as_str().unwrap().to_string();
        let eyes = indices["eyes"][eyes_code].as_str().unwrap().to_string();
        let acc = indices["head_acc"][acc_code].as_str().unwrap().to_string();
        let eniv = indices["eniv"][eniv_code].as_str().unwrap().to_string();

        Ok((bg, body, cloth, mouth, eyes, acc, eniv))
    }

    pub fn generate_svg(index: u128) -> Result<String> {
        let (bg, body, cloth, mouth, eyes, acc, eniv) = Self::decode_traits(index)?;
        let svg_templates = Self::get_svg_templates();

        let mut svg = String::from("<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" viewBox=\"0 0 500 500\">\n");

        for layer in [&bg, &body, &cloth, &mouth, &eyes, &acc, &eniv] {
            if layer != "none" {
                let template = svg_templates.get(layer)
                    .ok_or_else(|| anyhow!("Template not found: {}", layer))?;
                svg.push_str(template.as_str().unwrap());
                svg.push('\n');
            }
        }

        svg.push_str("</svg>");
        Ok(svg)
    }

    pub fn get_attributes(index: u128) -> Result<String> {
        let (bg, body, cloth, mouth, eyes, acc, eniv) = Self::decode_traits(index)?;
        let attributes = serde_json::json!([
            { "trait_type": "BG", "value": bg },
            { "trait_type": "Body", "value": body },
            { "trait_type": "Cloth", "value": cloth },
            { "trait_type": "Mouth", "value": mouth },
            { "trait_type": "Eyes", "value": eyes },
            { "trait_type": "head_acc", "value": acc },
            { "trait_type": "Eniv", "value": eniv }
        ]);
        Ok(attributes.to_string())
    }
}

mod png_generator;
use anyhow::Result;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use crate::png_generator::PngGenerator;

fn generate_pngs() -> Result<()> {
    println!("Starting png generation...");
    
    // Create output directory
    let output_dir = Path::new("output");
    if !output_dir.exists() {
        std::fs::create_dir(output_dir)?;
    }

    let total_items = 2222;
    for i in 0..total_items {
        let svg = PngGenerator::generate_png(i)?;
        let filename = format!("output/{:04}.png", i);
        std::fs::write(&filename, svg)?;
        
        if i % 100 == 0 {
            println!("Generated {}/{} images", i, total_items);
        }
    }
    
    println!("png generation completed!");
    Ok(())
}

fn generate_encoded_traits() -> Result<()> {
    println!("Starting encoded_traits.json generation...");
    
    // Read metadata.json
    let metadata_content = fs::read_to_string("src/metadata.json")?;
    let metadata: Vec<Value> = serde_json::from_str(&metadata_content)?;

    // First pass: collect all unique trait values for each trait type
    let mut trait_categories: HashMap<String, HashSet<String>> = HashMap::new();

    for item in &metadata {
        let attributes = item["attributes"].as_array().unwrap();
        for attr in attributes {
            let trait_type = attr["trait_type"].as_str().unwrap();
            let value = attr["value"].as_str().unwrap();

            trait_categories
                .entry(trait_type.to_string())
                .or_insert_with(HashSet::new)
                .insert(value.to_string());
        }
    }

    // Convert to sorted vectors and calculate bit requirements
    let mut trait_info: Vec<(String, Vec<String>, u64)> = Vec::new();
    let mut total_bits = 0;

    for (trait_type, values) in &trait_categories {
        let mut values_vec: Vec<String> = values.iter().cloned().collect();
        values_vec.sort(); // Ensure consistent ordering
        
        let bits_needed = if values_vec.len() <= 1 {
            1
        } else {
            (values_vec.len() as f64).log2().ceil() as u64
        };
        
        trait_info.push((trait_type.clone(), values_vec, bits_needed));
        total_bits += bits_needed;
    }

    // Sort by trait type for consistent ordering
    trait_info.sort_by(|a, b| a.0.cmp(&b.0));

    // Second pass: encode items
    let mut encoded_items: Vec<u64> = Vec::new();

    for item in &metadata {
        let attributes = item["attributes"].as_array().unwrap();
        let mut encoded_value: u64 = 0;
        let mut current_shift: u64 = 0;

        for (trait_type, values_vec, bits_needed) in &trait_info {
            // Find the attribute value for this trait type
            let attr_value = attributes
                .iter()
                .find(|attr| attr["trait_type"].as_str().unwrap() == *trait_type)
                .and_then(|attr| attr["value"].as_str())
                .unwrap_or("none");

            // Find the index of this value in the sorted vector
            if let Some(value_index) = values_vec.iter().position(|v| v == attr_value) {
                if current_shift + bits_needed <= 64 {
                    encoded_value |= (value_index as u64) << current_shift;
                }
            }
            current_shift += bits_needed;
        }

        encoded_items.push(encoded_value);
    }

    // Create the encoded_traits.json structure
    let mut format = HashMap::new();
    let mut indices = HashMap::new();
    let mut current_shift: u64 = 0;

    for (trait_type, values_vec, bits_needed) in &trait_info {
        let mask = if *bits_needed == 64 {
            u64::MAX
        } else {
            (1u64 << bits_needed) - 1
        };

        format.insert(
            trait_type.clone(),
            json!({
                "shift": current_shift,
                "mask": format!("0x{:x}", mask),
                "bits": bits_needed
            }),
        );

        indices.insert(trait_type.clone(), json!(values_vec));
        current_shift += bits_needed;
    }

    let encoded_traits = json!({
        "format": format,
        "indices": indices,
        "items": encoded_items
    });

    // Write to file
    let output = serde_json::to_string_pretty(&encoded_traits)?;
    fs::write("src/encoded_traits.json", output)?;

    println!("Generated encoded_traits.json successfully!");
    println!("Trait categories found: {:?}", trait_info.iter().map(|(t, _, _)| t).collect::<Vec<_>>());
    println!("Total items encoded: {}", encoded_items.len());
    println!("Total bits used: {}", total_bits);

    Ok(())
}

fn main() -> Result<()> {
    // Generate encoded_traits.json from metadata.json
    // generate_encoded_traits()?;
    
    // Generate PNG images (commented out for now)
    generate_pngs()?;
    
    println!("All tasks completed!");
    Ok(())
}

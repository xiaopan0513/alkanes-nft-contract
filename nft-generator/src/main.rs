mod png_generator;
use anyhow::Result;
use std::path::Path;
use crate::png_generator::PngGenerator;

fn main() -> Result<()> {
    println!("Starting png generation...");
    
    // Create output directory
    let output_dir = Path::new("output");
    if !output_dir.exists() {
        std::fs::create_dir(output_dir)?;
    }

    for i in 0..10000 {
        let svg = PngGenerator::generate_png(i)?;
        let filename = format!("output/{:04}.png", i);
        std::fs::write(&filename, svg)?;
        
        if i % 100 == 0 {
            println!("Generated {}/10000 images", i);
        }
    }
    
    println!("png generation completed!");
    Ok(())
}

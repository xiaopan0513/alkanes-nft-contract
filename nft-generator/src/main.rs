use anyhow::Result;
mod svg_generator;
use svg_generator::SvgGenerator;
use std::path::Path;

fn main() -> Result<()> {
    println!("Starting SVG generation...");
    
    // Create output directory
    let output_dir = Path::new("output");
    if !output_dir.exists() {
        std::fs::create_dir(output_dir)?;
    }

    for i in 0..3600 {
        let svg = SvgGenerator::generate_svg(i)?;
        let filename = format!("output/{:04}.svg", i);
        std::fs::write(&filename, svg)?;
        
        if i % 100 == 0 {
            println!("Generated {}/10000 images", i);
        }
    }
    
    println!("SVG generation completed!");
    Ok(())
}

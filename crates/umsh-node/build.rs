use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("session_colors.rs"), session_colors()).unwrap();
}

/// The 256 contact-exchange session colors as `0xRRGGBB`, from the formula
/// in `app-meet.md` (Code and Color): OKLCH at lightness 0.75 and chroma
/// 0.12, the hue in 256 steps, in 8-bit sRGB.
fn session_colors() -> String {
    let mut colors = Vec::new();
    for step in 0..256u32 {
        let h = f64::from(step) * core::f64::consts::TAU / 256.0;
        let (a, b) = (0.12 * h.cos(), 0.12 * h.sin());
        let l = (0.75 + 0.396_337_777_4 * a + 0.215_803_757_3 * b).powi(3);
        let m = (0.75 - 0.105_561_345_8 * a - 0.063_854_172_8 * b).powi(3);
        let s = (0.75 - 0.089_484_177_5 * a - 1.291_485_548_0 * b).powi(3);
        let linear = [
            4.076_741_662_1 * l - 3.307_711_591_3 * m + 0.230_969_929_2 * s,
            -1.268_438_004_6 * l + 2.609_757_401_1 * m - 0.341_319_396_5 * s,
            -0.004_196_086_3 * l - 0.703_418_614_7 * m + 1.707_614_701_0 * s,
        ];
        let mut rgb = 0u32;
        for x in linear {
            let x = x.clamp(0.0, 1.0);
            let encoded = if x <= 0.003_130_8 {
                12.92 * x
            } else {
                1.055 * x.powf(1.0 / 2.4) - 0.055
            };
            rgb = rgb << 8 | (encoded * 255.0).round() as u32;
        }
        colors.push(format!("0x{rgb:06X}"));
    }
    format!(
        "/// The session colors by hue step, as `0xRRGGBB`.\n\
         pub const SESSION_COLORS: [u32; 256] = [{}];\n",
        colors.join(", ")
    )
}

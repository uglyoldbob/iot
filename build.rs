fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    // false - run npm out of the source directory
    // true - run npm out of the build directory
    let use_out = false;

    let out_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("No output directory given"));
    let source_path =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("No source directory"));

    let settings = source_path.join("settings.ini");
    if !settings.exists() {
        let example = source_path.join("settings.example.ini");
        std::fs::copy(example, settings).unwrap();
    }

    let p = if use_out {
        let p = out_path.join("js");
        std::fs::create_dir_all(&p).expect("Failed to create file for npm work files");

        for f in ["package.json", "package-lock.json"] {
            let src = source_path.join(f);
            let dest = p.join(f);
            std::fs::copy(src, dest).expect(&format!("Failed to copy input file {} for npm", f));
        }
        p
    } else {
        source_path.join("js")
    };

    let npm_test = std::process::Command::new("npm")
        .current_dir(&p)
        .arg("--version")
        .status();

    if npm_test.is_ok() {
        println!("cargo:rerun-if-changed=js");
        let npm_output = std::process::Command::new("npm")
            .current_dir(&p)
            .arg("install")
            .status()
            .expect("Failed to run npm");
        if !npm_output.success() {
            panic!("Npm install failed");
        }

        let nfp = p.join("node_modules");
        let filenames = [
            ("node-forge/dist/forge.all.min.js", "forge.all.min.js"),
            ("node-forge/dist/forge.min.js", "forge.min.js"),
            ("node-forge/dist/forge.min.js.map", "forge.min.js.map"),
            ("node-forge/dist/prime.worker.min.js", "prime.worker.min.js"),
            ("certgen/index.min.js", "certgen.min.js"),
        ];
        if use_out {
            for (f, g) in filenames {
                let src = nfp.join(f);
                std::fs::copy(src, out_path.join(g))
                    .expect(&format!("Failed to copy js file {}", f));
            }
        } else {
            let p = source_path.join("content").join("js");
            std::fs::create_dir_all(&p).expect("Failed to create file for npm built files");
            for (f, g) in filenames {
                let src = nfp.join(f);
                let dst = p.join(g);
                std::fs::copy(&src, dst)
                    .expect(&format!("Failed to copy js file {}", src.to_str().unwrap()));
            }
        }
    }
}

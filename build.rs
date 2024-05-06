fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changes=./certgen/Cargo.toml");
    println!("cargo:rerun-if-changes=./certgen/src");
    println!("cargo:rerun-if-changes=./certgen/.cargo/config.toml");

    let wasm_build = std::process::Command::new("wasm-pack")
        .arg("build")
        .arg("--release")
        .current_dir("./certgen")
        .output()
        .unwrap();
    if !wasm_build.status.success() {
        println!("{}", String::from_utf8(wasm_build.stdout).unwrap());
        eprintln!("{}", String::from_utf8(wasm_build.stderr).unwrap());
    }

    // false - run npm out of the source directory
    // true - run npm out of the build directory
    let use_out = false;

    let out_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("No output directory given"));
    let source_path =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("No source directory"));

    let content_dest_path = source_path.join("content").join("js");

    let p = if use_out {
        let p = out_path.join("js");
        std::fs::create_dir_all(&p).expect("Failed to create file for npm work files");

        for f in ["package.json", "package-lock.json"] {
            let src = source_path.join(f);
            let dest = p.join(f);
            std::fs::copy(src, dest)
                .unwrap_or_else(|_| panic!("Failed to copy input file {} for npm", f));
        }
        p
    } else {
        source_path.join("js")
    };

    println!(
        "current dir is {}",
        std::env::current_dir().unwrap().display()
    );

    if !use_out {
        std::fs::create_dir_all(&content_dest_path)
            .expect("Failed to create file for npm built files");
    }

    let npm_test = std::process::Command::new("npm")
        .current_dir(&p)
        .arg("--version")
        .status();

    println!("Npm path is {}", p.display());

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
        let filenames = vec![
            ("node-forge/dist/forge.all.min.js", "forge.all.min.js"),
            ("node-forge/dist/forge.min.js", "forge.min.js"),
            ("node-forge/dist/forge.min.js.map", "forge.min.js.map"),
            ("node-forge/dist/prime.worker.min.js", "prime.worker.min.js"),
            ("certgen/index.min.js", "certgen.min.js"),
            ("certgen-wasm/certgen_bg.js", "certgen_bg.js"),
            ("certgen-wasm/certgen_bg.wasm", "certgen_bg.wasm"),
            ("certgen-wasm/certgen_bg.wasm.d.ts", "certgen_bg.wasm.d.ts"),
            ("certgen-wasm/certgen.d.ts", "certgen_wasm.d.ts"),
            ("certgen-wasm/certgen.js", "certgen_wasm.js"),
        ];
        if use_out {
            for (f, g) in filenames {
                let src = nfp.join(f);
                std::fs::copy(src, out_path.join(g))
                    .unwrap_or_else(|_| panic!("Failed to copy js file {}", f));
            }
        } else {
            for (f, g) in filenames {
                let src = nfp.join(f);
                let dst = content_dest_path.join(g);
                std::fs::copy(&src, dst)
                    .unwrap_or_else(|_| panic!("Failed to copy js file {}", src.to_str().unwrap()));
            }
        }
    }
}

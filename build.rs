fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=./certgen");
    println!("cargo::rerun-if-changed=./jcardsim/pom.xml");

    let out_path =
        std::path::PathBuf::from(std::env::var("OUT_DIR").expect("No output directory given"));

    std::env::set_var("CARGO_TARGET_DIR", out_path.clone());
    #[cfg(not(coverage))]
    {
        // Build WASM
        let wasm_build = std::process::Command::new("wasm-pack")
            .arg("build")
            .arg("--release")
            .arg("--target")
            .arg("no-modules")
            .current_dir("./certgen")
            .output()
            .unwrap();
        if !wasm_build.status.success() {
            println!("{}", String::from_utf8(wasm_build.stdout).unwrap());
            eprintln!("{}", String::from_utf8(wasm_build.stderr).unwrap());
            panic!("build failed");
        }

        // Build jcardsim JAR using Maven, setting JC_CLASSIC_HOME to javacard-sdk/jc305u3_kit
        let mut jcardsim_cmd = std::process::Command::new("mvn");
        jcardsim_cmd.arg("package").current_dir("./jcardsim");
        jcardsim_cmd.env("JC_CLASSIC_HOME", "../javacard-sdk/jc305u3_kit");
        let jcardsim_build = jcardsim_cmd
            .output()
            .expect("Failed to run mvn package for jcardsim");
        if !jcardsim_build.status.success() {
            println!("{}", String::from_utf8_lossy(&jcardsim_build.stdout));
            eprintln!("{}", String::from_utf8_lossy(&jcardsim_build.stderr));
            panic!("jcardsim build failed");
        }
    }

    // false - run npm out of the source directory
    // true - run npm out of the build directory
    let use_out = false;

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
    println!("cargo::rerun-if-changed=js");

    if npm_test.is_ok() {
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
            ("certgen-wasm/certgen_bg.wasm", "certgen_bg.wasm"),
            ("certgen-wasm/certgen.d.ts", "certgen_wasm.d.ts"),
            ("certgen-wasm/certgen.js", "certgen.js"),
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

    // Build the vsmartcard/virtualsmartcard/src/vpcd project using autotools and make
    let vsmartcard_dir = source_path.join("vsmartcard/virtualsmartcard");

    // --- Build PivApplet Java classes if present ---
    let pivapplet_src = source_path.join("PivApplet/src/net/cooperi/pivapplet");
    let pivapplet_out = source_path.join("PivApplet/classes");
    let jcardsim_jar = source_path.join("target/dependency/jcardsim-3.0.6.0.jar");

    if pivapplet_src.exists() {
        std::fs::create_dir_all(&pivapplet_out)
            .expect("Failed to create PivApplet/classes directory");

        // Enumerate all .java files and pass them individually to javac
        let java_files: Vec<_> = std::fs::read_dir(&pivapplet_src)
            .expect("Failed to read PivApplet source directory")
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension()? == "java" {
                    Some(path)
                } else {
                    None
                }
            })
            .collect();

        if java_files.is_empty() {
            panic!("No Java files found in PivApplet source directory");
        }

        // Add JavaCard SDK api_classic.jar to classpath
        let javacard_api_jar = source_path.join("javacard-sdk/jc305u3_kit/lib/api_classic.jar");
        let classpath = format!("{}:{}", jcardsim_jar.display(), javacard_api_jar.display());

        let mut javac_cmd = std::process::Command::new("javac");
        javac_cmd
            .arg("-d")
            .arg(&pivapplet_out)
            .arg("-classpath")
            .arg(&classpath);

        for file in &java_files {
            javac_cmd.arg(file);
        }

        let javac_status = javac_cmd
            .status()
            .expect("Failed to run javac for PivApplet");

        if !javac_status.success() {
            panic!("javac failed to build PivApplet");
        } else {
            println!("cargo:warning=PivApplet built successfully");
        }
    } else {
        println!("cargo:warning=PivApplet source not found, skipping Java build");
    }
    // Run autoreconf -vis
    let autoreconf_status = std::process::Command::new("autoreconf")
        .arg("-vis")
        .current_dir(&vsmartcard_dir)
        .status()
        .expect("Failed to run autoreconf for vsmartcard/virtualsmartcard");
    if !autoreconf_status.success() {
        panic!("autoreconf for vsmartcard/virtualsmartcard failed");
    }
    // Run ./configure
    let configure_status = std::process::Command::new("./configure")
        .current_dir(&vsmartcard_dir)
        .status()
        .expect("Failed to run configure for vsmartcard/virtualsmartcard");
    if !configure_status.success() {
        panic!("configure for vsmartcard/virtualsmartcard failed");
    }
    // Run make
    let make_status = std::process::Command::new("make")
        .current_dir(&vsmartcard_dir)
        .status()
        .expect("Failed to run make for vsmartcard/virtualsmartcard");
    if !make_status.success() {
        panic!("make for vsmartcard/virtualsmartcard failed");
    }
    println!("cargo::rerun-if-changed=vsmartcard/virtualsmartcard");
}

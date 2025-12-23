#![allow(unused)]
use std::process::Command;

/// Minimal PIV integration test using jcardsim directly.
/// This test creates a simple Java program that instantiates the PIV applet
/// and tests basic functionality without requiring external processes.
#[test]
fn piv_apdu_integration() {
    // Create a minimal Java test that just verifies the PIV applet can be loaded
    let java_test_code = r#"
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

public class PivTest {
    public static void main(String[] args) {
        try {
            System.out.println("Creating simulator...");
            Simulator simulator = new Simulator();

            System.out.println("Creating PIV AID...");
            AID pivAID = AIDUtil.create("A000000308000010000100");

            System.out.println("Installing PIV applet...");
            simulator.installApplet(pivAID, net.cooperi.pivapplet.PivApplet.class);

            System.out.println("Selecting PIV applet...");
            simulator.selectApplet(pivAID);

            System.out.println("PIV applet integration test completed successfully!");

        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
"#;

    // Write the Java test to a temporary file
    let temp_dir = std::env::temp_dir();
    let java_file = temp_dir.join("PivTest.java");
    std::fs::write(&java_file, java_test_code).expect("Failed to write Java test file");

    // Compile the Java test
    let jcardsim_jar = "jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar";
    let jc_api_jar = "javacard-sdk/jc305u3_kit/lib/api_classic.jar";
    let pivapplet_classes = "PivApplet/bin";
    let bouncy_castle_jar = format!(
        "{}/.m2/repository/org/bouncycastle/bcprov-jdk14/1.71/bcprov-jdk14-1.71.jar",
        std::env::var("HOME").unwrap()
    );
    let classpath = format!(
        "{}:{}:{}:{}",
        jcardsim_jar, jc_api_jar, pivapplet_classes, bouncy_castle_jar
    );

    let compile_output = Command::new("javac")
        .arg("-cp")
        .arg(&classpath)
        .arg("-d")
        .arg(&temp_dir)
        .arg(&java_file)
        .output()
        .expect("Failed to run javac");

    if !compile_output.status.success() {
        panic!(
            "Java compilation failed:\nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&compile_output.stdout),
            String::from_utf8_lossy(&compile_output.stderr)
        );
    }

    // Run the Java test
    let test_output = Command::new("java")
        .arg("-cp")
        .arg(format!("{}:{}", temp_dir.display(), classpath))
        .arg("PivTest")
        .output()
        .expect("Failed to run Java test");

    let stdout = String::from_utf8_lossy(&test_output.stdout);
    let stderr = String::from_utf8_lossy(&test_output.stderr);

    println!("Java test output:\n{}", stdout);
    if !stderr.is_empty() {
        eprintln!("Java test errors:\n{}", stderr);
    }

    if !test_output.status.success() {
        panic!(
            "Java PIV test failed with exit code: {}",
            test_output.status
        );
    }

    // Clean up
    let _ = std::fs::remove_file(&java_file);
    let _ = std::fs::remove_file(temp_dir.join("PivTest.class"));

    println!("PIV integration test with jcardsim completed successfully!");
}

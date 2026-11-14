// يضمّن ملف manifest في البرنامج حتى يستعمل Windows مكتبة Common Controls v6
// (بدونه يظهر الخطأ: GetWindowSubclass introuvable)
fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        embed_manifest::embed_manifest(embed_manifest::new_manifest("InstaAutoreplyGui"))
            .expect("unable to embed manifest");
    }
    println!("cargo:rerun-if-changed=build.rs");
}

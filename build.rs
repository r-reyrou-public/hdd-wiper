fn main() {
    // exe のアイコン(tools/make_icon.py で生成した .res をリンクする)
    println!("cargo:rerun-if-changed=assets/icon.res");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        let dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        println!("cargo:rustc-link-arg-bins={dir}/assets/icon.res");
    }
    println!("cargo:rerun-if-env-changed=HDDWIPER_NO_ADMIN_MANIFEST");
    // 管理者権限での起動を要求するマニフェストを埋め込む (MSVCリンカ)
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
        && std::env::var("HDDWIPER_NO_ADMIN_MANIFEST").is_err()
    {
        println!("cargo:rustc-link-arg-bins=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg-bins=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'");
    }
}

fn main() {
    #[cfg(feature = "gui")]
    slint_build::compile("ui/k5.slint").expect("failed to compile ui/k5.slint");
}

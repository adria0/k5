// The k5 Android app: the k5 window (`k5gui`) as an Android activity. The
// keys (`k5.toml`) and the database live in the app's private storage; the
// notary, if any, comes from the `[notary]` section of that `k5.toml`.
//
// Logs go to logcat, tagged `k5`: `adb logcat -s k5`.
//
// Built with cargo-apk, in a Docker image: see `k5-android.sh`.

#[cfg(target_os = "android")]
mod camera;

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    // k5's own messages, and only the warnings of its dependencies (iroh's
    // info messages would bury them).
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Info)
            .with_tag("k5")
            .with_filter(
                android_logger::FilterBuilder::new()
                    .parse("warn,k5gui=info,k5net=info,k5lib=info,k5android=info")
                    .build(),
            ),
    );
    // Panics would otherwise leave no trace.
    std::panic::set_hook(Box::new(|info| log::error!("{info}")));

    if let Err(e) = run(app) {
        log::error!("{e:#}");
    }
}

#[cfg(target_os = "android")]
fn run(app: slint::android::AndroidApp) -> anyhow::Result<()> {
    let dir = app
        .internal_data_path()
        .ok_or_else(|| anyhow::anyhow!("the app has no private storage"))?;
    // The camera keeps the app: its activity asks for the permission.
    let scanner = camera::CameraScanner::new(app.clone());
    slint::android::init(app).map_err(|e| anyhow::anyhow!("{e}"))?;

    k5gui::start(k5gui::Options {
        config: dir.join("k5.toml"),
        db: dir.join("db"),
        notary_key: k5lib::api::DEFAULT_NOTARY_KEY.to_string(),
        notary: None,
        offline: false,
        scanner: Some(Box::new(scanner)),
    })
}

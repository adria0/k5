// The system clipboard, to hand over tickets, signcrypted messages and the
// local k5: arboard on the desktop, Android's `ClipboardManager` (through JNI)
// on Android, where arboard has no backend.

/// Puts text on the system clipboard.
#[derive(Default)]
pub struct Clipboard {
    /// Kept open: on Linux the content is lost when it is closed.
    #[cfg(not(target_os = "android"))]
    desktop: Option<arboard::Clipboard>,
}

impl Clipboard {
    pub fn set_text(&mut self, text: String) -> anyhow::Result<()> {
        #[cfg(not(target_os = "android"))]
        {
            self.desktop()?.set_text(text)?;
            Ok(())
        }
        #[cfg(target_os = "android")]
        {
            android::set_text(&text)
        }
    }

    /// The text on the clipboard, `None` if there is none.
    pub fn get_text(&mut self) -> anyhow::Result<Option<String>> {
        #[cfg(not(target_os = "android"))]
        {
            match self.desktop()?.get_text() {
                Ok(text) => Ok(Some(text)),
                Err(arboard::Error::ContentNotAvailable) => Ok(None),
                Err(e) => Err(e.into()),
            }
        }
        #[cfg(target_os = "android")]
        {
            android::get_text()
        }
    }

    #[cfg(not(target_os = "android"))]
    fn desktop(&mut self) -> anyhow::Result<&mut arboard::Clipboard> {
        if self.desktop.is_none() {
            self.desktop = Some(arboard::Clipboard::new()?);
        }
        self.desktop
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("no clipboard"))
    }
}

/// The first ticket (`k5ticket:...`) in `text`, e.g. a message that
/// contains one.
pub fn find_ticket(text: &str) -> Option<&str> {
    let start = text.find("k5ticket:")?;
    let rest = &text[start..];
    let end = rest["k5ticket:".len()..]
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .map_or(rest.len(), |end| end + "k5ticket:".len());

    Some(&rest[..end]).filter(|ticket| ticket.len() > "k5ticket:".len())
}

/// `ClipboardManager` through JNI, with the Java VM and the `Context` that
/// `android-activity` (Slint's Android backend) registers in `ndk-context`.
/// Also compiled in tests, to check it off Android.
#[cfg(any(target_os = "android", test))]
mod android {
    use anyhow::{anyhow, Context as _};
    use jni::{
        jni_sig, jni_str,
        objects::{JObject, JString, JValue},
        refs::Global,
    };

    /// Label of the clips, shown by some keyboards.
    const LABEL: &str = "k5";

    /// Runs `f` with the Java VM, the app's `Context` and its
    /// `ClipboardManager`.
    fn with_clipboard<T>(
        f: impl FnOnce(&mut jni::Env, &JObject, &JObject) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let android = ndk_context::android_context();
        if android.vm().is_null() || android.context().is_null() {
            return Err(anyhow!("no Android context to reach the clipboard"));
        }
        // Safety: a non-null Java VM pointer, from ndk-context.
        let vm = unsafe { jni::JavaVM::from_raw(android.vm().cast()) };

        vm.attach_current_thread(|env| -> anyhow::Result<T> {
            // Safety: ndk-context holds a global reference to an
            // `android.content.Context` for the life of the app; the cast
            // does not own it, so it is never deleted here.
            let raw: jni::sys::jobject = android.context().cast();
            let context = unsafe { env.as_cast_raw::<Global<JObject>>(&raw) }
                .context("invalid Android context")?;
            let context: &JObject = &context;

            let service = env.new_string("clipboard")?;
            let manager = env
                .call_method(
                    context,
                    jni_str!("getSystemService"),
                    jni_sig!("(Ljava/lang/String;)Ljava/lang/Object;"),
                    &[JValue::Object(&service)],
                )?
                .l()?;
            if manager.is_null() {
                return Err(anyhow!("no clipboard service"));
            }

            f(env, context, &manager)
        })
    }

    pub fn set_text(text: &str) -> anyhow::Result<()> {
        with_clipboard(|env, _, manager| {
            let label = env.new_string(LABEL)?;
            let text = env.new_string(text)?;
            let clip = env
                .call_static_method(
                    jni_str!("android/content/ClipData"),
                    jni_str!("newPlainText"),
                    jni_sig!(
                        "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;"
                    ),
                    &[JValue::Object(&label), JValue::Object(&text)],
                )?
                .l()?;
            env.call_method(
                manager,
                jni_str!("setPrimaryClip"),
                jni_sig!("(Landroid/content/ClipData;)V"),
                &[JValue::Object(&clip)],
            )?;

            Ok(())
        })
    }

    /// The text of the first item of the clipboard, if any.
    pub fn get_text() -> anyhow::Result<Option<String>> {
        with_clipboard(|env, context, manager| {
            let clip = env
                .call_method(
                    manager,
                    jni_str!("getPrimaryClip"),
                    jni_sig!("()Landroid/content/ClipData;"),
                    &[],
                )?
                .l()?;
            if clip.is_null() {
                return Ok(None);
            }
            let items = env
                .call_method(&clip, jni_str!("getItemCount"), jni_sig!("()I"), &[])?
                .i()?;
            if items == 0 {
                return Ok(None);
            }
            let item = env
                .call_method(
                    &clip,
                    jni_str!("getItemAt"),
                    jni_sig!("(I)Landroid/content/ClipData$Item;"),
                    &[JValue::Int(0)],
                )?
                .l()?;
            // Plain text, or the text of a URI or an intent.
            let text = env
                .call_method(
                    &item,
                    jni_str!("coerceToText"),
                    jni_sig!("(Landroid/content/Context;)Ljava/lang/CharSequence;"),
                    &[JValue::Object(context)],
                )?
                .l()?;
            if text.is_null() {
                return Ok(None);
            }
            let text = env
                .call_method(
                    &text,
                    jni_str!("toString"),
                    jni_sig!("()Ljava/lang/String;"),
                    &[],
                )?
                .l()?;
            let text = env.cast_local::<JString>(text)?;

            Ok(Some(text.try_to_string(env)?))
        })
    }

    #[test]
    fn test_no_android_context() {
        // Off Android, ndk-context is empty: an error, not a crash.
        let result = std::panic::catch_unwind(|| set_text("x"));
        assert!(!matches!(result, Ok(Ok(()))));
        let result = std::panic::catch_unwind(get_text);
        assert!(!matches!(result, Ok(Ok(_))));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_ticket() {
        assert_eq!(find_ticket("k5ticket:eyJp_d-9"), Some("k5ticket:eyJp_d-9"));
        // In a message, up to the first character a ticket cannot have.
        assert_eq!(
            find_ticket("here it is: k5ticket:eyJp9. see you\n"),
            Some("k5ticket:eyJp9")
        );
        assert_eq!(find_ticket("  k5ticket:abc\n"), Some("k5ticket:abc"));
        assert_eq!(find_ticket("no ticket here"), None);
        assert_eq!(find_ticket("k5ticket:"), None);
    }
}

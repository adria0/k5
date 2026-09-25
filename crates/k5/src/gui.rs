// `k5 gui`: a Slint desktop front end of the k5 API (`ui/k5.slint`).
//
// The window runs on the main thread. A worker thread owns the [`K5`] and a
// tokio runtime, and serves the requests of the window: it loads and verifies
// the attestations once (and on rescan), then answers searches and dossiers
// from that cache, and signs or signcrypts outgoing messages. Results go back
// to the window as plain data through `upgrade_in_event_loop`.
//
// There is no transport: a sent message is copied to the clipboard, ready to be
// handed to the recipient.

use std::{
    collections::{BTreeSet, HashSet},
    sync::mpsc,
    thread,
};

use slint::{ComponentHandle, ModelRc, VecModel};

use k5::api::{ProfileAttestation, ATTESTATIONS_DIR, K5};

slint::include_modules!();

/// Platforms of the self attestations, never shown (their only use, the KEM
/// key, is in the dossier), and of the keysigns.
const SELF: &str = "self_attestation";
const KEYSIGN: &str = "keysignparty";
/// Maximum number of search results shown.
const MAX_HITS: usize = 300;

enum Request {
    Rescan,
    Search(String),
    Select(String),
    Send {
        to: String,
        msg: String,
        cipher: bool,
    },
}

/// Opens the window, blocking until it is closed.
pub fn run(k5: K5) -> Result<(), Box<dyn std::error::Error>> {
    let ui = AppWindow::new()?;
    ui.set_me(short(&k5.k5()).into());

    let (tx, rx) = mpsc::channel();
    ui.on_search({
        let tx = tx.clone();
        move |query| {
            let _ = tx.send(Request::Search(query.into()));
        }
    });
    ui.on_select({
        let tx = tx.clone();
        move |k5| {
            let _ = tx.send(Request::Select(k5.into()));
        }
    });
    ui.on_send({
        let tx = tx.clone();
        move |to, msg, cipher| {
            let _ = tx.send(Request::Send {
                to: to.into(),
                msg: msg.into(),
                cipher,
            });
        }
    });
    ui.on_rescan({
        let tx = tx.clone();
        move || {
            let _ = tx.send(Request::Rescan);
        }
    });

    let weak = ui.as_weak();
    thread::spawn(move || Worker::new(k5, weak).serve(rx));
    tx.send(Request::Rescan)?;

    ui.run()?;

    Ok(())
}

struct Worker {
    k5: K5,
    ui: slint::Weak<AppWindow>,
    /// The verified attestations, as of the last scan.
    attestations: Vec<ProfileAttestation>,
    trusted: HashSet<String>,
    query: String,
    clipboard: Option<arboard::Clipboard>,
}

impl Worker {
    fn new(k5: K5, ui: slint::Weak<AppWindow>) -> Self {
        Self {
            k5,
            ui,
            attestations: Vec::new(),
            trusted: HashSet::new(),
            query: String::new(),
            clipboard: None,
        }
    }

    fn serve(mut self, rx: mpsc::Receiver<Request>) {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => return self.status(format!("ERROR: {e}"), false),
        };

        while let Ok(request) = rx.recv() {
            match request {
                Request::Rescan => self.rescan(&runtime),
                Request::Search(query) => {
                    self.query = query;
                    self.search();
                }
                Request::Select(k5) => self.select(&k5),
                Request::Send { to, msg, cipher } => self.send(&runtime, &to, &msg, cipher),
            }
        }
    }

    fn status(&self, status: String, busy: bool) {
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_status(status.into());
            ui.set_busy(busy);
        });
    }

    fn rescan(&mut self, runtime: &tokio::runtime::Runtime) {
        self.status(format!("SCANNING {ATTESTATIONS_DIR}/ ..."), true);

        let listing = match runtime.block_on(self.k5.list()) {
            Ok(listing) => listing,
            Err(e) => return self.status(format!("SCAN FAILED: {e}"), false),
        };
        self.trusted = self.k5.web_of_trust(&listing.attestations);
        self.attestations = listing.attestations;

        let ids: BTreeSet<&str> = self
            .attestations
            .iter()
            .map(|attestation| attestation.profile.k5.as_str())
            .collect();
        let (ids, trusted) = (ids.len(), self.trusted.len());
        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_stats_ids(ids.to_string().into());
            ui.set_stats_trusted(trusted.to_string().into());
        });
        let status = match listing.invalid.len() {
            0 => String::new(),
            invalid => format!("{invalid} INVALID RECORDS IGNORED"),
        };
        self.status(status, false);
        self.search();
    }

    /// Posts the attestations whose user or k5 contains the query, ignoring
    /// case, deduplicated by profile. An empty query matches everything.
    fn search(&self) {
        let query = self.query.trim().to_lowercase();
        let query = query.strip_prefix("k5:").unwrap_or(&query);

        let mut hits: Vec<Hit> = Vec::new();
        for attestation in &self.attestations {
            let profile = &attestation.profile;
            if profile.platform == SELF {
                continue;
            }
            if !profile.user.to_lowercase().contains(query) && !profile.k5.contains(query) {
                continue;
            }
            let platform = platform(profile.platform);
            let existing = hits.iter().position(|hit| {
                hit.platform == platform && hit.user == profile.user && hit.k5 == profile.k5
            });
            match existing {
                Some(idx) => hits[idx].count += 1,
                None if hits.len() < MAX_HITS => hits.push(Hit {
                    platform: platform.into(),
                    label: label(profile.platform).into(),
                    user: profile.user.as_str().into(),
                    k5: profile.k5.as_str().into(),
                    short: short(&profile.k5).into(),
                    count: 1,
                }),
                None => {}
            }
        }

        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_hits(ModelRc::new(VecModel::from(hits)));
        });
    }

    /// Posts the dossier of `k5`: its profile counts, whether it has an
    /// encryption subkey, and its trust path.
    fn select(&self, k5: &str) {
        let attestations: Vec<&ProfileAttestation> = self
            .attestations
            .iter()
            .filter(|attestation| attestation.profile.k5 == k5)
            .collect();
        let count = |platform: &str| {
            attestations
                .iter()
                .filter(|attestation| attestation.profile.platform == platform)
                .count() as i32
        };
        let attribute = |attestation: &ProfileAttestation, name: &str| {
            attestation
                .attributes
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.clone())
        };

        let kem = attestations
            .iter()
            .filter(|attestation| attestation.profile.platform == "self_attestation")
            .filter_map(|attestation| attribute(attestation, "encryption_subkey"))
            .any(|subkey| !subkey.is_empty());
        let name = ["X", "github", "site", "keysignparty"]
            .iter()
            .find_map(|platform| {
                attestations
                    .iter()
                    .find(|attestation| attestation.profile.platform == *platform)
                    .map(|attestation| attestation.profile.user.clone())
            })
            .unwrap_or_else(|| "UNKNOWN".to_string());
        let (k5_a, k5_b) = k5.split_at(k5.len() / 2);

        let dossier = Dossier {
            k5: k5.into(),
            k5_a: k5_a.into(),
            k5_b: k5_b.into(),
            name: name.into(),
            kem,
            trusted: self.trusted.contains(k5),
            me: k5 == self.k5.k5(),
            x: count("X"),
            github: count("github"),
            site: count("site"),
            keysign: count("keysignparty"),
        };

        let glyph = glyph(k5);
        let me = self.k5.k5();
        let path: Vec<Link> = self
            .k5
            .trust_path(&self.attestations, k5)
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|node| Link {
                label: if *node == me {
                    "ME".into()
                } else {
                    who(&me, &self.attestations, node).into()
                },
                short: short(node).into(),
                me: *node == me,
            })
            .collect();

        let _ = self.ui.upgrade_in_event_loop(move |ui| {
            ui.set_dossier(dossier);
            ui.set_glyph(ModelRc::new(VecModel::from(glyph)));
            ui.set_path(ModelRc::new(VecModel::from(path)));
            ui.set_has_dossier(true);
        });
    }

    /// Signs (and, with `cipher`, encrypts) `msg` to `to`, writing it to
    /// the clipboard.
    fn send(&mut self, runtime: &tokio::runtime::Runtime, to: &str, msg: &str, cipher: bool) {
        self.status("SEALING MESSAGE ...".to_string(), true);

        let sealed = runtime.block_on(async {
            if cipher {
                self.k5
                    .signcrypt(to, msg)
                    .await
                    .map(|sealed| sealed.armored)
            } else {
                self.k5.sign(msg).await
            }
        });
        let armored = match sealed {
            Ok(armored) => armored,
            Err(e) => return self.status(format!("SEND FAILED: {e}"), false),
        };

        match self.copy(armored) {
            Ok(()) => self.status("MESSAGE COPIED TO CLIPBOARD".to_string(), false),
            Err(e) => self.status(format!("COPY TO CLIPBOARD FAILED: {e}"), false),
        }
    }

    /// Puts `text` on the clipboard. The clipboard is kept open: on Linux its
    /// content is lost when it is closed.
    fn copy(&mut self, text: String) -> Result<(), arboard::Error> {
        let clipboard = match &mut self.clipboard {
            Some(clipboard) => clipboard,
            None => self.clipboard.insert(arboard::Clipboard::new()?),
        };
        clipboard.set_text(text)
    }
}

/// Icon key of a platform.
fn platform(platform: &str) -> &'static str {
    match platform {
        "X" => "x",
        "github" => "github",
        "site" => "site",
        "keysignparty" => "keysign",
        "self_attestation" => "self",
        _ => "other",
    }
}

/// Display name of a platform.
fn label(platform: &str) -> String {
    match platform {
        "keysignparty" => "KEYSIGN".to_string(),
        "self_attestation" => "SELF".to_string(),
        other => other.to_uppercase(),
    }
}

/// `0123abcd…cdef` for a long hex string.
fn short(hex: &str) -> String {
    if hex.len() <= 16 {
        return hex.to_string();
    }
    format!("{}…{}", &hex[..8], &hex[hex.len() - 4..])
}

/// Who `k5` is, among `attestations` (`me` being the local k5): its
/// profiles (`X:handle · GITHUB:user`), or else the name it was keysigned
/// with, or else its short id.
fn who(me: &str, attestations: &[ProfileAttestation], k5: &str) -> String {
    if k5 == me {
        return "YOU".to_string();
    }
    let about = || {
        attestations
            .iter()
            .filter(move |attestation| attestation.profile.k5 == k5)
    };

    let profiles: BTreeSet<String> = about()
        .filter(|attestation| !matches!(attestation.profile.platform, SELF | KEYSIGN))
        .map(|attestation| {
            format!(
                "{}:{}",
                label(attestation.profile.platform),
                attestation.profile.user
            )
        })
        .collect();
    if !profiles.is_empty() {
        return profiles.into_iter().collect::<Vec<_>>().join(" · ");
    }

    match about().find(|attestation| attestation.profile.platform == KEYSIGN) {
        Some(keysign) => format!("{} (k5:{})", keysign.profile.user, short(k5)),
        None => format!("k5:{}", short(k5)),
    }
}

/// A 9x9 horizontally symmetric identicon from the bits of `k5`.
fn glyph(k5: &str) -> Vec<i32> {
    let bits: Vec<bool> = k5
        .chars()
        .filter_map(|c| c.to_digit(16))
        .flat_map(|nibble| (0..4).map(move |bit| nibble >> bit & 1 == 1))
        .collect();

    (0..81)
        .map(|i| {
            let (row, col) = (i / 9, i % 9);
            let col = col.min(8 - col);
            bits.get(row * 5 + col).copied().unwrap_or(false) as i32
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders the window with sample data to `$K5_SNAPSHOT/search.ppm`,
    /// `dossier.ppm` and `compose.ppm`, with the software renderer, to look at the design
    /// without a display.
    #[test]
    #[ignore = "writes window snapshots to $K5_SNAPSHOT"]
    fn snapshot() {
        use std::rc::Rc;

        use slint::platform::{
            software_renderer::{MinimalSoftwareWindow, RepaintBufferType},
            Platform, WindowAdapter,
        };

        struct Offscreen(Rc<MinimalSoftwareWindow>);
        impl Platform for Offscreen {
            fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
                Ok(self.0.clone())
            }
        }

        let dir = std::env::var("K5_SNAPSHOT").expect("set K5_SNAPSHOT to a directory");
        let (width, height) = (430, 932);
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(Offscreen(window.clone()))).unwrap();
        window.set_size(slint::PhysicalSize::new(width, height));

        let ui = AppWindow::new().unwrap();
        let me = "04d3b0f990d5564e5d7a698940483d07e030f37a9dfb112ad337dd23b512c785";
        let bob = "21e0a274bcf03711864c5eb1164a3a3735db671b058373ba6cf75acd4b214cbd";
        ui.set_me(short(me).into());
        ui.set_stats_ids("51".into());
        ui.set_stats_trusted("41".into());
        let hit = |platform: &str, label: &str, user: &str, k5: &str, count| Hit {
            platform: platform.into(),
            label: label.into(),
            user: user.into(),
            k5: k5.into(),
            short: short(k5).into(),
            count,
        };
        ui.set_hits(ModelRc::new(VecModel::from(vec![
            hit("x", "X", "adria0", me, 1),
            hit("github", "GITHUB", "adria0", me, 1),
            hit("site", "SITE", "ethbcn.dev", me, 1),
            hit("keysign", "KEYSIGN", "BobTheBuilder", bob, 3),
            hit("x", "X", "bob_builds", bob, 1),
            hit("other", "OTHER", "mystery", bob, 1),
        ])));
        ui.set_dossier(Dossier {
            k5: me.into(),
            k5_a: me[..32].into(),
            k5_b: me[32..].into(),
            name: "adria0".into(),
            kem: true,
            trusted: true,
            me: false,
            x: 1,
            github: 1,
            site: 1,
            keysign: 1,
        });
        ui.set_glyph(ModelRc::new(VecModel::from(glyph(me))));
        let link = |label: &str, k5: &str, me| Link {
            label: label.into(),
            short: short(k5).into(),
            me,
        };
        ui.set_path(ModelRc::new(VecModel::from(vec![
            link("GITHUB:adria0 · SITE:ethbcn.dev · X:adria0", me, false),
            link("X:bob_builds · GITHUB:bob", bob, false),
            link("ME", me, true),
        ])));
        ui.show().unwrap();

        let render = |name: &str| {
            slint::platform::update_timers_and_animations();
            window.request_redraw();
            let mut buffer = vec![slint::Rgb8Pixel::default(); (width * height) as usize];
            window.draw_if_needed(|renderer| {
                renderer.render(&mut buffer, width as usize);
            });
            let mut ppm = format!("P6\n{width} {height}\n255\n").into_bytes();
            for pixel in &buffer {
                ppm.extend([pixel.r, pixel.g, pixel.b]);
            }
            std::fs::write(format!("{dir}/{name}.ppm"), ppm).unwrap();
        };
        render("search");
        ui.set_has_dossier(true);
        render("dossier");
        ui.set_cipher(true);
        ui.set_composing(true);
        render("compose");
    }

    #[test]
    fn test_glyph() {
        let glyph = glyph(&"a5".repeat(32));
        assert_eq!(glyph.len(), 81);
        for row in glyph.chunks(9) {
            let mirrored: Vec<i32> = row.iter().rev().copied().collect();
            assert_eq!(row, mirrored);
        }
    }

    #[test]
    fn test_who() {
        use k5::api::Profile;

        let attestation = |platform: &'static str, user: &str, k5: &str| ProfileAttestation {
            profile: Profile {
                platform,
                user: user.to_string(),
                k5: k5.to_string(),
            },
            signer: None,
            attributes: Vec::new(),
            file: String::new(),
            fake: false,
        };
        let [me, alice, bob, carol] = ["a", "b", "c", "d"].map(|c| c.repeat(64));
        let attestations = [
            attestation("github", "alice", &alice),
            attestation("X", "alice_x", &alice),
            attestation(SELF, "self", &alice),
            attestation(KEYSIGN, "Alice", &alice),
            attestation(SELF, "self", &bob),
            attestation(KEYSIGN, "Bob", &bob),
        ];

        assert_eq!(who(&me, &attestations, &me), "YOU");
        assert_eq!(who(&me, &attestations, &alice), "GITHUB:alice · X:alice_x");
        assert_eq!(
            who(&me, &attestations, &bob),
            format!("Bob (k5:{})", short(&bob))
        );
        assert_eq!(
            who(&me, &attestations, &carol),
            format!("k5:{}", short(&carol))
        );
    }

    #[test]
    fn test_short() {
        assert_eq!(short("abc"), "abc");
        assert_eq!(short(&"0123456789abcdef".repeat(4)), "01234567…cdef");
    }
}

// The back camera, to read tickets from QR codes (`k5gui::scanner`), with the
// NDK camera API (camera2ndk) and an image reader (mediandk): frames of
// `WIDTH` x `HEIGHT` in YUV, whose luminance plane is all a QR decoder needs.
//
// The camera permission is asked at run time (through JNI) the first time,
// on the app's activity (the `Context` of ndk-context may not be one).

use std::{
    ffi::{c_void, CStr},
    ptr::{self, null_mut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{bail, Context as _};
use k5gui::scanner::{Frame, OnScan, Scan, Scanner};
use ndk_sys::*;

// ndk-sys declares the camera API but does not link it.
#[link(name = "camera2ndk")]
extern "C" {}

/// Size of the frames: enough detail for a ticket's QR code on a screen.
const WIDTH: i32 = 1280;
const HEIGHT: i32 = 720;
/// How long to wait for the user to grant the camera permission.
const PERMISSION_WAIT: Duration = Duration::from_secs(60);
const CAMERA_PERMISSION: &str = "android.permission.CAMERA";

/// The camera of the phone, as a [`Scanner`].
pub struct CameraScanner {
    /// The app, whose activity asks for the camera permission (its
    /// reference is valid while this is kept).
    app: slint::android::AndroidApp,
    /// The thread reading frames, and its stop flag.
    running: Option<(Arc<AtomicBool>, thread::JoinHandle<()>)>,
}

impl CameraScanner {
    pub fn new(app: slint::android::AndroidApp) -> Self {
        Self { app, running: None }
    }
}

impl Scanner for CameraScanner {
    fn start(&mut self, mut on_scan: OnScan) {
        self.stop();
        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let app = self.app.clone();
        let handle = thread::spawn(move || {
            if let Err(e) = scan(&app, &flag, &mut on_scan) {
                log::warn!("camera: {e:#}");
                on_scan(Scan::Failed(format!("{e:#}")));
            }
        });
        self.running = Some((running, handle));
    }

    fn stop(&mut self) {
        if let Some((running, handle)) = self.running.take() {
            running.store(false, Ordering::Relaxed);
            let _ = handle.join();
        }
    }
}

/// Sends the camera's frames to `on_scan` while `running`.
fn scan(
    app: &slint::android::AndroidApp,
    running: &AtomicBool,
    on_scan: &mut OnScan,
) -> anyhow::Result<()> {
    permission::ensure(app, running)?;
    if !running.load(Ordering::Relaxed) {
        return Ok(());
    }

    let camera = Camera::open()?;
    log::info!("camera open, rotation {}", camera.rotation);
    let (mut frames, mut waits, mut last_report) = (0u64, 0u64, Instant::now());
    while running.load(Ordering::Relaxed) {
        match camera.latest_image()? {
            Some(image) => {
                let frame = image.frame(camera.rotation)?;
                if frames == 0 {
                    log::info!(
                        "first frame: {}x{}, stride {}, {} bytes",
                        frame.width,
                        frame.height,
                        frame.stride,
                        frame.luma.len()
                    );
                }
                let started = Instant::now();
                on_scan(Scan::Frame(frame));
                frames += 1;
                if last_report.elapsed() > Duration::from_secs(5) {
                    log::info!(
                        "{frames} frames ({waits} waits), last took {} ms",
                        started.elapsed().as_millis()
                    );
                    last_report = Instant::now();
                }
            }
            None => {
                waits += 1;
                if waits % 250 == 0 {
                    log::info!("{frames} frames, {waits} waits: no frame yet");
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }

    Ok(())
}

/// Fails with `what` unless the camera call succeeded.
fn check(status: camera_status_t, what: &str) -> anyhow::Result<()> {
    if status != camera_status_t::ACAMERA_OK {
        bail!("{what} failed ({})", status.0);
    }
    Ok(())
}

/// Fails with `what` unless the media call succeeded.
fn check_media(status: media_status_t, what: &str) -> anyhow::Result<()> {
    if status != media_status_t::AMEDIA_OK {
        bail!("{what} failed ({})", status.0);
    }
    Ok(())
}

/// An open camera, streaming to an image reader. Everything is released,
/// in reverse order, when dropped.
struct Camera {
    manager: *mut ACameraManager,
    device: *mut ACameraDevice,
    reader: *mut AImageReader,
    container: *mut ACaptureSessionOutputContainer,
    output: *mut ACaptureSessionOutput,
    target: *mut ACameraOutputTarget,
    request: *mut ACaptureRequest,
    session: *mut ACameraCaptureSession,
    /// Callbacks the camera may still call: kept until the end.
    _device_callbacks: Box<ACameraDevice_StateCallbacks>,
    _session_callbacks: Box<ACameraCaptureSession_stateCallbacks>,
    /// Clockwise rotation that shows the frames upright.
    rotation: u32,
}

unsafe extern "C" fn on_device_state(_: *mut c_void, _: *mut ACameraDevice) {}
unsafe extern "C" fn on_device_error(_: *mut c_void, _: *mut ACameraDevice, error: i32) {
    log::warn!("camera error {error}");
}
unsafe extern "C" fn on_session_state(_: *mut c_void, _: *mut ACameraCaptureSession) {}

impl Camera {
    /// Opens the back camera (or the first one) and starts streaming.
    fn open() -> anyhow::Result<Self> {
        let mut camera = Camera {
            manager: unsafe { ACameraManager_create() },
            device: null_mut(),
            reader: null_mut(),
            container: null_mut(),
            output: null_mut(),
            target: null_mut(),
            request: null_mut(),
            session: null_mut(),
            _device_callbacks: Box::new(ACameraDevice_StateCallbacks {
                context: null_mut(),
                onDisconnected: Some(on_device_state),
                onError: Some(on_device_error),
            }),
            _session_callbacks: Box::new(ACameraCaptureSession_stateCallbacks {
                context: null_mut(),
                onClosed: Some(on_session_state),
                onReady: Some(on_session_state),
                onActive: Some(on_session_state),
            }),
            rotation: 0,
        };
        if camera.manager.is_null() {
            bail!("no camera manager");
        }
        // From here, dropping `camera` releases what was set up.
        unsafe { camera.start()? };

        Ok(camera)
    }

    /// Sets up the camera, the reader and the capture session.
    unsafe fn start(&mut self) -> anyhow::Result<()> {
        let (id, rotation) = self.back_camera()?;
        self.rotation = rotation;

        let callbacks: *mut ACameraDevice_StateCallbacks = &mut *self._device_callbacks;
        check(
            ACameraManager_openCamera(self.manager, id.as_ptr(), callbacks, &mut self.device),
            "opening the camera",
        )?;

        check_media(
            AImageReader_new(
                WIDTH,
                HEIGHT,
                AIMAGE_FORMATS::AIMAGE_FORMAT_YUV_420_888.0 as i32,
                2,
                &mut self.reader,
            ),
            "creating the image reader",
        )?;
        let mut window: *mut ANativeWindow = null_mut();
        check_media(
            AImageReader_getWindow(self.reader, &mut window),
            "getting the reader's window",
        )?;

        check(
            ACaptureSessionOutputContainer_create(&mut self.container),
            "creating the outputs",
        )?;
        check(
            ACaptureSessionOutput_create(window, &mut self.output),
            "creating the output",
        )?;
        check(
            ACaptureSessionOutputContainer_add(self.container, self.output),
            "adding the output",
        )?;
        check(
            ACameraOutputTarget_create(window, &mut self.target),
            "creating the target",
        )?;
        check(
            ACameraDevice_createCaptureRequest(
                self.device,
                ACameraDevice_request_template::TEMPLATE_PREVIEW,
                &mut self.request,
            ),
            "creating the request",
        )?;
        check(
            ACaptureRequest_addTarget(self.request, self.target),
            "adding the target",
        )?;
        // Keeps focusing, as the code gets closer or further.
        let focus = acamera_metadata_enum_acamera_control_af_mode::ACAMERA_CONTROL_AF_MODE_CONTINUOUS_PICTURE
            .0 as u8;
        check(
            ACaptureRequest_setEntry_u8(
                self.request,
                acamera_metadata_tag::ACAMERA_CONTROL_AF_MODE.0,
                1,
                &focus,
            ),
            "setting the focus mode",
        )?;

        check(
            ACameraDevice_createCaptureSession(
                self.device,
                self.container,
                &*self._session_callbacks,
                &mut self.session,
            ),
            "creating the session",
        )?;
        let mut requests = [self.request];
        check(
            ACameraCaptureSession_setRepeatingRequest(
                self.session,
                null_mut(),
                1,
                requests.as_mut_ptr(),
                null_mut(),
            ),
            "starting the capture",
        )
    }

    /// The id of the back camera (else the first), and the rotation of its
    /// sensor.
    unsafe fn back_camera(&self) -> anyhow::Result<(std::ffi::CString, u32)> {
        let mut list: *mut ACameraIdList = null_mut();
        check(
            ACameraManager_getCameraIdList(self.manager, &mut list),
            "listing the cameras",
        )?;
        let ids: Vec<std::ffi::CString> = (0..(*list).numCameras as usize)
            .map(|i| CStr::from_ptr(*(*list).cameraIds.add(i)).to_owned())
            .collect();
        ACameraManager_deleteCameraIdList(list);

        let mut chosen = None;
        for id in &ids {
            let mut metadata: *mut ACameraMetadata = null_mut();
            if ACameraManager_getCameraCharacteristics(self.manager, id.as_ptr(), &mut metadata)
                != camera_status_t::ACAMERA_OK
            {
                continue;
            }
            let facing = entry(metadata, acamera_metadata_tag::ACAMERA_LENS_FACING)
                .map(|entry| *entry.data.u8_);
            let rotation = entry(metadata, acamera_metadata_tag::ACAMERA_SENSOR_ORIENTATION)
                .map_or(0, |entry| *entry.data.i32_);
            ACameraMetadata_free(metadata);

            let back = facing
                == Some(
                    acamera_metadata_enum_acamera_lens_facing::ACAMERA_LENS_FACING_BACK.0 as u8,
                );
            if back || chosen.is_none() {
                chosen = Some((id.clone(), rotation.rem_euclid(360) as u32));
            }
            if back {
                break;
            }
        }

        chosen.context("no camera")
    }

    /// The newest frame, if a new one arrived.
    fn latest_image(&self) -> anyhow::Result<Option<Image>> {
        let mut image: *mut AImage = null_mut();
        let status = unsafe { AImageReader_acquireLatestImage(self.reader, &mut image) };
        if status == media_status_t::AMEDIA_OK && !image.is_null() {
            return Ok(Some(Image(image)));
        }
        if status != media_status_t::AMEDIA_IMGREADER_NO_BUFFER_AVAILABLE {
            bail!("reading a frame failed ({})", status.0);
        }
        Ok(None)
    }
}

/// A metadata entry of a camera, if it has it.
unsafe fn entry(
    metadata: *const ACameraMetadata,
    tag: acamera_metadata_tag,
) -> Option<ACameraMetadata_const_entry> {
    let mut entry: ACameraMetadata_const_entry = std::mem::zeroed();
    (ACameraMetadata_getConstEntry(metadata, tag.0, &mut entry) == camera_status_t::ACAMERA_OK
        && entry.count > 0)
        .then_some(entry)
}

impl Drop for Camera {
    fn drop(&mut self) {
        unsafe {
            if !self.session.is_null() {
                ACameraCaptureSession_stopRepeating(self.session);
                ACameraCaptureSession_close(self.session);
            }
            if !self.request.is_null() {
                ACaptureRequest_free(self.request);
            }
            if !self.target.is_null() {
                ACameraOutputTarget_free(self.target);
            }
            if !self.output.is_null() {
                ACaptureSessionOutput_free(self.output);
            }
            if !self.container.is_null() {
                ACaptureSessionOutputContainer_free(self.container);
            }
            if !self.device.is_null() {
                ACameraDevice_close(self.device);
            }
            if !self.reader.is_null() {
                AImageReader_delete(self.reader);
            }
            ACameraManager_delete(self.manager);
        }
    }
}

/// A frame from the reader, given back when dropped.
struct Image(*mut AImage);

impl Image {
    /// Its luminance plane, as a frame rotated by `rotation` to be upright.
    fn frame(&self, rotation: u32) -> anyhow::Result<Frame<'_>> {
        let (mut width, mut height, mut stride, mut length) = (0, 0, 0, 0);
        let mut data: *mut u8 = ptr::null_mut();
        unsafe {
            check_media(AImage_getWidth(self.0, &mut width), "frame width")?;
            check_media(AImage_getHeight(self.0, &mut height), "frame height")?;
            check_media(
                AImage_getPlaneRowStride(self.0, 0, &mut stride),
                "frame stride",
            )?;
            check_media(
                AImage_getPlaneData(self.0, 0, &mut data, &mut length),
                "frame data",
            )?;
        }
        if data.is_null() || width <= 0 || height <= 0 || stride < width || length <= 0 {
            bail!("empty frame");
        }

        Ok(Frame {
            // Valid until the image is deleted, when `self` is dropped.
            luma: unsafe { std::slice::from_raw_parts(data, length as usize) },
            width: width as usize,
            height: height as usize,
            stride: stride as usize,
            rotation,
        })
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        unsafe { AImage_delete(self.0) };
    }
}

/// The camera permission, asked at run time through JNI.
mod permission {
    use super::*;
    use jni::{
        jni_sig, jni_str,
        objects::{JObject, JValue},
        refs::Global,
    };
    use slint::android::AndroidApp;

    /// Waits until the app may use the camera, asking the user first. Ends
    /// early (without error) when `running` turns false.
    pub fn ensure(app: &AndroidApp, running: &AtomicBool) -> anyhow::Result<()> {
        if granted(app)? {
            return Ok(());
        }
        request(app)?;
        let deadline = Instant::now() + PERMISSION_WAIT;
        while running.load(Ordering::Relaxed) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(300));
            if granted(app)? {
                return Ok(());
            }
        }
        if running.load(Ordering::Relaxed) {
            bail!("no permission to use the camera");
        }

        Ok(())
    }

    /// Runs `f` with the Java VM and the app's activity.
    fn with_activity<T>(
        app: &AndroidApp,
        f: impl FnOnce(&mut jni::Env, &JObject) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        if app.vm_as_ptr().is_null() || app.activity_as_ptr().is_null() {
            bail!("no Android activity");
        }
        // Safety: a non-null Java VM pointer, from the app.
        let vm = unsafe { jni::JavaVM::from_raw(app.vm_as_ptr().cast()) };
        vm.attach_current_thread(|env| -> anyhow::Result<T> {
            // Safety: a global reference to the activity, valid while `app`
            // is; the cast does not own it, so it is never deleted here.
            let raw: jni::sys::jobject = app.activity_as_ptr().cast();
            let activity = unsafe { env.as_cast_raw::<Global<JObject>>(&raw) }
                .context("invalid Android context")?;
            f(env, &activity)
        })
    }

    fn granted(app: &AndroidApp) -> anyhow::Result<bool> {
        with_activity(app, |env, activity| {
            let permission = env.new_string(CAMERA_PERMISSION)?;
            let result = env
                .call_method(
                    activity,
                    jni_str!("checkSelfPermission"),
                    jni_sig!("(Ljava/lang/String;)I"),
                    &[JValue::Object(&permission)],
                )?
                .i()?;
            // PackageManager.PERMISSION_GRANTED
            Ok(result == 0)
        })
    }

    fn request(app: &AndroidApp) -> anyhow::Result<()> {
        with_activity(app, |env, activity| {
            let permission = env.new_string(CAMERA_PERMISSION)?;
            let permissions = env.new_object_array(1, jni_str!("java/lang/String"), &permission)?;
            env.call_method(
                activity,
                jni_str!("requestPermissions"),
                jni_sig!("([Ljava/lang/String;I)V"),
                &[JValue::Object(&permissions), JValue::Int(1)],
            )?;
            Ok(())
        })
    }
}

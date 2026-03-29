use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cadeau::xmf::recorder::Recorder as XmfRecorder;
use ironrdp_connector::legacy;
use ironrdp_core::WriteBuf;
use ironrdp_graphics::image_processing::PixelFormat;
use ironrdp_pdu::geometry::{InclusiveRectangle, Rectangle as _};
use ironrdp_pdu::rdp::capability_sets::CapabilitySet;
use ironrdp_pdu::rdp::headers::ShareControlPdu;
use ironrdp_session::fast_path::{Processor as FastPathProcessor, ProcessorBuilder, UpdateKind};
use ironrdp_session::image::DecodedImage;

use crate::config::Conf;
use crate::interceptor::Inspector;
use crate::rdp_gfx::{GfxConfig, GfxFilter};
use crate::recording::RecordingMessageSender;
use crate::token::RecordingFileType;
use crate::wrapped_gfx::WrappedGfxExtractor;

pub(crate) const PLAYBACK_BOOTSTRAP_TRACE_SCHEMA_VERSION: u32 = 1;

#[derive(Debug)]
struct PlaybackBootstrapTraceInner {
    session_id: uuid::Uuid,
    started_at: Instant,
    seq: AtomicU64,
    thread_started: AtomicBool,
    first_packet: AtomicBool,
    first_fastpath_update: AtomicBool,
    first_wrapped_gfx_update: AtomicBool,
    update_none: AtomicBool,
    first_chunk_appended: AtomicBool,
}

#[derive(Clone, Debug)]
pub(crate) struct PlaybackBootstrapTrace {
    inner: Arc<PlaybackBootstrapTraceInner>,
}

impl PlaybackBootstrapTrace {
    pub(crate) fn new(session_id: uuid::Uuid) -> Self {
        Self {
            inner: Arc::new(PlaybackBootstrapTraceInner {
                session_id,
                started_at: Instant::now(),
                seq: AtomicU64::new(0),
                thread_started: AtomicBool::new(false),
                first_packet: AtomicBool::new(false),
                first_fastpath_update: AtomicBool::new(false),
                first_wrapped_gfx_update: AtomicBool::new(false),
                update_none: AtomicBool::new(false),
                first_chunk_appended: AtomicBool::new(false),
            }),
        }
    }

    fn next_seq(&self) -> u64 {
        self.inner.seq.fetch_add(1, Ordering::SeqCst).saturating_add(1)
    }

    fn monotonic_ns(&self) -> u64 {
        let nanos = self.inner.started_at.elapsed().as_nanos();
        u64::try_from(nanos).unwrap_or(u64::MAX)
    }

    pub(crate) fn emit(
        &self,
        thread: &'static str,
        event: &'static str,
        status: &'static str,
        source: &'static str,
        byte_len: Option<usize>,
        error: Option<&str>,
    ) {
        let seq = self.next_seq();
        info!(
            session_id = %self.inner.session_id,
            bootstrap_schema_version = PLAYBACK_BOOTSTRAP_TRACE_SCHEMA_VERSION,
            bootstrap_seq = seq,
            bootstrap_ts_ns = self.monotonic_ns(),
            bootstrap_thread = thread,
            bootstrap_event = event,
            bootstrap_status = status,
            bootstrap_source = source,
            bootstrap_byte_len = u64::try_from(byte_len.unwrap_or(0)).unwrap_or(u64::MAX),
            bootstrap_error = error.unwrap_or(""),
            "Playback bootstrap trace"
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_once(
        &self,
        gate: &AtomicBool,
        thread: &'static str,
        event: &'static str,
        status: &'static str,
        source: &'static str,
        byte_len: Option<usize>,
        error: Option<&str>,
    ) {
        if gate
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.emit(thread, event, status, source, byte_len, error);
        }
    }

    pub(crate) fn emit_thread_started(&self) {
        self.emit_once(
            &self.inner.thread_started,
            "playback-thread",
            "playback.thread.start",
            "ok",
            "thread",
            None,
            None,
        );
    }

    pub(crate) fn emit_first_packet(&self, source: &'static str, byte_len: usize) {
        self.emit_once(
            &self.inner.first_packet,
            "playback-thread",
            "playback.thread.first_packet",
            "ok",
            source,
            Some(byte_len),
            None,
        );
    }

    pub(crate) fn emit_first_fastpath_update(&self, source: &'static str) {
        self.emit_once(
            &self.inner.first_fastpath_update,
            "playback-thread",
            "playback.update.fastpath.first",
            "ok",
            source,
            None,
            None,
        );
    }

    pub(crate) fn emit_first_wrapped_gfx_update(&self, source: &'static str) {
        self.emit_once(
            &self.inner.first_wrapped_gfx_update,
            "playback-thread",
            "playback.update.wrapped_gfx.first",
            "ok",
            source,
            None,
            None,
        );
    }

    pub(crate) fn emit_first_chunk_appended(&self) {
        self.emit_once(
            &self.inner.first_chunk_appended,
            "playback-thread",
            "playback.chunk.appended.first",
            "ok",
            "recording",
            None,
            None,
        );
    }

    pub(crate) fn emit_update_none_if_needed(&self) {
        if self.inner.first_fastpath_update.load(Ordering::SeqCst)
            || self.inner.first_wrapped_gfx_update.load(Ordering::SeqCst)
        {
            return;
        }

        self.emit_once(
            &self.inner.update_none,
            "playback-thread",
            "playback.update.none",
            "ok",
            "none",
            None,
            None,
        );
    }
}

#[derive(Debug)]
enum PlaybackPacket {
    Client(Vec<u8>),
    Server(Vec<u8>),
}

#[derive(Debug)]
pub struct RdpPlaybackProducer {
    sender: Option<mpsc::Sender<PlaybackPacket>>,
    thread: Option<JoinHandle<()>>,
    recordings: RecordingMessageSender,
    session_id: uuid::Uuid,
}

impl RdpPlaybackProducer {
    pub(crate) async fn maybe_start(
        conf: &Arc<Conf>,
        recordings: RecordingMessageSender,
        session_id: uuid::Uuid,
        disconnected_ttl: Duration,
        trace: PlaybackBootstrapTrace,
    ) -> anyhow::Result<Self> {
        let xmf_library = conf
            .get_lib_xmf_path()
            .context("libxmf path is not configured for proxy-owned RDP playback")?;
        ObserverXmfRecordingBackend::prepare_library(xmf_library.as_std_path())?;

        let recording_path = recordings
            .begin_external_recording(session_id, RecordingFileType::WebM, disconnected_ttl)
            .await
            .context("reserve proxy-owned playback recording path")?;

        let (sender, receiver) = mpsc::channel::<PlaybackPacket>();
        let recording_path_for_thread = recording_path.into_std_path_buf();
        let recordings_for_thread = recordings.clone();
        let trace_for_thread = trace.clone();
        let thread = match thread::Builder::new()
            .name(format!("rdp-playback-{session_id}"))
            .spawn(move || {
                playback_thread(
                    receiver,
                    recording_path_for_thread,
                    recordings_for_thread,
                    session_id,
                    trace_for_thread,
                )
            }) {
            Ok(thread) => thread,
            Err(error) => {
                recordings
                    .end_external_recording(session_id)
                    .await
                    .context("cleanup proxy-owned playback recording after thread spawn failure")?;
                return Err(anyhow::Error::new(error).context("spawn proxy-owned playback thread"));
            }
        };

        Ok(Self {
            sender: Some(sender),
            thread: Some(thread),
            recordings,
            session_id,
        })
    }

    pub fn inspector(&self) -> anyhow::Result<RdpPlaybackInspector> {
        Ok(RdpPlaybackInspector {
            sender: self
                .sender
                .as_ref()
                .context("proxy-owned playback sender is already closed")?
                .clone(),
            side: PlaybackPacketSide::Server,
        })
    }

    pub fn client_inspector(&self) -> anyhow::Result<RdpPlaybackInspector> {
        Ok(RdpPlaybackInspector {
            sender: self
                .sender
                .as_ref()
                .context("proxy-owned playback sender is already closed")?
                .clone(),
            side: PlaybackPacketSide::Client,
        })
    }

    pub fn submit_server_bytes(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let sender = self
            .sender
            .as_ref()
            .context("proxy-owned playback sender is already closed")?;
        sender
            .send(PlaybackPacket::Server(bytes.to_vec()))
            .context("proxy-owned playback thread terminated")
    }

    pub fn submit_client_bytes(&self, bytes: &[u8]) -> anyhow::Result<()> {
        let sender = self
            .sender
            .as_ref()
            .context("proxy-owned playback sender is already closed")?;
        sender
            .send(PlaybackPacket::Client(bytes.to_vec()))
            .context("proxy-owned playback thread terminated")
    }

    pub async fn finish(mut self) -> anyhow::Result<()> {
        let _ = self.sender.take();

        let thread_result = match self.thread.take() {
            Some(thread) => thread
                .join()
                .map_err(|error| anyhow::anyhow!("proxy-owned playback thread panicked: {error:?}")),
            None => Ok(()),
        };

        let disconnect_result = self
            .recordings
            .end_external_recording(self.session_id)
            .await
            .context("finalize proxy-owned playback recording");

        thread_result?;
        disconnect_result
    }
}

pub struct RdpPlaybackInspector {
    sender: mpsc::Sender<PlaybackPacket>,
    side: PlaybackPacketSide,
}

#[derive(Clone, Copy)]
enum PlaybackPacketSide {
    Client,
    Server,
}

impl Inspector for RdpPlaybackInspector {
    fn inspect_bytes(&mut self, bytes: &[u8]) -> anyhow::Result<()> {
        self.sender
            .send(match self.side {
                PlaybackPacketSide::Client => PlaybackPacket::Client(bytes.to_vec()),
                PlaybackPacketSide::Server => PlaybackPacket::Server(bytes.to_vec()),
            })
            .context("proxy-owned playback thread terminated")
    }
}

fn playback_thread(
    receiver: mpsc::Receiver<PlaybackPacket>,
    recording_path: PathBuf,
    recordings: RecordingMessageSender,
    session_id: uuid::Uuid,
    trace: PlaybackBootstrapTrace,
) {
    let mut observer = PlaybackObserver::new(session_id);
    let backend = ObserverXmfRecordingBackend::new(recording_path.clone());

    trace.emit_thread_started();

    debug!(
        session.id = %session_id,
        path = %recording_path.display(),
        "Proxy-owned RDP playback thread started",
    );

    while let Ok(packet) = receiver.recv() {
        let (source, byte_len) = match &packet {
            PlaybackPacket::Client(bytes) => ("client", bytes.len()),
            PlaybackPacket::Server(bytes) => ("server", bytes.len()),
        };
        trace.emit_first_packet(source, byte_len);

        let updates = observer.observe(packet, &trace);
        if updates.is_empty() {
            continue;
        }

        let mut appended_chunk = false;
        for update in updates {
            match backend.submit_rgba_update(
                update.surface_width,
                update.surface_height,
                u32::from(update.rectangle.left),
                u32::from(update.rectangle.top),
                u32::from(update.rectangle.width()),
                u32::from(update.rectangle.height()),
                update.rgba_data,
            ) {
                Ok(()) => appended_chunk = true,
                Err(error) => {
                    warn!(
                        session.id = %session_id,
                        error = format!("{error:#}"),
                        source = update.source,
                        "Proxy-owned playback update was rejected",
                    );
                }
            }
        }

        if appended_chunk {
            trace.emit_first_chunk_appended();
            if let Err(error) = recordings.new_chunk_appended(session_id) {
                warn!(
                    session.id = %session_id,
                    error = format!("{error:#}"),
                    "Failed to notify JREC listeners about proxy-owned playback data",
                );
            }
        }
    }

    trace.emit_update_none_if_needed();
    observer.log_summary(session_id);
    backend.finish();

    debug!(
        session.id = %session_id,
        path = %recording_path.display(),
        "Proxy-owned RDP playback thread stopped",
    );
}

struct PlaybackObserver {
    fastpath: ObserverFastPath,
    wrapped_gfx: WrappedGfxExtractor,
    gfx: GfxFilter,
}

impl PlaybackObserver {
    fn new(session_id: uuid::Uuid) -> Self {
        Self {
            fastpath: ObserverFastPath::new(),
            wrapped_gfx: WrappedGfxExtractor::new(),
            gfx: GfxFilter::new(GfxConfig::default(), session_id.to_string()),
        }
    }

    fn observe(&mut self, packet: PlaybackPacket, trace: &PlaybackBootstrapTrace) -> Vec<FastPathSurfaceUpdate> {
        match packet {
            PlaybackPacket::Client(bytes) => {
                self.wrapped_gfx.observe_client_packet(&bytes);
                Vec::new()
            }
            PlaybackPacket::Server(bytes) => {
                let mut updates = self.fastpath.observe_server_packet(&bytes);
                if let Some(first_fastpath_update) = updates.first() {
                    trace.emit_first_fastpath_update(first_fastpath_update.source);
                }
                let wrapped_gfx_pdus = self.wrapped_gfx.observe_server_packet(&bytes);

                for pdu in wrapped_gfx_pdus {
                    match self.gfx.observe_bare_server_pdu(&pdu) {
                        Ok(true) => {}
                        Ok(false) => {
                            debug!(
                                pdu_len = pdu.len(),
                                "Wrapped graphics payload was not a bare RDPEGFX server PDU"
                            );
                        }
                        Err(error) => {
                            warn!(
                                error = format!("{error:#}"),
                                pdu_len = pdu.len(),
                                "Failed to decode wrapped RDPEGFX payload into playback surfaces",
                            );
                        }
                    }
                }

                let wrapped_updates = self.gfx.drain_surface_updates();
                if let Some(first_wrapped_update) = wrapped_updates.first() {
                    trace.emit_first_wrapped_gfx_update(first_wrapped_update.source);
                }

                updates.extend(wrapped_updates.into_iter().map(|update| FastPathSurfaceUpdate {
                    source: update.source,
                    surface_width: update.surface_width,
                    surface_height: update.surface_height,
                    rectangle: update.rectangle,
                    rgba_data: update.rgba_data,
                }));

                updates
            }
        }
    }

    fn log_summary(&mut self, session_id: uuid::Uuid) {
        self.wrapped_gfx.log_summary(session_id);
        self.gfx.log_summary(session_id);
    }
}

#[derive(Debug)]
struct FastPathSurfaceUpdate {
    source: &'static str,
    surface_width: u32,
    surface_height: u32,
    rectangle: InclusiveRectangle,
    rgba_data: Vec<u8>,
}

#[derive(Default)]
struct ObserverFastPath {
    server_pdu_buffer: Vec<u8>,
    desktop_size: Option<(u16, u16)>,
    io_channel_id: Option<u16>,
    processor: Option<FastPathProcessor>,
    image: Option<DecodedImage>,
}

impl ObserverFastPath {
    fn new() -> Self {
        Self::default()
    }

    fn observe_server_packet(&mut self, data: &[u8]) -> Vec<FastPathSurfaceUpdate> {
        let mut updates = Vec::new();
        self.server_pdu_buffer.extend_from_slice(data);

        while let Some((frame, action)) = Self::take_next_rdp_frame(&mut self.server_pdu_buffer) {
            match action {
                ironrdp_pdu::Action::X224 => self.observe_x224_frame(&frame),
                ironrdp_pdu::Action::FastPath => updates.extend(self.observe_fastpath_frame(&frame)),
            }
        }

        updates
    }

    fn observe_x224_frame(&mut self, frame: &[u8]) {
        let Ok(data_ctx) = legacy::decode_send_data_indication(frame) else {
            return;
        };
        let Ok(share_control_ctx) = legacy::decode_share_control(data_ctx) else {
            return;
        };

        let ShareControlPdu::ServerDemandActive(server_demand_active) = share_control_ctx.pdu else {
            return;
        };

        let desktop_size = server_demand_active
            .pdu
            .capability_sets
            .iter()
            .find_map(|capability| match capability {
                CapabilitySet::Bitmap(bitmap) => Some((bitmap.desktop_width, bitmap.desktop_height)),
                _ => None,
            });

        let Some((width, height)) = desktop_size else {
            return;
        };

        if self.desktop_size == Some((width, height)) && self.io_channel_id == Some(share_control_ctx.channel_id) {
            return;
        }

        self.desktop_size = Some((width, height));
        self.io_channel_id = Some(share_control_ctx.channel_id);
        self.processor = Some(
            ProcessorBuilder {
                io_channel_id: share_control_ctx.channel_id,
                user_channel_id: 0,
                enable_server_pointer: true,
                pointer_software_rendering: true,
            }
            .build(),
        );
        self.image = Some(DecodedImage::new(PixelFormat::RgbA32, width, height));

        info!(
            io_channel_id = share_control_ctx.channel_id,
            desktop_width = width,
            desktop_height = height,
            "Initialized passive FastPath observer from ServerDemandActive",
        );
    }

    fn observe_fastpath_frame(&mut self, frame: &[u8]) -> Vec<FastPathSurfaceUpdate> {
        let Some(processor) = self.processor.as_mut() else {
            return Vec::new();
        };
        let Some(image) = self.image.as_mut() else {
            return Vec::new();
        };

        let mut output = WriteBuf::new();
        let processor_updates = match processor.process(image, frame, &mut output) {
            Ok(processor_updates) => processor_updates,
            Err(error) => {
                warn!(
                    error = format!("{error:#}"),
                    frame_len = frame.len(),
                    "Passive FastPath observer failed to process server frame",
                );
                return Vec::new();
            }
        };

        if !output.filled().is_empty() {
            debug!(
                ignored_response_len = output.filled().len(),
                "Passive FastPath observer ignored synthesized response bytes",
            );
        }

        let mut surface_updates = Vec::new();
        for processor_update in processor_updates {
            let UpdateKind::Region(rectangle) = processor_update else {
                continue;
            };

            if rectangle.width() == 0 || rectangle.height() == 0 {
                continue;
            }

            surface_updates.push(FastPathSurfaceUpdate {
                source: "fastpath_region",
                surface_width: u32::from(image.width()),
                surface_height: u32::from(image.height()),
                rgba_data: copy_tight_rgba_region(image, &rectangle),
                rectangle,
            });
        }

        surface_updates
    }

    fn take_next_rdp_frame(buffer: &mut Vec<u8>) -> Option<(Vec<u8>, ironrdp_pdu::Action)> {
        match ironrdp_pdu::find_size(buffer) {
            Ok(Some(info)) => {
                if buffer.len() < info.length {
                    return None;
                }

                let frame = buffer.drain(..info.length).collect();
                Some((frame, info.action))
            }
            Ok(None) => None,
            Err(error) => {
                let prefix_len = buffer.len().min(16);
                let prefix = buffer[..prefix_len]
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                warn!(
                    buffer_len = buffer.len(),
                    prefix_hex = %prefix,
                    error = %error,
                    "Passive FastPath observer dropped an invalid RDP frame prefix",
                );
                buffer.clear();
                None
            }
        }
    }
}

fn copy_tight_rgba_region(image: &DecodedImage, rectangle: &InclusiveRectangle) -> Vec<u8> {
    let width = usize::from(rectangle.width());
    let height = usize::from(rectangle.height());
    let row_len = width * 4;
    let stride = image.stride();
    let mut rgba = vec![0; row_len * height];

    for row in 0..height {
        let src_offset = (usize::from(rectangle.top) + row) * stride + usize::from(rectangle.left) * 4;
        let dst_offset = row * row_len;
        rgba[dst_offset..dst_offset + row_len].copy_from_slice(&image.data()[src_offset..src_offset + row_len]);
    }

    rgba
}

#[derive(Clone)]
struct ObserverXmfRecordingBackend {
    inner: Arc<ObserverXmfRecordingBackendInner>,
}

struct ObserverXmfRecordingBackendInner {
    recording_path: PathBuf,
    recorder: Arc<Mutex<ObserverXmfRecorderState>>,
    timeout_state: Arc<Mutex<XmfTimeoutState>>,
    timeout_condvar: Arc<Condvar>,
    timeout_thread: Mutex<Option<JoinHandle<()>>>,
}

#[derive(Default)]
struct ObserverXmfRecorderState {
    recorder: Option<XmfRecorder>,
    frame_size: Option<(u32, u32)>,
    surface_rgba: Vec<u8>,
    submitted_frame_count: u64,
    last_current_time_ms: Option<u64>,
}

// SAFETY: The libxmf recorder handle is only accessed behind a mutex and is never used concurrently.
unsafe impl Send for ObserverXmfRecorderState {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum XmfTimeoutState {
    Idle,
    Finish,
}

static XMF_LIBRARY_PATH: OnceLock<String> = OnceLock::new();

impl ObserverXmfRecordingBackend {
    fn prepare_library(library_path: &Path) -> anyhow::Result<()> {
        let resolved_path = std::fs::canonicalize(library_path)
            .unwrap_or_else(|_| library_path.to_path_buf())
            .to_string_lossy()
            .into_owned();

        if let Some(existing_path) = XMF_LIBRARY_PATH.get() {
            anyhow::ensure!(
                existing_path == &resolved_path,
                "libxmf is already initialized from {}, cannot switch to {} in the same process",
                existing_path,
                resolved_path
            );
            return Ok(());
        }

        // SAFETY: libxmf initialization is process-global and guarded by `XMF_LIBRARY_PATH`,
        // so we only initialize once for a single resolved library path in this process.
        unsafe { cadeau::xmf::init(&resolved_path) }.with_context(|| format!("load libxmf from {}", resolved_path))?;
        let _ = XMF_LIBRARY_PATH.set(resolved_path);
        Ok(())
    }

    fn new(recording_path: PathBuf) -> Self {
        let recorder = Arc::new(Mutex::new(ObserverXmfRecorderState::default()));
        let timeout_state = Arc::new(Mutex::new(XmfTimeoutState::Idle));
        let timeout_condvar = Arc::new(Condvar::new());

        let timeout_thread = thread::spawn({
            let recorder = Arc::clone(&recorder);
            let timeout_state = Arc::clone(&timeout_state);
            let timeout_condvar = Arc::clone(&timeout_condvar);
            move || xmf_timeout_loop(recorder, timeout_state, timeout_condvar)
        });

        Self {
            inner: Arc::new(ObserverXmfRecordingBackendInner {
                recording_path,
                recorder,
                timeout_state,
                timeout_condvar,
                timeout_thread: Mutex::new(Some(timeout_thread)),
            }),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "surface and update geometry must be passed to the recorder"
    )]
    fn submit_rgba_update(
        &self,
        surface_width: u32,
        surface_height: u32,
        update_x: u32,
        update_y: u32,
        update_width: u32,
        update_height: u32,
        rgba_data: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut recorder_state = self
            .inner
            .recorder
            .lock()
            .expect("observer xmf recorder mutex poisoned");
        recorder_state.submit_rgba_update(
            &self.inner.recording_path,
            surface_width,
            surface_height,
            update_x,
            update_y,
            update_width,
            update_height,
            &rgba_data,
        )
    }

    fn finish(&self) {
        {
            let mut timeout_state = self
                .inner
                .timeout_state
                .lock()
                .expect("observer xmf timeout state mutex poisoned");
            *timeout_state = XmfTimeoutState::Finish;
            self.inner.timeout_condvar.notify_all();
        }

        if let Some(timeout_thread) = self
            .inner
            .timeout_thread
            .lock()
            .expect("observer xmf timeout thread mutex poisoned")
            .take()
        {
            let _ = timeout_thread.join();
        }

        let mut recorder_state = self
            .inner
            .recorder
            .lock()
            .expect("observer xmf recorder mutex poisoned");
        if recorder_state.submitted_frame_count == 0 {
            warn!(
                path = %self.inner.recording_path.display(),
                "libxmf observer recorder finished without any submitted frames",
            );
        }

        if let Some(mut recorder) = recorder_state.recorder.take() {
            let finish_time_ms = recorder_state.next_current_time_millis();
            recorder.set_current_time(finish_time_ms);
            recorder.timeout();
            drop(recorder);
        }

        if self.inner.recording_path.exists() {
            debug!(
                path = %self.inner.recording_path.display(),
                "Finalized observer WebM without post-processing repair",
            );
        }
    }
}

impl ObserverXmfRecorderState {
    #[expect(
        clippy::too_many_arguments,
        reason = "surface and update geometry must be passed through to libxmf"
    )]
    fn submit_rgba_update(
        &mut self,
        recording_path: &Path,
        surface_width: u32,
        surface_height: u32,
        update_x: u32,
        update_y: u32,
        update_width: u32,
        update_height: u32,
        rgba_data: &[u8],
    ) -> anyhow::Result<()> {
        self.ensure_initialized(recording_path, surface_width, surface_height)?;
        blit_rgba_update(
            &mut self.surface_rgba,
            surface_width,
            surface_height,
            update_x,
            update_y,
            update_width,
            update_height,
            rgba_data,
        )?;

        let frame_time_ms = self.next_current_time_millis();
        let recorder = self
            .recorder
            .as_mut()
            .context("libxmf recorder is unexpectedly missing after initialization")?;
        recorder.set_current_time(frame_time_ms);
        recorder
            .update_frame(
                &self.surface_rgba,
                0,
                0,
                surface_width as usize,
                surface_height as usize,
                surface_width.saturating_mul(4) as usize,
            )
            .context("submit full RGBA surface to libxmf recorder")?;
        self.submitted_frame_count = self.submitted_frame_count.saturating_add(1);

        Ok(())
    }

    fn ensure_initialized(
        &mut self,
        recording_path: &Path,
        surface_width: u32,
        surface_height: u32,
    ) -> anyhow::Result<()> {
        match self.frame_size {
            Some((existing_width, existing_height))
                if existing_width != surface_width || existing_height != surface_height =>
            {
                anyhow::bail!(
                    "libxmf observer recorder does not support surface resize within one recording (current {}x{}, new {}x{})",
                    existing_width,
                    existing_height,
                    surface_width,
                    surface_height
                );
            }
            None => {
                if let Some(parent) = recording_path.parent() {
                    std::fs::create_dir_all(parent)
                        .with_context(|| format!("create observer xmf recording directory {}", parent.display()))?;
                }

                let initial_time_ms = self.next_current_time_millis();
                let recorder = XmfRecorder::builder(surface_width as usize, surface_height as usize)
                    .frame_rate(10)
                    .current_time(initial_time_ms)
                    .init(recording_path)
                    .with_context(|| {
                        format!(
                            "initialize libxmf recorder at {} for {}x{} frames",
                            recording_path.display(),
                            surface_width,
                            surface_height
                        )
                    })?;

                self.recorder = Some(recorder);
                self.frame_size = Some((surface_width, surface_height));
                self.surface_rgba = vec![0; surface_width.saturating_mul(surface_height).saturating_mul(4) as usize];
            }
            Some(_) => {}
        }

        Ok(())
    }

    fn next_current_time_millis(&mut self) -> u64 {
        let now_ms = current_time_millis();
        let next_ms = self
            .last_current_time_ms
            .map(|last_ms| now_ms.max(last_ms.saturating_add(1)))
            .unwrap_or(now_ms);
        self.last_current_time_ms = Some(next_ms);
        next_ms
    }
}

impl Drop for ObserverXmfRecordingBackendInner {
    fn drop(&mut self) {
        {
            let mut timeout_state = self
                .timeout_state
                .lock()
                .expect("observer xmf timeout state mutex poisoned");
            *timeout_state = XmfTimeoutState::Finish;
            self.timeout_condvar.notify_all();
        }

        if let Some(timeout_thread) = self
            .timeout_thread
            .lock()
            .expect("observer xmf timeout thread mutex poisoned")
            .take()
        {
            let _ = timeout_thread.join();
        }
    }
}

fn xmf_timeout_loop(
    recorder: Arc<Mutex<ObserverXmfRecorderState>>,
    timeout_state: Arc<Mutex<XmfTimeoutState>>,
    timeout_condvar: Arc<Condvar>,
) {
    loop {
        let timeout_ms = {
            let mut recorder_state = recorder.lock().expect("observer xmf recorder mutex poisoned");
            recorder_state
                .recorder
                .as_mut()
                .map(|recorder| recorder.get_timeout())
                .unwrap_or(250)
        };

        let state = timeout_state.lock().expect("observer xmf timeout state mutex poisoned");
        match *state {
            XmfTimeoutState::Finish => break,
            XmfTimeoutState::Idle => {}
        }

        let (state, wait_result) = timeout_condvar
            .wait_timeout(state, Duration::from_millis(u64::from(timeout_ms)))
            .expect("observer xmf timeout condvar wait failed");

        match *state {
            XmfTimeoutState::Finish => break,
            XmfTimeoutState::Idle if wait_result.timed_out() => {
                drop(state);
                let mut recorder_state = recorder.lock().expect("observer xmf recorder mutex poisoned");
                let timeout_time_ms = recorder_state.next_current_time_millis();
                if let Some(recorder) = recorder_state.recorder.as_mut() {
                    recorder.set_current_time(timeout_time_ms);
                    recorder.timeout();
                }
            }
            XmfTimeoutState::Idle => {}
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "blit helper needs both surface and update geometry"
)]
fn blit_rgba_update(
    surface_rgba: &mut [u8],
    surface_width: u32,
    surface_height: u32,
    update_x: u32,
    update_y: u32,
    update_width: u32,
    update_height: u32,
    rgba_data: &[u8],
) -> anyhow::Result<()> {
    if update_x.saturating_add(update_width) > surface_width || update_y.saturating_add(update_height) > surface_height
    {
        anyhow::bail!(
            "RGBA update rectangle {}x{} at {},{} exceeds {}x{} surface",
            update_width,
            update_height,
            update_x,
            update_y,
            surface_width,
            surface_height
        );
    }

    let expected_len = update_width
        .checked_mul(update_height)
        .and_then(|pixel_count| pixel_count.checked_mul(4))
        .context("RGBA update size overflowed")? as usize;
    anyhow::ensure!(
        rgba_data.len() == expected_len,
        "RGBA update length mismatch: expected {expected_len} bytes for {}x{} update, got {}",
        update_width,
        update_height,
        rgba_data.len()
    );

    let surface_stride = surface_width as usize * 4;
    let update_stride = update_width as usize * 4;
    for row in 0..update_height as usize {
        let src_offset = row * update_stride;
        let dst_offset = ((update_y as usize + row) * surface_stride) + (update_x as usize * 4);
        surface_rgba[dst_offset..dst_offset + update_stride]
            .copy_from_slice(&rgba_data[src_offset..src_offset + update_stride]);
    }

    Ok(())
}

fn current_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::blit_rgba_update;

    #[test]
    fn blit_rgba_update_copies_region_into_surface_buffer() {
        let mut surface = vec![0u8; 4 * 4 * 4];
        let update = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        blit_rgba_update(&mut surface, 4, 4, 1, 1, 2, 2, &update).expect("blit update into surface");

        let pixel = |x: usize, y: usize| -> [u8; 4] {
            let offset = (y * 4 + x) * 4;
            [
                surface[offset],
                surface[offset + 1],
                surface[offset + 2],
                surface[offset + 3],
            ]
        };

        assert_eq!(pixel(1, 1), [1, 2, 3, 4]);
        assert_eq!(pixel(2, 1), [5, 6, 7, 8]);
        assert_eq!(pixel(1, 2), [9, 10, 11, 12]);
        assert_eq!(pixel(2, 2), [13, 14, 15, 16]);
        assert_eq!(pixel(0, 0), [0, 0, 0, 0]);
    }
}

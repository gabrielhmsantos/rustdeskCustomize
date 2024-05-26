use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
	let app_title = "InfoMaster Remote Desktop";
    frame.set_title(&app_title); //(JEM)
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn default_video_save_directory(&self) -> String {
        default_video_save_directory()
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn default_video_save_directory();
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,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".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}

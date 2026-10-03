use chromiumoxide::browser::{Browser, BrowserConfig};
use chromiumoxide::handler::viewport::Viewport;
use futures::StreamExt;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::error::Error;

// --- Structures for CDP proxy authorization ---
#[derive(Serialize)]
struct AuthChallengeResponse {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "authChallengeResponse")]
    auth_challenge_response: ChallengeResponse,
}

#[derive(Serialize)]
struct ChallengeResponse {
    response: &'static str,
    username: &'static str,
    password: &'static str,
}

// --- DIGITAL BROWSER PROFILE STRUCTURE ---
#[derive(Debug, Clone)]
struct BrowserProfile {
    user_agent: String,
    platform: String,
    screen_width: u32,
    screen_height: u32,
    gl_vendor: String,
    gl_renderer: String,
    canvas_noise_seed: u8, // Unique noise seed for this session
    languages: Vec<String>,
}

impl BrowserProfile {

    /// Generator of realistic and consistent profiles
    fn generate_random() -> Self {
        let mut rng = rand::thread_rng();

        // 1. Lists of approved operating systems and platforms
        let os_options = vec![
            ("Windows", "Win32", vec![
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
            ]),
            ("Macintosh", "MacIntel", vec![
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
            ])
        ];

        let selected_os = os_options.choose(&mut rng).unwrap();
        let platform = selected_os.1.to_string();
        let user_agent = selected_os.2.choose(&mut rng).unwrap().to_string();

        // 2. supported screen resolutions
        let screen_resolutions = vec![
            (1920, 1080),
            (1440, 900),
            (1536, 864),
            (2560, 1440)
        ];
        let (screen_width, screen_height) = *screen_resolutions.choose(&mut rng).unwrap();

        // 3. compatible graphics cards (WebGL)
        let gpu_options = if selected_os.0 == "Windows" {
            vec![
                ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
                ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Laptop GPU Direct3D11 vs_5_0 ps_5_0, D3D11)"),
                ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)")
            ]
        } else {
            vec![
                ("Apple", "Apple M1"),
                ("Apple", "Apple M2"),
                ("Apple", "Apple M3")
            ]
        };
        let (gl_vendor, gl_renderer) = *gpu_options.choose(&mut rng).unwrap();

        // 4. Language packs
        let lang_options = vec![
            vec!["ru-RU".to_string(), "ru".to_string(), "en-US".to_string(), "en".to_string()],
            vec!["en-US".to_string(), "en".to_string()]
        ];
        let languages = lang_options.choose(&mut rng).unwrap().clone();

        // 5. A unique seed for injecting noise into the Canvas
        let canvas_noise_seed = rng.gen_range(1..=5);

        BrowserProfile {
            user_agent,
            platform,
            screen_width,
            screen_height,
            gl_vendor: gl_vendor.to_string(),
            gl_renderer: gl_renderer.to_string(),
            canvas_noise_seed,
            languages,
        }
    }

    /// Assembling a custom JS injection script based on the generated profile
    fn compile_js_injector(&self, proxy_ip: &str) -> String {

        let langs_json = serde_json::to_string(&self.languages).unwrap_or_else(|_| "['en-US']".to_string());
        
        format!(r#"
            (function() {{
                // --- Spoofing of the WebRTC Network Identifier ---
                const FAKE_IP = '{proxy_ip}';
                const OriginalRTCPeerConnection = window.RTCPeerConnection || window.webkitRTCPeerConnection;
                if (OriginalRTCPeerConnection) {{
                    function SpoofedRTCPeerConnection(config, constraints) {{
                        const pc = new OriginalRTCPeerConnection(config, constraints);
                        const originalAddEventListener = pc.addEventListener;
                        pc.addEventListener = function(type, listener, options) {{
                            if (type === 'icecandidate') {{
                                const wrappedListener = function(event) {{
                                    if (event.candidate) {{
                                        const spoofedStr = event.candidate.candidate.replace(
                                            /([0-9]{1,3}(\.[0-9]{1,3}){{3}})|([a-f0-9:]+:+[a-f0-9:]+)/gi, FAKE_IP
                                        );
                                        const newCandidate = new RTCIceCandidate({{
                                            candidate: spoofedStr, sdpMid: event.candidate.sdpMid, sdpMLineIndex: event.candidate.sdpMLineIndex
                                        }});
                                        listener.call(this, {{ candidate: newCandidate }});
                                    }} else {{ listener.call(this, event); }}
                                }};
                                return originalAddEventListener.call(this, type, wrappedListener, options);
                            }}
                            return originalAddEventListener.call(this, type, listener, options);
                        }};
                        return pc;
                    }}
                    SpoofedRTCPeerConnection.prototype = OriginalRTCPeerConnection.prototype;
                    window.RTCPeerConnection = SpoofedRTCPeerConnection;
                }}

                // --- Spoofing Navigator and Window properties ---
                Object.defineProperty(navigator, 'userAgent', {{ get: () => '{user_agent}' }});
                Object.defineProperty(navigator, 'platform', {{ get: () => '{platform}' }});
                Object.defineProperty(navigator, 'webdriver', {{ get: () => undefined }});
                Object.defineProperty(navigator, 'languages', {{ get: () => {languages} }});

                // Screen resolution
                Object.defineProperty(window.screen, 'width', {{ get: () => {width} }});
                Object.defineProperty(window.screen, 'height', {{ get: () => {height} }});
                Object.defineProperty(window.screen, 'availWidth', {{ get: () => {width} }});
                Object.defineProperty(window.screen, 'availHeight', {{ get: () => {height} - 40 }});

                // --- stable Canvas noise for the current profile --- 
                const SEED = {seed};
                const originalGetImageData = CanvasRenderingContext2D.prototype.getImageData;
                CanvasRenderingContext2D.prototype.getImageData = function(x, y, w, h) {{
                    const imageData = originalGetImageData.apply(this, arguments);
                    const data = imageData.data;

                    // We use a static profile SEED so that the Canvas hash remains
                    // unchanged upon re-reading within a single session
                    for (let i = 0; i < data.length; i += 4) {{
                        data[i]     = data[i]     ^ (SEED & 1);
                        data[i + 1] = data[i + 1] ^ ((SEED >> 1) & 1);
                    }}
                    return imageData;
                }};

                const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                HTMLCanvasElement.prototype.toDataURL = function() {{
                    const ctx = this.getContext('2d');
                    if (ctx) {{ try {{ ctx.getImageData(0, 0, 1, 1); }} catch(e) {{}} }}
                    return originalToDataURL.apply(this, arguments);
                }};

                // --- GPU Spoofing in WebGL ---
                const originalGetParameter = WebGLRenderingContext.prototype.getParameter;
                WebGLRenderingContext.prototype.getParameter = function(parameter) {{
                    if (parameter === 37445) return '{gl_vendor}'; 
                    if (parameter === 37446) return '{gl_renderer}';
                    return originalGetParameter.apply(this, arguments);
                }};

                console.log('--- [Antidetect] Profile successfully generated and applied ---');
            })();
        "#,
        proxy_ip = proxy_ip,
        user_agent = self.user_agent,
        platform = self.platform,
        languages = langs_json,
        width = self.screen_width,
        height = self.screen_height,
        seed = self.canvas_noise_seed,
        gl_vendor = self.gl_vendor,
        gl_renderer = self.gl_renderer
        )
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    // 1. Generation of a unique digital fingerprint
    let my_profile = BrowserProfile::generate_random();

    println!("=== A new anti-detect profile has been generated ===");
    println!("{:#?}", my_profile);

    // Proxy data
    let proxy_ip = "198.51.100.42";
    let proxy_port = "8080";
    let proxy_user = "my_proxy_user";
    let proxy_pass = "my_proxy_password";

    // 2. Chromium configuration based on the generated profile
    let config = BrowserConfig::builder()
        .no_sandbox()
        .arg(format!("--proxy-server=http://{}:{}", proxy_ip, proxy_port))
        .arg("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")
        .arg("--disable-blink-features=AutomationControlled")
        .viewport(Viewport {
            width: my_profile.screen_width,
            height: my_profile.screen_height,
            ..Default::default()
        })
        .build()?;
    let (browser, mut handler) = Browser::launch(config).await?;

    // 3. Proxy network authentication handler via CDP
    tokio::spawn(async move {
        while let Some(event_res) = handler.next().await {
            if let Ok(event) = event_res {
                if event.method == "Fetch.requestPaused" {
                    if let Some(params) = event.params {
                        if params.get("authChallenge").is_some() {
                            if let Some(req_id) = params.get("requestId").and_then(|id| id.as_str()) {
                                let auth_response = AuthChallengeResponse {
                                    request_id: req_id.to_string(),
                                    auth_challenge_response: ChallengeResponse {
                                        response: "ProvideCredentials",
                                        username: proxy_user,
                                        password: proxy_pass,
                                    },
                                };
                                let _ = event.client.execute("Fetch.continueWithAuth", auth_response).await;
                            }
                        } else {
                            if let Some(req_id) = params.get("requestId").and_then(|id| id.as_str()) {
                                let _ = event.client.execute("Fetch.continueRequest", serde_json::json!({ "requestId": req_id })).await;
                            }
                        }
                    }
                }
            }
        }
    });
    
    // 4. Page initialization and enabling network interception
    let page = browser.new_page("about:blank").await?;
    page.execute_raw_js("Fetch.enable({ handleAuthRequests: true })").await?;

    // 5. Compilation and injection of a dynamic fingerprint-swapping script
    let dynamic_js = my_profile.compile_js_injector(proxy_ip);
    page.execute_raw_js(format!("Page.addScriptToEvaluateOnNewDocument({{source: {}}})", dynamic_js)).await?;

    // 6. Go to the verification site
    println!("** Initiating fingerprint parameter verification ..");

    page.goto("browserleaks.com").await?;
    tokio::time::sleep(std::time::Duration::from_secs(40)).await;

    browser.close().await?;

    Ok(())
}

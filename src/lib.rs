pub mod server {
    pub const MAX_HEADER_SIZE: usize = 1024;
    pub const MAX_BODY_SIZE: usize = 1024;
    pub const MHS_PORT: u16 = 80;
    pub const MAX_HTTP_CLIENT: usize = 5;
    pub const HTTP_SERVER: &str = "Micro CHTTP Server";

    pub type Socket = i32;

    // nix는 Unix API에 대한 바인딩을 제공하므로 윈도우에서 작동하지 않는다.
    use nix::sys::select::FdSet;

    #[derive(Debug)]
    pub struct HTTPServer {
        sock: Socket,
        max_sock: Socket,
        read_sock_pool: FdSet,
        write_sock_pool: FdSet,
    }

    #[derive(Debug)]
    pub struct HTTPHeaderField {
        key: String,
        value: String,
    }

    pub const MAX_HEADER_FIELDS: usize = 20;

    #[derive(Debug)]
    pub enum HTTPMethod {
        Get,
        Post,
        Put,
        Delete,
        NumMethod,
    }

    #[derive(Debug)]
    pub struct HTTPReqHeader {
        method: HTTPMethod,
        uri: String,
        version: String,
        fields: Vec<HTTPHeaderField>, 
        amount: u32,
    }

    #[derive(Debug)]
    pub struct HTTPReqMessage {
        header: HTTPReqHeader,
        body: Vec<u8>,
        buf: Vec<u8>,
        index: u16,
    }

    #[derive(Debug)]
    pub struct HTTPResHeader {
        version: String,
        status_code: String,
        description: String,
        fields: Vec<HTTPHeaderField>,
        amount: u32,
    }

    #[derive(Debug)]
    pub struct HTTPResMessage {
        header: HTTPResHeader,
        body: Vec<u8>, 
        buf: Vec<u8>,
        index: u16,
    }

    pub type HTTPReqCallback = fn(&mut HTTPReqMessage, &mut HTTPResMessage);

    //pub fn http_server_init(server: &mut HTTPServer, port: u16);

    //pub fn http_server_run(server: &mut HTTPServer, callback: HTTPReqCallback);

    pub fn http_server_run_loop(server: &mut HTTPServer, callback: HTTPReqCallback) {
        loop {
            //http_server_run(server, callback);
        }
    }

    //pub fn http_server_close(server: &mut HTTPServer);

    // 디버그 메시지 매크로
    #[cfg(debug_assertions)]
    macro_rules! debug_msg {
        ($($arg:tt)*) => (println!($($arg)*));
    }

    #[cfg(not(debug_assertions))]
    macro_rules! debug_msg {
        ($($arg:tt)*) => {};
    }
}

pub mod middleware {
    use crate::server::{HTTPMethod, HTTPReqMessage, HTTPResMessage, HTTPReqCallback};

    pub const MAX_HTTP_ROUTES: usize = 10;

    // 서버에서 정적 파일 제공 기능을 활성화했을 때 "static/" 폴더를 사용
    #[cfg(feature = "enable_static_file")]
    pub const STATIC_FILE_FOLDER: &str = "static/";

    pub type SAF = HTTPReqCallback;

    /* 
    - 아래 함수들의 구현은 현재 모듈에서 진행할 것이라면 남겨둔다.
    - main에서 구현할 것이라면 아래 함수들은 지운다.
    */
    //pub fn add_route(method: HTTPMethod, path: &str, callback: SAF) -> i32;

    // 응답 메시지는 함수 내부에서 수정할 필요가 있을 수 있으므로 가변변수로 설정
    //pub fn dispatch(req: &HTTPReqMessage, res: &mut HTTPResMessage);
}
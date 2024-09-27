pub const MAX_HEADER_SIZE: usize = 1024;
pub const MAX_BODY_SIZE: usize = 1024;
pub const MHS_PORT: u16 = 80; // 기본 포트
pub const MAX_HTTP_CLIENT: usize = 5;
pub const HTTP_SERVER: &str = "Micro CHTTP Server";

pub type Socket = i32;

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

pub fn http_server_init(server: &mut HTTPServer, port: u16);

pub fn http_server_run(server: &mut HTTPServer, callback: HTTPReqCallback);

pub fn http_server_run_loop(server: &mut HTTPServer, callback: HTTPReqCallback) {
    loop {
        http_server_run(server, callback);
    }
}

pub fn http_server_close(server: &mut HTTPServer);

// 디버그 메시지 매크로
#[cfg(debug_assertions)]
macro_rules! debug_msg {
    ($($arg:tt)*) => (println!($($arg)*));
}

#[cfg(not(debug_assertions))]
macro_rules! debug_msg {
    ($($arg:tt)*) => {};
}

println!("Test");
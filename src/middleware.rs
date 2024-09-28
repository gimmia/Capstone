mod server;

use server::{HTTPMethod, HTTPReqMessage, HTTPResMessage, HTTPREQ_CALLBACK};

pub const MAX_HTTP_ROUTES: usize = 10;

// 서버에서 정적 파일 제공 기능을 활성화했을 때 "static/" 폴더를 사용
#[cfg(feature = "enable_static_file")]
pub const STATIC_FILE_FOLDER: &str = "static/";

pub type SAF = HTTPREQ_CALLBACK;

pub fn add_route(method: HTTPMethod, path: &str, callback: SAF) -> i32;

// 응답 메시지는 함수 내부에서 수정할 필요가 있을 수 있으므로 가변변수로 설정
pub fn dispatch(req: &HTTPReqMessage, res: &mut HTTPResMessage);
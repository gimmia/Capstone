// 컴파일 시 다음 플래그를 활성화: cargo build --features "enable_static_file"

use std::sync::Mutex;  // mutex를 사용하는 것이 올바른지는 add_route() 함수를 실행하는 스레드가 존재할 경우에 판단할 수 있음
use std::os::unix::fs::PermissionsExt;
use std::fs;  // <sys/stat.h> 헤더를 대체할 수 있다. 이후 코드를 분석하면서 use std::fs::File;와 같이 어떤 상태 관련 모듈을 가져올 지 명시 필요
use crate::middleware::{MAX_HTTP_ROUTES, SAF, STATIC_FILE_FOLDER};  // lib.rs 파일의 middleware 모듈을 참조
use crate::server::{HTTPMethod, HTTPReqMessage, HTTPResMessage, MAX_BODY_SIZE};  // lib.rs 파일의 server 모듈을 참조

pub struct Route {
    pub method: HTTPMethod,
    pub uri: String,
    pub saf: SAF,
}
/* 
// lazy_static! 매크로는 전역 데이터나 변수를 지연 초기화하는 매크로
// [None, None, None, None, ..., None] // 총 `MAX_HTTP_ROUTES` 크기로 ROUTES 벡터를 0x00으로 초기화
// 원본 소스 코드에서는 Mutex를 사용하는 등의 보호 기법을 사용하지 않기 때문에 제거했으며, 따라서 new 메소드로 필요 없어짐
lazy_static! {
    pub static ref ROUTES: [Option<Route>; MAX_HTTP_ROUTES] = [None; MAX_HTTP_ROUTES];  
    pub static ref ROUTES_USED: usize = 0;
}
*/

static mut ROUTES: [Option<Route>; MAX_HTTP_ROUTES] = [None; MAX_HTTP_ROUTES];
static mut ROUTES_USED: usize = 0;

// add_route 함수의 반환 형은 int를 대체할 i32를 사용
pub fn add_route(method: HTTPMethod, uri: &str, saf: SAF) -> i32 {
    unsafe {
        if ROUTES_USED < MAX_HTTP_ROUTES {
            let route = Route {
                method,
                uri: uri.to_string(), // &str을 String으로 변환
                saf,
            };

            ROUTES[ROUTES_USED] = Some(route);
            ROUTES_USED += 1;

            ROUTES_USED  // 추가된 라우트 수 반환
        } else {
            0  // 라우트 테이블이 가득 찼을 때 0을 반환
        }
    }
}

// 함수의 반환값은 원본 코드에서 uint8_t이므로 이를 대체할 u8을 사용함
#[cfg(feature = "enable_static_file")]
pub fn read_static_files(req: &HTTPReqMessage, res: &HTTPResMessage) -> u8 {
    
    let mut found: u8 = 0;
    let mut depth: i8 = 0;
    let uri: &str = &req.header.uri; // String 형인 uri를 &str로 변환
    let mut n = uri.len();
    let mut i: usize;
    
    let mut path = STATIC_FILE_FOLDER.to_string();  // &str 형을 String 형으로 변환
    
    let header: &str = "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                        Content-Type: text/html; charset=UTF-8\r\n\r\n";
    
    /* Prevent Path Traversal. */
    for i in 0..n {
        // 성능 면에서 uri.as_bytes() 메소드를 사용하는 것이 좋다. "/"는 UTF-8로 인코딩된 문자열로 취급하기 때문
        if uri.as_bytes()[i] == b'/' {  
            // &uri[i+1..i+2]와 같이 슬라이스를 사용하면 각 문자를 비교할 때 추가적인 메모리 할당이 발생 가능
            if if (n - i) > 2 && uri.as_bytes()[i + 1] == b'.' && uri.as_bytes()[i + 2] == b'.' {  
                depth -= 1;
                if depth < 0 {
                    break;
                }
            } else if (n - i) > 1 && uri.as_bytes()[i + 1] == b'.' {
                continue;
            } else {
                depth += 1;
            }
        }
    }

    if depth >= 0 && uri.as_bytes()[i - 1] != b'/' { 
        // 원본 소스 코드에서 memcpy(path + strlen(STATIC_FILE_FOLDER), uri, strlen(uri)); 부분과 동일한 기능 수행
        // push_str() 메소드는 uri의 길이를 확인하고 path의 공간이 충분한지 검사하고 부족할 경우 추가로 메모리를 할당함
        // 단, push_str() 메소드는 String에만 문자열을 추가할 수 있음
        path.push_str(uri);

        match std::fs::File::open(&path) {
            Ok(mut file) => {
                // metadata() : file에 대한 여러 정보를 Result 형으로 반환
                // map(|m| m.len()) : metadata() 메소드의 반환 값을 클로저 익명 함수(||)의 m 매개변수로 받고 len() 메소드로 file의 길이를 구함
                // unwrap_or(0) : 실행이 실패하면 Error를 반환
                let size = file.metadata().map(|m| m.len()).unwrap_or(0);

                if size < MAX_BODY_SIZE as u64 {  // MAX_BODY_SIZE 값을 u64 타입으로 변환하여 size와 연산 가능하도록 함
                    n = header.len();
                    // res.buf는 Vec<u8> 형이며, as_bytes() 메소드의 반환 타입은 &[u8]이므로 호환 가능
                    res.buf[..n].copy_from_slice(header.as_bytes());
                    i = n;

                    n = file.read(&mut res._buf[i..(i + size as usize)]).unwrap_or(0);
                    i += n;

                    res.index = i;

                    found = 1;
                }
            }
        }
        // Error 
        found
    }
}
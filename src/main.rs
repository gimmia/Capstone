// 컴파일 시 다음 플래그를 활성화: cargo build --features "enable_static_file"

use std::os::unix::fs::PermissionsExt;
use std::fs;
use crate::middleware::{MAX_HTTP_ROUTES, SAF, STATIC_FILE_FOLDER}; 
use crate::server::{HTTPMethod, HTTPReqMessage, HTTPResMessage, MAX_BODY_SIZE};  

pub struct Route {
    pub method: HTTPMethod,
    pub uri: String,
    pub saf: SAF,
}

static mut ROUTES: [Option<Route>; MAX_HTTP_ROUTES] = [None; MAX_HTTP_ROUTES];
static mut ROUTES_USED: usize = 0;

pub fn add_route(method: HTTPMethod, uri: &str, saf: SAF) -> i32 {
    unsafe {
        if ROUTES_USED < MAX_HTTP_ROUTES {
            let route = Route {
                method,
                uri: uri.to_string(), 
                saf,
            };

            ROUTES[ROUTES_USED] = Some(route);
            ROUTES_USED += 1;

            ROUTES_USED
        } else {
            0 
        }
    }
}


#[cfg(feature = "enable_static_file")]
pub fn read_static_files(req: &HTTPReqMessage, res: &HTTPResMessage) -> u8 {
    
    let mut found: u8 = 0;
    let mut depth: i8 = 0;
    let uri: &str = &req.header.uri;
    let mut n = uri.len();
    let mut i: usize;
    
    let mut path = STATIC_FILE_FOLDER.to_string();
    
    let header: &str = "HTTP/1.1 200 OK\r\nConnection: close\r\n\
                        Content-Type: text/html; charset=UTF-8\r\n\r\n";
    
    /* Prevent Path Traversal. */
    for i in 0..n {
        if uri.as_bytes()[i] == b'/' {  
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
        path.push_str(uri);

        match std::fs::File::open(&path) {
            Ok(mut file) => {
                let size = file.metadata().map(|m| m.len()).unwrap_or(0);

                if size < MAX_BODY_SIZE as u64 {
                    n = header.len();
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
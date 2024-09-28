// self를 가져와 io::으로 std::io의 다른 모든 항목을 사용할 수 있도록 함
// Write를 가져와 Write 트레이트를 사용할 수 있도록 함
use std::io::{self, Write};
use std::fs;

// 서버에서 정적 파일 제공 기능을 활성화했을 때 metadata 함수를 사용하여 파일 상태 정보를 얻음
#[cfg(feature = "enable_static_file")]
use std::fs::Metadata;

mod lib;

use lib::server;
use lib::middleware;

fn main() {
    println!("Hello, world!");
}

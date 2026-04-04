#[cfg(target_os = "windows")]
fn main() {
    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    use windows_sys::Win32::NetworkManagement::WindowsFirewall::{
        NETISO_ERROR_TYPE_INTERNET_CLIENT, NETISO_ERROR_TYPE_INTERNET_CLIENT_SERVER,
        NETISO_ERROR_TYPE_NONE, NETISO_ERROR_TYPE_PRIVATE_NETWORK,
        NetworkIsolationDiagnoseConnectFailureAndGetInfo,
    };

    fn to_wide(value: &str) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        eprintln!("usage: windows_net_diag <host> <port> <timeout_ms>");
        std::process::exit(2);
    }

    let host = &args[1];
    let port = args[2].parse::<u16>().expect("port should parse");
    let timeout_ms = args[3].parse::<u64>().expect("timeout should parse");
    let address = format!("{host}:{port}")
        .parse::<SocketAddr>()
        .expect("host must be an IP literal");

    match TcpStream::connect_timeout(&address, Duration::from_millis(timeout_ms)) {
        Ok(stream) => {
            println!("connect=ok");
            drop(stream);
            return;
        }
        Err(error) => {
            eprintln!("connect_error={error}");
        }
    }

    let host_wide = to_wide(host);
    let mut diagnosis = NETISO_ERROR_TYPE_NONE;
    let status = unsafe {
        NetworkIsolationDiagnoseConnectFailureAndGetInfo(host_wide.as_ptr(), &mut diagnosis)
    };
    println!("diag_status={status}");
    println!(
        "diag_reason={}",
        match diagnosis {
            NETISO_ERROR_TYPE_NONE => "none",
            NETISO_ERROR_TYPE_PRIVATE_NETWORK => "private_network",
            NETISO_ERROR_TYPE_INTERNET_CLIENT => "internet_client",
            NETISO_ERROR_TYPE_INTERNET_CLIENT_SERVER => "internet_client_server",
            other => {
                eprintln!("unknown_diag_reason={other}");
                "unknown"
            }
        }
    );
    std::process::exit(1);
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("windows_net_diag is only supported on Windows");
    std::process::exit(2);
}

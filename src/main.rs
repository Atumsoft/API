extern crate os_type;
extern crate pcap;
use pcap::{Device, Capture, };
use std::fmt::Write as fmt_write;
use std::io::Error as ioerr;

//pub mod base;
pub mod arp_scan;
//pub mod windows_adapter;
//pub mod ubuntu_adapter;

//use windows_adapter::WindowsAdapter;
//use ubuntu_adapter::UbuntuAdapter;

fn convert_to_hex(buffer: &[u8]) -> Result<(String), ioerr>{
    let mut s = String::new();
    for &byte in buffer {
        write!(&mut s, "{:02X} ", byte).unwrap();
    }
    Ok(s)
}

fn main() {
    arp_scan::find_device("wlp3s0");

    let devices = Device::list();
    println!("{:?}", devices);
    let default_dev = Device::lookup();
    println!("{:?}", default_dev);

    let mut cap = Device::lookup().unwrap().open().unwrap();

    cap.sendpacket("hello".to_string().into_bytes().as_slice());

    while let Ok(packet) = cap.next() {
        println!("received packet! {} \nlen: {}", convert_to_hex(packet.data).unwrap(), packet.data.len());
    }

//
//    let supported_platforms: Vec<& str> = vec!["WINDOWS", "UBUNTU"];
//
////    let os_type = match os_type::current_platform() {
////        os_type::OSType::Windows => WindowsAdapter,
////        os_type::OSType::Ubuntu => UbuntuAdapter,
////        _ => {println!("Your platform is currently not supported");std::process::exit(1);}
////    };
//
////    if supported_platforms.contains(&os_type) {
////        println!("{}", os_type);
////    }
//
}

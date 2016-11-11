use std::error::Error;
use std::io::prelude::*;
use std::process::{Command, Stdio};

pub fn find_device(iface_name: &str) {
    let mut process = match Command::new("netdiscover")
                                .args(&["-S", "-P", &format!("-i{}", iface_name)])
                                .stdout(Stdio::piped())
                                .spawn() {
        Err(why) => panic!("couldn't spawn netdiscover: {}", why.description()),
        Ok(process) => process,
    };

    loop {
        let mut devices = String::new();
        'line: loop {
            let mut s = [0; 1];
            let amt = process.stdout.as_mut().unwrap().read(&mut s);
            let output = int_to_char(&s);
            devices.push_str(&output);
            if output == "\n" || output == "\r" { break }

        };
        if devices.starts_with(" _") || devices.starts_with(" -") || devices.starts_with("  ") {
            continue;
        }
        else {
            print!("{}", devices);
            break;
        };

    };

    process.kill();
}

fn int_to_char(byte_array: &[u8; 1]) -> String{
    let mut new_vec = Vec::new();
    for i in byte_array.iter(){
        if *i != 0 {
            new_vec.push(*i);
        }
    }

    String::from_utf8(new_vec).unwrap()
}
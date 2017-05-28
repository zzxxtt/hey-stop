
extern crate clap;
extern crate libc;
extern crate nix;
extern crate ptrace;
//#[macro_use] extern crate log;
#[macro_use] extern crate syscall;
use clap::{Arg, App, SubCommand};
use std::env;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::string::String;
use std::ffi::CString;
use nix::unistd;

struct Execve {
    args : Vec<CString>,
}

impl Execve {
    pub fn new(args: &[&str]) -> Execve {
        Execve {
            args: args.iter().map(|s| CString::new(*s).unwrap()).collect(),
        }
    }
    pub fn execute(&self) -> Result<(), ()> {
        match unistd::execve(&self.args[0],&self.args, &[]) {
            Ok(_)=>Ok(()),
            Err(_) => Err(()),
        }
    }
}

struct Process {
    pid: libc::pid_t,
    in_syscall: bool,
}

impl Process {
    pub fn new(pid: libc::pid_t) -> Process {
        Process {
            pid: pid,
            in_syscall: false,
        }
    }
    pub fn get_controller(&self) -> ProcessController{
        ProcessController{
            pid: self.pid,
        }
    }
}
#[derive(Clone)]
struct ProcessController{
    pid: libc::pid_t,
}
impl ProcessController {
    pub fn new(pid: libc::pid_t) -> ProcessController {
        ProcessController {
            pid: pid,
        }
    }
    pub fn get_reader(&self)->ptrace::Reader {
        return ptrace::Reader {
            pid: self.pid,
        }
    }
    pub fn get_writer(&self) -> ptrace::Writer{
        return ptrace::Writer{
            pid: self.pid,
        }
    }
}




fn main(){ 
    let matches = App::new("Hey-stop")
        .version("0.0.1")
        .author("Yang Zhou and Xiting Zhao")
        .about("Program Behavior Controller")
        .arg(Arg::with_name("command")
             .required(true)
             .multiple(true)
             .takes_value(true))
        .get_matches();
    let args: Vec<&str> = matches.values_of("command").unwrap().collect();
    let executor = Execve::new(args.as_slice());
    executor.execute();

}

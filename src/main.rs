
extern crate clap;
extern crate libc;
extern crate nix;
extern crate ptrace;
extern crate fnv;
#[macro_use]
extern crate syscall;
use clap::{Arg, App, SubCommand};
use std::env;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::string::String;
use std::ffi::CString;
use nix::unistd;
use nix::sys::signal;
use nix::sys::wait;
use syscall::nr;
use fnv::FnvHashMap;
use std::sync::Condvar;
use std::sync::Mutex;


pub struct Execvp {
    args: Vec<CString>,
}

impl Execvp {
    pub fn new(args: &[&str]) -> Execvp {
        Execvp { args: args.iter().map(|s| CString::new(*s).unwrap()).collect() }
    }
    pub fn execute(&self) -> Result<(), ()> {
        match unistd::execvp(&self.args[0], &self.args) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }
}



pub struct Process {
    pub pid: libc::pid_t,
    pub in_syscall: bool,
}

impl Process {
    pub fn new(pid: libc::pid_t) -> Process {
        Process {
            pid: pid,
            in_syscall: false,
        }
    }

    pub fn get_controller(&self) -> ProcessController {
        ProcessController { pid: self.pid }
    }
}

#[derive(Clone)]
pub struct ProcessController {
    pub pid: libc::pid_t,
}

impl ProcessController {
    pub fn new(pid: libc::pid_t) -> ProcessController {
        ProcessController { pid: pid }
    }

    pub fn get_reader(&self) -> ptrace::Reader {
        return ptrace::Reader { pid: self.pid };
    }

    pub fn get_writer(&self) -> ptrace::Writer {
        return ptrace::Writer { pid: self.pid };
    }
}



pub struct process {
    executor: Box<Execvp>,

    child_pid: libc::pid_t,
    children: FnvHashMap<libc::pid_t, Process>,
}


impl process {
    pub fn new(executor: Box<Execvp>) -> process {
        process {
            executor: executor,

            child_pid: -1,
            children: FnvHashMap::default(),
        }
    }

    pub fn start(&mut self) -> Result<(), i32> {

        match unistd::fork() {
            Ok(fork_result) => {
                match fork_result {
                    unistd::ForkResult::Parent { child } => {
                        //info!("pid: {}", child);
                        self.child_pid = child;
                        self.children.insert(child, Process::new(child));
                        println!("parent");
                        let result = self.monitor();
                        result
                    }
                    unistd::ForkResult::Child => {
                        println!("child");
                        let result = self.start_program();
                        if result.is_ok() {
                            panic!("Program successfully started; but process did not end");
                        }
                        Err(1)
                    }
                }
            }
            Err(_) => Err(1), 
        }
    }

    pub fn start_program(&self) -> Result<(), ()> {
        ptrace::traceme().expect("Failed to traceme!");
        signal::raise(signal::SIGSTOP).expect("Failed to raise SIGSTOP!");
        self.executor.execute()
    }

    fn monitor(&mut self) -> Result<(), i32> {

        {
            let status = wait::waitpid(self.child_pid, None).expect("Failed to wait");
            println!("{:?}", status);
            if let wait::WaitStatus::Stopped(_, sig) = status {

                if let signal::Signal::SIGSTOP = sig {


                    let mut ptrace_options = 0;
                    ptrace_options |= ptrace::PTRACE_O_EXITKILL;
                    ptrace_options |= ptrace::PTRACE_O_TRACECLONE;
                    ptrace::setoptions(self.child_pid, ptrace_options)
                        .expect("Failed to set ptrace options!");

                    ptrace::cont_syscall(self.child_pid, None).expect("Failed to continue!");

                } else {
                    self.kill_program().expect("Failed to kill child!");
                    return Err(1);
                }
            } else {
                self.kill_program().expect("Failed to kill child!");
                return Err(1);
            }
        }


        loop {
            let status = wait::waitpid(-1, None).expect("Failed to wait");


            match status {
                wait::WaitStatus::Exited(_, code) => {

                    let result = if code == 0 { Ok(()) } else { Err(1) };
                    return result;
                }
                wait::WaitStatus::Signaled(_, signal, _) => {


                    let result = Err(1);
                    self.kill_program().expect("Failed to kill child!"); 
                    return result;
                }
                wait::WaitStatus::Stopped(pid, sig) => {
                    match sig {
                        signal::Signal::SIGTRAP => {
                            if let Err(code) = self.process_syscall(pid) {
                                let result = Err(code);
                                self.kill_program().expect("Failed to kill child!");
                                return result;
                            }
                        }
                        signal::Signal::SIGSEGV => {
                            let result = Err(1);
                            self.kill_program().expect("Failed to kill child!");
                            return result;
                        }
                        signal::Signal::SIGXCPU => {
                            let result = Err(1);
                            self.kill_program().expect("Failed to kill child!");
                            return result;
                        }
                        _ => (),
                    }
                    ptrace::cont_syscall(pid, None).expect("Failed to continue!");
                }
                wait::WaitStatus::PtraceEvent(pid, _, event) => {
                    match event {
                        ptrace::PTRACE_EVENT_CLONE => {
                            let new_pid = ptrace::geteventmsg(pid).unwrap() as libc::pid_t;
                            if !self.children.contains_key(&pid) {
                                self.children.insert(pid, Process::new(pid));
                            }
                            ptrace::cont_syscall(pid, None).expect("Failed to continue!");
                        }
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            }
        }


        let result = Err(1);
        drop(self.kill_program());
        result
    }
    fn kill_program(&self) -> Result<(), ()> {
        match signal::kill(self.child_pid, signal::SIGKILL) {
            Ok(_) => Ok(()),
            Err(_) => Err(()),
        }
    }

    fn process_syscall(&mut self, pid: libc::pid_t) -> Result<(), i32> {
        let mut syscall = ptrace::Syscall::from_pid(pid).expect("Failed to get syscall");
        if !self.children.contains_key(&pid) {
            self.children.insert(pid, Process::new(pid));
        }

        let (in_syscall, controller) = {
            let process = self.children.get(&pid).unwrap();
            (process.in_syscall, process.get_controller())
        };

        if !in_syscall {

            println!("{:?}", syscall.call);

//read rdi register,need fix
	    if syscall.call==0 {
			let mut reader=ptrace::Reader::new(self.child_pid);
			println!("{:?}",reader.read_string(syscall.args[0],1000));
	    }

            if syscall.return_val == -libc::ENOSYS as isize {


                self.children.get_mut(&pid).unwrap().in_syscall = true;
            } else {
                if syscall.call != nr::EXECVE {

                    return Err(1);
                }

            }
        } else {


            self.children.get_mut(&pid).unwrap().in_syscall = false;
        }
        Ok(())
    }
}

fn main() {
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
    let executor = Execvp::new(args.as_slice());

    let mut newprocess = process::new(Box::new(executor));
    let result = newprocess.start();
}

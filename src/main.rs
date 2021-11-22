use std::env;

use anyhow::{anyhow, Result};
use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid::{self, listpidinfo, listpids, pidinfo, ProcType};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        println!("usage: lsport [port]");
        return Err(anyhow!("Invalid arguments"));
    }

    let target_port: i32 = args[1].parse()?;

    let pids = listpids(ProcType::ProcAllPIDS);

    if let Err(e) = pids {
        return Err(anyhow!("Unable to convert port, {}", e));
    }

    for pid in pids.unwrap() {
        let pid: i32 = pid.try_into().unwrap();
        if let Ok(info) = pidinfo::<BSDInfo>(pid, 0) {
            if let Ok(fds) = listpidinfo::<ListFDs>(pid, info.pbi_nfiles as usize) {
                for fd in &fds {
                    if let ProcFDType::Socket = fd.proc_fdtype.into() {
                        if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid, fd.proc_fd) {
                            if let SocketInfoKind::Tcp = socket.psi.soi_kind.into() {
                                let info = unsafe { socket.psi.soi_proto.pri_tcp };

                                // change endian and cut off because insi_lport is network endian and 16bit witdh.
                                let mut port = 0;
                                port |= info.tcpsi_ini.insi_lport >> 8 & 0x00ff;
                                port |= info.tcpsi_ini.insi_lport << 8 & 0xff00;

                                let s_addr =
                                    unsafe { info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr };

                                let mut addr = 0;
                                addr |= s_addr >> 24 & 0x000000ff;
                                addr |= s_addr >> 8 & 0x0000ff00;
                                addr |= s_addr << 8 & 0x00ff0000;
                                addr |= s_addr << 24 & 0xff000000;

                                if port == target_port {
                                    let name = proc_pid::name(pid).map_err(|e| {
                                        anyhow!(
                                            "Found port, but unable to read process name, {}",
                                            e
                                        )
                                    })?;
                                    println!(
                                        "{}: {}.{}.{}.{}:{} ({})",
                                        name,
                                        addr >> 24 & 0xff,
                                        addr >> 16 & 0xff,
                                        addr >> 8 & 0xff,
                                        addr & 0xff,
                                        port,
                                        pid
                                    );
                                    return Ok(());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err(anyhow!(
        "Did not find any processes listening on that port."
    ))
}

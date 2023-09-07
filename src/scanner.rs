use std::net::{Ipv4Addr};
use std::net::{TcpStream, SocketAddr};
use std::fmt::{Display, Formatter};
use std::time::Duration;

use serde::{Serialize};
use serde_yaml;

/// Scanner for an IP
#[derive(Debug, Clone, Serialize)]
pub struct Scanner {
  pub ip: Ipv4Addr,
  ports: Vec<u16>,

  #[serde(rename(deserialize = "results"))]
  result: Vec<IpScanResult>,
}

/// Trait for reporting the result of a scan
pub trait Report {
  fn report(&self) -> String;
}

/// Result of a scan on a single IP
/// Return the IP and the open ports
#[derive(Debug, Clone, Serialize)]
pub struct IpScanResult {
  /// IP scanned
  pub ip: Ipv4Addr,

  /// List of open ports
  #[serde(rename = "openPorts")]
  pub open_ports: Vec<u16>,
}

impl Display for IpScanResult {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    if self.open_ports.len() == 0 {
      return Ok(());
    }
    let formatted_ports = self.open_ports.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(", ");
    write!(f, "{}: {:>15}\n", self.ip, formatted_ports)
  }
}

impl Display for Scanner {
  fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    write!(f, "Scanner for {}\n", self.ip).unwrap();
    write!(f, "Ports: {:?}\n", self.ports).unwrap();
    Ok(())
  }
}

impl Scanner {
  pub fn new(ip: String, ports: Option<Vec<u16>>) -> Self {
    let ip = ip.parse::<Ipv4Addr>().unwrap();

    let ports = match ports {
      Some(ports) => ports,
      None => vec![80, 22, 443, 8080]
    };

    Self {
      ip,
      ports,
      result: Vec::new(),
    }
  }

  pub async fn scan(&mut self) {
    let ips = self.get_ips();
    let mut results: Vec<IpScanResult> = Vec::new();

    println!("Scanning {} IPs for {} ports", ips.len(), self.ports.len());

    let mut handles = Vec::with_capacity(ips.len());
    for ip in ips {
      let ports = self.ports.clone();

      handles.push(tokio::spawn(async move {
        scan_ip(ip, ports)
      }));
    }

    for handle in handles {
      let result = handle.await.unwrap();
      results.push(result);
    }


    self.result = results;
  }

  pub fn get_ips(&self) -> Vec<Ipv4Addr> {
    let mut ips: Vec<Ipv4Addr> = Vec::new();
    let base_ips: [u8; 4] = self.ip.octets();

    let number_of_groups = base_ips.iter().filter(|x| **x == 0).count() as u32;
    if number_of_groups == 0 {
      return vec![self.ip];
    }

    let number_of_ips = 256_u32.pow(number_of_groups);


    // Handle the case where the number of IPs is 256 to exclude the broadcast address
    let number_of_ips = if number_of_ips == 256 {
      number_of_ips - 1
    } else {
      number_of_ips
    };

    for i in 1..number_of_ips {
      let mut ip = base_ips.clone();
      let l1 = i % 255;
      let l2 = i / 255 % 256;
      let l3 = i / 255 / 255 % 256;
      let l4 = i / 255 / 255 / 255 % 256;

      if ip[0] == 0 {
        ip[0] = l4 as u8;
      }

      if ip[1] == 0 {
        ip[1] = l3 as u8;
      }

      if ip[2] == 0 {
        ip[2] = l2 as u8;
      }

      if ip[3] == 0 {
        ip[3] = l1 as u8;
      }

      ips.push(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]));
    }

    ips
  }
}

impl Report for Scanner {
  fn report(&self) -> String {
    let mut report = String::new();

    report.push_str(&format!("Scanner for {}\n", self.ip));
    report.push_str(&format!("Ports: {:?}\n", self.ports));
    report.push_str(&format!("=========================\n"));

    for result in &self.result {
      let result = format!("{}\n", result);
      report.push_str(&result);
    }

    report
  }
}

/// Scan an IP for a list of ports
/// Use TCP
/// Return the IP and the open ports
fn scan_ip(ip: Ipv4Addr, ports: Vec<u16>) -> IpScanResult {
    let mut open_ports: Vec<u16> = Vec::new();

    println!("Scanning {}…", ip);

    for port in &ports {
      let is_open = scan_port(ip.clone(), *port);
      if is_open {
        open_ports.push(*port);
      }
    }

    IpScanResult {
      ip,
      open_ports,
    }
  }

  fn scan_port(ip: Ipv4Addr, port: u16) -> bool {
    let address =  SocketAddr::from((ip.octets(), port));

    let result = TcpStream::connect_timeout(&address, Duration::new(1, 0));

    let is_open = match result {
      Ok(_) => true,
      Err(_) => false,
    };

    is_open
  }


#[cfg(test)]
mod tests {
  use super::*;

  fn test_get_one_ip() {
    let scanner = Scanner::new("192.168.1.1".to_string());
    let ips = scanner.get_ips();

    assert_eq!(ips.len(), 1);
    assert_eq!(ips[0], "192.168.1.1".parse::<Ipv4Addr>().unwrap());
  }

  #[test]
  fn test_get_ips_24() {
    let scanner = Scanner::new("192.168.1.0".to_string());
    let ips = scanner.get_ips();

    assert_eq!(ips.len(), 254);

    for i in 0..=253 {
      assert_eq!(ips[i], format!("192.168.1.{}", i + 1).parse::<Ipv4Addr>().unwrap());
    }
  }

  #[test]
  fn test_get_ips_8() {
    let scanner = Scanner::new("192.0.0.0".to_string());
    let ips = scanner.get_ips();
    let ips_to_compare = vec![
      "192.1.0.0",
      "192.1.1.1",
      "192.1.1.254",
      "192.254.254.254",
      "192.255.255.254",
      "192.254.128.254",
    ];


    for ip in ips_to_compare {
      assert_eq!(ips.contains(&ip.parse::<Ipv4Addr>().unwrap()), true, "Should contain [{}]", ip);
    }
  }
}

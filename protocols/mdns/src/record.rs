// protocols\mdns\src\record.rs

// /protocols/mdns/record.rs
use crate::name::DnsName;
use std::io::Read;
use bytes::Buf;
use serde::Serialize;
/// Represents DNS resource records (RR) used in the mDNS protocol.
///
/// `DnsRecord` supports multiple record types such as A, PTR, SRV, and TXT.
#[derive(Debug, Clone,Serialize)]
pub enum DnsRecord {
    /// A Record - Maps a name to an IPv4 address.
    A {
        name: DnsName,
        ttl: u32,
        ip: [u8; 4],
    },
    /// AAAA Record - Maps a name to an IPv6 address.
    AAAA{
        name : DnsName,
        ttl : u32,
        ip : [u8; 16],
    },
    /// PTR Record - Maps a name to another name.
    PTR {
        name: DnsName,
        ttl: u32,
        ptr_name: DnsName,
    },
    /// SRV Record - Specifies the location of a service.
    SRV {
        name: DnsName,
        ttl: u32,
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },
    /// TXT Record - Contains text data.
    TXT {
        name: DnsName,
        ttl: u32,
        txt_data: Vec<u8>,
    },
    // Additional record types can be added as needed.
}

impl DnsRecord {
    /// Writes the DNS record to a buffer in DNS wire format.
    ///
    /// # Arguments
    /// * `buffer` - A mutable vector to write the serialized DNS record.
    pub fn write(&self, buffer: &mut Vec<u8>) {
        match self {
            DnsRecord::A { name, ttl, ip } => {
                name.write(buffer);
                buffer.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
                buffer.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
                buffer.extend_from_slice(&ttl.to_be_bytes());  // TTL
                buffer.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                buffer.extend_from_slice(ip);                 // RDATA (IPv4 address)
            }
            DnsRecord::AAAA { name, ttl, ip } => {
                name.write(buffer);
                buffer.extend_from_slice(&28u16.to_be_bytes()); // TYPE AAAA (28)
                buffer.extend_from_slice(&1u16.to_be_bytes());  // CLASS IN (1)
                buffer.extend_from_slice(&ttl.to_be_bytes());   // TTL
                buffer.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH (16 bytes for IPv6)
                buffer.extend_from_slice(ip);                   // RDATA (IPv6 address)
            }
            DnsRecord::PTR { name, ttl, ptr_name } => {
                name.write(buffer);
                buffer.extend_from_slice(&12u16.to_be_bytes()); // TYPE PTR
                buffer.extend_from_slice(&1u16.to_be_bytes());  // CLASS IN
                buffer.extend_from_slice(&ttl.to_be_bytes());   // TTL
                let mut rdata = Vec::new();
                ptr_name.write(&mut rdata);
                buffer.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
                buffer.extend_from_slice(&rdata);                              // RDATA
            }
            DnsRecord::SRV {
                name,
                ttl,
                priority,
                weight,
                port,
                target,
            } => {
                name.write(buffer);
                buffer.extend_from_slice(&33u16.to_be_bytes()); // TYPE SRV
                buffer.extend_from_slice(&1u16.to_be_bytes());  // CLASS IN
                buffer.extend_from_slice(&ttl.to_be_bytes());   // TTL
                let mut rdata = Vec::new();
                rdata.extend_from_slice(&priority.to_be_bytes());
                rdata.extend_from_slice(&weight.to_be_bytes());
                rdata.extend_from_slice(&port.to_be_bytes());
                target.write(&mut rdata);
                buffer.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
                buffer.extend_from_slice(&rdata);                              // RDATA
            }
            DnsRecord::TXT { name, ttl, txt_data } => {
                name.write(buffer);
                buffer.extend_from_slice(&16u16.to_be_bytes()); // TYPE TXT
                buffer.extend_from_slice(&1u16.to_be_bytes());  // CLASS IN
                buffer.extend_from_slice(&ttl.to_be_bytes());   // TTL

                let mut rdata = Vec::new();
                for txt_segment in txt_data.chunks(255) {
                    rdata.push(txt_segment.len() as u8);
                    rdata.extend_from_slice(txt_segment);
                }

                buffer.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
                buffer.extend_from_slice(&rdata);                             // RDATA
            }
        }
    }

    /// Parses a `DnsRecord` from a cursor containing DNS wire format data.
    ///
    /// # Arguments
    /// * `cursor` - A mutable cursor over the byte slice to parse.
    ///
    /// # Returns
    /// * `Ok(DnsRecord)` - If parsing succeeds.
    /// * `Err(Box<dyn std::error::Error>)` - If parsing fails.
    pub fn parse(cursor: &mut std::io::Cursor<&[u8]>) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let name = DnsName::parse(cursor)?;
        let rtype = cursor.get_u16();
        let _rclass = cursor.get_u16();
        let ttl = cursor.get_u32();
        let rdlength = cursor.get_u16();

        match rtype {
            1 => { // A Record
                let mut ip = [0u8; 4];
                cursor.read_exact(&mut ip)?;
                Ok(DnsRecord::A { name, ttl, ip })
            }
            28 => { // AAAA Record (IPv6)
                let mut ip = [0u8; 16];
                cursor.read_exact(&mut ip)?;
                Ok(DnsRecord::AAAA { name, ttl, ip })
            }
            12 => { // PTR Record
                let ptr_name = DnsName::parse(cursor)?;
                Ok(DnsRecord::PTR { name, ttl, ptr_name })
            }
            33 => { // SRV Record
                let priority = cursor.get_u16();
                let weight = cursor.get_u16();
                let port = cursor.get_u16();
                let target = DnsName::parse(cursor)?;
                Ok(DnsRecord::SRV { name, ttl, priority, weight, port, target })
            }
            16 => { // TXT Record
                let mut txt_data = vec![0; rdlength as usize];
                cursor.read_exact(&mut txt_data)?;
                Ok(DnsRecord::TXT { name, ttl, txt_data })
            }
            _ => {
                cursor.advance(rdlength as usize);
                Err("Unknown record type".into())
            }
        }
    }
}

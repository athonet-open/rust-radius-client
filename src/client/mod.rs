/// Dictionary
pub mod dictionary;
mod host;

use std::io;
use std::time::Duration;

use super::radius::{RadiusCode, RadiusAttribute, RadiusAttributeDef, RadiusData};

use self::host::Host;
use self::dictionary::Dictionary;

use mio::net::UdpSocket;
use mio::{Events, Ready, Poll, PollOpt, Token};

use crypto::digest::Digest;
use crypto::md5::Md5;

/// RADIUS client
pub struct Client {
    host: Host,
    server: String,
    secret: String,
    retries: usize,
    timeout: usize,
    poll: Poll,
}

impl Client {
    /// constructor
    pub fn new(server: &str, authport: usize, accport: usize, coaport: usize, secret: &str, dict: Dictionary) -> Result<Client, io::Error> {
        Ok(Client {
            host: Host::new(authport, accport, coaport, dict).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            server: server.to_owned(),
            secret: secret.to_owned(),
            retries: 3,
            timeout: 5,
            poll: Poll::new()?
        })
    }

    /// Creates a RadiusAttribute element starting from Dictionary's attribute name
    pub fn create_attribute_by_name(&self, name: &str, value: Vec<u8>) -> Result<RadiusAttribute, String> {
        self.host.create_attribute_by_name(name, value)
    }

    /// Creates a RadiusAttribute element starting from Dictionary's attribute code
    pub fn create_attribute_by_code(&self, code: u8, value: Vec<u8>) -> Result<RadiusAttribute, String> {
        self.host.create_attribute_by_code(code, value)
    }

    /// generates an authentication request packet
    pub fn get_auth_packet(&self, username: &str, password: &str, identifier: Option<u8>, authenticator: Option<Vec<u8>>, attributes: Option<Vec<RadiusAttribute>>) -> Result<RadiusData, String> {
        self.host.get_auth_packet(username, password, self.secret.as_bytes(), identifier, authenticator, attributes)
    }

    /// sends a packet to the RADIUS server
    pub fn send_packet(&self, p: RadiusData) -> Result<RadiusData, io::Error> {
        let local = "0.0.0.0:0".parse().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let remote = &format!("{}:{}", self.server, self.host.get_port(p.get_code())).parse().map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let socket = UdpSocket::bind(&local)?;
        self.poll.register(&socket, Token(0), Ready::readable(), PollOpt::edge())?;

        let timeout = Duration::from_secs(self.timeout as u64);
        let mut events = Events::with_capacity(1024);
        let mut retry = 0;
        loop {
            if retry >= self.retries {
                break;
            }

            socket.send_to(&p.get_bytes(), remote)?;

            self.poll.poll(&mut events, Some(timeout))?;

            for event in events.iter() {
                match event.token() {
                    Token(0) => {
                        let mut response = [0; 4096];
                        let amount = socket.recv(&mut response)?;

                        if amount > 0 {
                            let response = &response[0..amount];//shrink slice
                            return self.verify_reply(p, self.host.from_bytes(&response).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?);
                        }
                    },
                    _ => return Err(io::Error::new(io::ErrorKind::Other, "Invalid Token")),
                }
            }

            retry += 1;
        }

        return Err(io::Error::new(io::ErrorKind::TimedOut, ""));
    }

    fn verify_reply(&self, req: RadiusData, res: RadiusData) -> Result<RadiusData, io::Error> {
        if req.get_identifier() != res.get_identifier() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, String::from("Mismatching packet identifier")));
        }

        let rawreply = res.get_bytes();
        let mut temp = Vec::new();
        temp.append(&mut (&rawreply[0..4]).to_vec());
        temp.append(&mut req.get_authenticator().to_vec());
        temp.append(&mut (&rawreply[20..]).to_vec());
        temp.append(&mut self.secret.as_bytes().to_vec());

        let mut md5 = Md5::new();
        md5.input(&temp);
        let mut hash = [0; 16];
        md5.result(&mut hash);

        if hash == res.get_authenticator() {
            Ok(res)
        }
        else {
            Err(io::Error::new(io::ErrorKind::InvalidData, String::from("Mismatching packet authenticator")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Client, Dictionary, RadiusCode};
    use client::dictionary::DEFAULT_DICTIONARY;
    use std::str::FromStr;

    #[test]
    fn authentication() {
        // test with https://hub.docker.com/r/marcelmaatkamp/freeradius/
        let d = Dictionary::from_str(DEFAULT_DICTIONARY).unwrap();
        let c = Client::new("172.25.0.100", 1812, 1813, 3799, "SECRET", d).unwrap();
        let p = c.get_auth_packet("testing", "password", None, None, Some(vec![
            c.create_attribute_by_name("NAS-IP-Address", vec![172, 25, 0, 1]).unwrap(),
            c.create_attribute_by_name("NAS-Port", vec![0]).unwrap(),
        ])).unwrap();
        let r = c.send_packet(p).unwrap();
        assert!(r.get_code() == &RadiusCode::AccessAccept);
    }
}

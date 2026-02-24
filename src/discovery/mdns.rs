use anyhow::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::mpsc;

const SERVICE_TYPE: &str = "_p2pchat._udp.local.";

pub struct DiscoveryManager {
    daemon: ServiceDaemon,
    my_identity: String,
}

impl DiscoveryManager {
    /// Initializes the mDNS daemon.
    pub fn new(my_identity: String) -> Result<Self> {
        let daemon = ServiceDaemon::new()?;
        Ok(Self {
            daemon,
            my_identity,
        })
    }

    /// Broadcasts our presence on the local network.
    pub fn start_broadcasting(&self, port: u16) -> Result<()> {
        // Use our public key snippet or unique hash as the instance name
        let instance_name = format!("peer-{}", &self.my_identity[..8]);
        let host_name = format!("{}.local.", instance_name);

        // We can advertise metadata via TXT records
        let mut properties = HashMap::new();
        properties.insert("version".to_string(), "1.0".to_string());
        properties.insert("pubkey".to_string(), self.my_identity.clone());

        let service_info = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &host_name,
            "", // Listen on all IP addresses naturally
            port,
            Some(properties),
        )?;

        self.daemon.register(service_info)?;
        Ok(())
    }

    /// Discovers other peers on the local network and pushes them to a channel.
    pub fn start_listening(&self, peer_tx: mpsc::Sender<SocketAddr>) -> Result<()> {
        let receiver = self.daemon.browse(SERVICE_TYPE)?;
        let my_identity_clone = self.my_identity.clone();

        tokio::spawn(async move {
            while let Ok(event) = receiver.recv_async().await {
                if let ServiceEvent::ServiceResolved(info) = event {
                    // Ignore our own broadcast
                    let is_me = info.get_properties().get("pubkey").map(|prop| prop.val_str()) == Some(&my_identity_clone);
                    if !is_me {
                        // Extract IP and Port
                        if let Some(ip) = info.get_addresses().iter().next() {
                            let addr = SocketAddr::new(*ip, info.get_port());
                            let _ = peer_tx.send(addr).await;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Stops all broadcasts and browsing.
    pub fn shutdown(&self) {
        self.daemon.shutdown().unwrap();
    }
}

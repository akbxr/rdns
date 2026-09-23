use crate::config::CustomDnsConfig;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct CustomRecord {
    pub ipv4s: Vec<Ipv4Addr>,
    pub ipv6s: Vec<Ipv6Addr>,
    pub cnames: Vec<String>,
    pub ptrs: Vec<String>,
}

impl Default for CustomRecord {
    fn default() -> Self {
        Self {
            ipv4s: Vec::new(),
            ipv6s: Vec::new(),
            cnames: Vec::new(),
            ptrs: Vec::new(),
        }
    }
}

pub struct CustomDnsManager {
    records: HashMap<String, CustomRecord>,
    ttl_secs: u32,
}

impl CustomDnsManager {
    pub fn from_config(config: &CustomDnsConfig) -> Self {
        let mut records: HashMap<String, CustomRecord> = HashMap::new();
        let mut auto_ptrs: Vec<(String, String)> = Vec::new();

        for (domain, targets) in &config.mapping {
            let norm_domain = domain.trim().trim_end_matches('.').to_lowercase();
            let entry = records.entry(norm_domain.clone()).or_default();

            for target in targets {
                let target = target.trim();
                if let Ok(ip) = target.parse::<IpAddr>() {
                    match ip {
                        IpAddr::V4(ipv4) => {
                            entry.ipv4s.push(ipv4);
                            auto_ptrs.push((ipv4_to_ptr_name(ipv4), norm_domain.clone()));
                        }
                        IpAddr::V6(ipv6) => {
                            entry.ipv6s.push(ipv6);
                            auto_ptrs.push((ipv6_to_ptr_name(ipv6), norm_domain.clone()));
                        }
                    }
                } else {
                    // CNAME target or explicit PTR target
                    let norm_target = target.trim_end_matches('.').to_lowercase();
                    if norm_domain.ends_with(".in-addr.arpa") || norm_domain.ends_with(".ip6.arpa") {
                        entry.ptrs.push(norm_target);
                    } else {
                        entry.cnames.push(norm_target);
                    }
                }
            }
        }

        // Insert auto PTRs
        for (ptr_name, domain) in auto_ptrs {
            records.entry(ptr_name).or_default().ptrs.push(domain);
        }

        Self {
            records,
            ttl_secs: config.custom_ttl.as_secs().max(1) as u32,
        }
    }

    /// Try to answer query from custom DNS records.
    /// Returns Some(Message) if record matched (even if NODATA), or None if domain not in custom DNS.
    pub fn resolve(&self, query: &Message) -> Option<Message> {
        let question = query.queries.first()?;
        let query_name_str = question.name.to_utf8();
        let norm_domain = query_name_str.trim().trim_end_matches('.').to_lowercase();

        let record = self.records.get(&norm_domain)?;

        let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = query.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.authoritative = true;
        resp.metadata.response_code = ResponseCode::NoError;
        resp.queries = query.queries.clone();

        if let Some(edns) = &query.edns {
            resp.set_edns(edns.clone());
        }

        let qname = question.name.clone();

        match question.query_type {
            RecordType::A => {
                if !record.ipv4s.is_empty() {
                    for &ipv4 in &record.ipv4s {
                        let rec = Record::from_rdata(qname.clone(), self.ttl_secs, RData::A(A(ipv4)));
                        resp.add_answer(rec);
                    }
                } else if !record.cnames.is_empty() {
                    self.add_cname_answers(&mut resp, &qname, &record.cnames, RecordType::A);
                }
            }
            RecordType::AAAA => {
                if !record.ipv6s.is_empty() {
                    for &ipv6 in &record.ipv6s {
                        let rec = Record::from_rdata(qname.clone(), self.ttl_secs, RData::AAAA(AAAA(ipv6)));
                        resp.add_answer(rec);
                    }
                } else if !record.cnames.is_empty() {
                    self.add_cname_answers(&mut resp, &qname, &record.cnames, RecordType::AAAA);
                }
            }
            RecordType::CNAME => {
                for cname_target in &record.cnames {
                    if let Ok(cname_name) = Name::from_str(&format!("{cname_target}.")) {
                        let rec = Record::from_rdata(qname.clone(), self.ttl_secs, RData::CNAME(CNAME(cname_name)));
                        resp.add_answer(rec);
                    }
                }
            }
            RecordType::PTR => {
                for ptr_target in &record.ptrs {
                    if let Ok(ptr_name) = Name::from_str(&format!("{ptr_target}.")) {
                        let rec = Record::from_rdata(qname.clone(), self.ttl_secs, RData::PTR(PTR(ptr_name)));
                        resp.add_answer(rec);
                    }
                }
            }
            _ => {
                // Return empty answers (NODATA) with NoError
            }
        }

        Some(resp)
    }

    fn add_cname_answers(
        &self,
        resp: &mut Message,
        qname: &Name,
        cnames: &[String],
        target_type: RecordType,
    ) {
        for target in cnames {
            if let Ok(target_name) = Name::from_str(&format!("{target}.")) {
                resp.add_answer(Record::from_rdata(
                    qname.clone(),
                    self.ttl_secs,
                    RData::CNAME(CNAME(target_name.clone())),
                ));

                // If the target domain is also in our custom DNS records, include its IP in answers
                if let Some(target_rec) = self.records.get(target) {
                    match target_type {
                        RecordType::A => {
                            for &ipv4 in &target_rec.ipv4s {
                                resp.add_answer(Record::from_rdata(
                                    target_name.clone(),
                                    self.ttl_secs,
                                    RData::A(A(ipv4)),
                                ));
                            }
                        }
                        RecordType::AAAA => {
                            for &ipv6 in &target_rec.ipv6s {
                                resp.add_answer(Record::from_rdata(
                                    target_name.clone(),
                                    self.ttl_secs,
                                    RData::AAAA(AAAA(ipv6)),
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

pub fn ipv4_to_ptr_name(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0])
}

pub fn ipv6_to_ptr_name(ip: Ipv6Addr) -> String {
    let octets = ip.octets();
    let mut parts = Vec::with_capacity(32);
    for &octet in octets.iter().rev() {
        parts.push(format!("{:x}", octet & 0x0f));
        parts.push(format!("{:x}", (octet >> 4) & 0x0f));
    }
    format!("{}.ip6.arpa", parts.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use std::time::Duration;

    #[test]
    fn test_custom_dns_a_and_ptr() {
        let mut config = CustomDnsConfig::default();
        config.custom_ttl = Duration::from_secs(300);
        config.mapping.insert(
            "router.lan".to_string(),
            vec!["192.168.1.1".to_string(), "fd00::1".to_string()],
        );
        config.mapping.insert(
            "gateway.lan".to_string(),
            vec!["router.lan".to_string()],
        );

        let manager = CustomDnsManager::from_config(&config);

        // Test A record
        let mut query_a = Message::new(1, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = "router.lan.".parse().unwrap();
        q.query_type = RecordType::A;
        query_a.queries.push(q);

        let resp_a = manager.resolve(&query_a).expect("Expected resolution");
        assert_eq!(resp_a.answers.len(), 1);
        assert_eq!(resp_a.answers[0].ttl, 300);

        // Test AAAA record
        let mut query_aaaa = Message::new(2, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = "router.lan.".parse().unwrap();
        q.query_type = RecordType::AAAA;
        query_aaaa.queries.push(q);

        let resp_aaaa = manager.resolve(&query_aaaa).expect("Expected resolution");
        assert_eq!(resp_aaaa.answers.len(), 1);

        // Test Reverse PTR record
        let mut query_ptr = Message::new(3, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = "1.1.168.192.in-addr.arpa.".parse().unwrap();
        q.query_type = RecordType::PTR;
        query_ptr.queries.push(q);

        let resp_ptr = manager.resolve(&query_ptr).expect("Expected PTR resolution");
        assert_eq!(resp_ptr.answers.len(), 1);

        // Test CNAME resolution
        let mut query_cname = Message::new(4, MessageType::Query, OpCode::Query);
        let mut q = Query::new();
        q.name = "gateway.lan.".parse().unwrap();
        q.query_type = RecordType::A;
        query_cname.queries.push(q);

        let resp_cname = manager.resolve(&query_cname).expect("Expected CNAME resolution");
        // Should have CNAME + target's A record!
        assert_eq!(resp_cname.answers.len(), 2);
    }
}

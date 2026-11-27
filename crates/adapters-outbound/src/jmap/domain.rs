//! `x:Domain` on the wire.

use application::ports::{DesiredDomain, DomainPatch, GatewayError, RemoteDnsServer, RemoteDomain};
use domain::mail_domain::{DnsManagement, RemoteDns};
use serde_json::{Map, Value, json};

/// What a read asks for: the fields compared, nothing else (a full get
/// also computes the domain's DNS zone file).
pub const PROPERTIES: &[&str] = &[
    "id",
    "name",
    "aliases",
    "catchAllAddress",
    "allowRelaying",
    "subAddressing",
    "dkimManagement",
    "dnsManagement",
    "certificateManagement",
];

/// A set, as JMAP spells it.
fn set(values: &[String]) -> Value {
    Value::Object(
        values
            .iter()
            .map(|v| (v.clone(), Value::Bool(true)))
            .collect(),
    )
}

fn variant(name: &str) -> Value {
    json!({"@type": name})
}

/// `dnsManagement` on the wire: `Automatic` with its server, the record
/// types and no `origin` (the domain's own name).
fn dns(dns: &DnsManagement) -> Value {
    match dns {
        DnsManagement::Manual => variant(dns.as_str()),
        DnsManagement::Automatic { server_id, records } => json!({
            "@type": dns.as_str(),
            "dnsServerId": server_id,
            "origin": null,
            "publishRecords": records,
        }),
    }
}

/// The creation of `desired`: every owned field, the server's defaults for
/// the rest (`Automatic` DKIM with its default parameters).
pub fn create(desired: &DesiredDomain) -> Value {
    let mut object = Map::new();
    object.insert("name".into(), desired.name.clone().into());
    object.insert("aliases".into(), set(&desired.aliases));
    if let Some(catch_all) = &desired.catch_all {
        object.insert("catchAllAddress".into(), catch_all.clone().into());
    }
    object.insert("allowRelaying".into(), DesiredDomain::ALLOW_RELAYING.into());
    object.insert(
        "subAddressing".into(),
        variant(desired.sub_addressing.as_str()),
    );
    object.insert("dkimManagement".into(), variant(desired.dkim.as_str()));
    object.insert("dnsManagement".into(), dns(&desired.dns));
    object.insert(
        "certificateManagement".into(),
        variant(DesiredDomain::CERTIFICATE_MANAGEMENT),
    );
    Value::Object(object)
}

/// The fields of `patch`, and only those.
pub fn patch(patch: &DomainPatch) -> Value {
    let mut object = Map::new();
    if let Some(name) = &patch.name {
        object.insert("name".into(), name.clone().into());
    }
    if let Some(aliases) = &patch.aliases {
        object.insert("aliases".into(), set(aliases));
    }
    if let Some(catch_all) = &patch.catch_all {
        object.insert(
            "catchAllAddress".into(),
            catch_all.clone().map_or(Value::Null, Value::from),
        );
    }
    if let Some(relay) = patch.allow_relaying {
        object.insert("allowRelaying".into(), relay.into());
    }
    if let Some(sub) = patch.sub_addressing {
        object.insert("subAddressing".into(), variant(sub.as_str()));
    }
    if let Some(dkim) = patch.dkim {
        object.insert("dkimManagement".into(), variant(dkim.as_str()));
    }
    if let Some(d) = &patch.dns {
        object.insert("dnsManagement".into(), dns(d));
    }
    if let Some(certificate) = patch.certificate {
        object.insert("certificateManagement".into(), variant(certificate));
    }
    Value::Object(object)
}

fn unexpected(field: &str, object: &Value) -> GatewayError {
    GatewayError::Api(format!("x:Domain/get: unexpected {field} in {object}"))
}

fn type_of(object: &Value, field: &str) -> Result<String, GatewayError> {
    object
        .get(field)
        .and_then(|v| v.get("@type"))
        .and_then(Value::as_str)
        .map(String::from)
        .ok_or_else(|| unexpected(field, object))
}

fn remote_dns(object: &Value) -> Result<RemoteDns, GatewayError> {
    let field = object
        .get("dnsManagement")
        .ok_or_else(|| unexpected("dnsManagement", object))?;
    Ok(RemoteDns {
        kind: type_of(object, "dnsManagement")?,
        server_id: field
            .get("dnsServerId")
            .and_then(Value::as_str)
            .map(String::from),
        records: field
            .get("publishRecords")
            .and_then(Value::as_object)
            .map(|r| {
                r.iter()
                    .filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b)))
                    .collect()
            })
            .unwrap_or_default(),
    })
}

/// An `x:DnsServer` as read: its id and its top-level string fields.
pub fn dns_server_from_wire(object: &Value) -> Result<RemoteDnsServer, GatewayError> {
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::Api(format!("x:DnsServer/get: no id in {object}")))?;
    let fields = object
        .as_object()
        .map(|o| {
            o.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();
    Ok(RemoteDnsServer {
        id: id.to_string(),
        fields,
    })
}

/// A domain as read: the set's keys whose value is `true`.
pub fn from_wire(object: &Value) -> Result<RemoteDomain, GatewayError> {
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| unexpected("name", object))?;
    let aliases = match object.get("aliases") {
        Some(Value::Object(set)) => set
            .iter()
            .filter(|(_, v)| v.as_bool() == Some(true))
            .map(|(k, _)| k.clone())
            .collect(),
        None | Some(Value::Null) => Vec::new(),
        Some(_) => return Err(unexpected("aliases", object)),
    };
    let catch_all = match object.get("catchAllAddress") {
        Some(Value::String(s)) => Some(s.clone()),
        None | Some(Value::Null) => None,
        Some(_) => return Err(unexpected("catchAllAddress", object)),
    };
    Ok(RemoteDomain {
        name: name.to_string(),
        aliases,
        catch_all,
        allow_relaying: object
            .get("allowRelaying")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        sub_addressing: type_of(object, "subAddressing")?,
        dkim: type_of(object, "dkimManagement")?,
        dns: remote_dns(object)?,
        certificate: type_of(object, "certificateManagement")?,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn automatic_dns_is_sent_with_its_server_and_records() {
        let records = BTreeMap::from([("caa".to_string(), false)]);
        let wire = dns(&DnsManagement::automatic("srv1", &records));
        assert_eq!(wire["@type"], "Automatic");
        assert_eq!(wire["dnsServerId"], "srv1");
        assert_eq!(wire["origin"], Value::Null);
        assert_eq!(wire["publishRecords"]["caa"], false);
        assert_eq!(wire["publishRecords"]["mx"], true);
        assert_eq!(dns(&DnsManagement::Manual), json!({"@type": "Manual"}));
    }

    #[test]
    fn dns_management_reads_back_as_sent() {
        let sent = DnsManagement::automatic("srv1", &BTreeMap::new());
        let object = json!({
            "name": "weebo.internal",
            "subAddressing": {"@type": "Enabled"},
            "dkimManagement": {"@type": "Automatic"},
            "certificateManagement": {"@type": "Manual"},
            "dnsManagement": dns(&sent),
        });
        let remote = from_wire(&object).unwrap();
        assert!(sent.matches(&remote.dns), "{:?}", remote.dns);
        let manual = json!({"dnsManagement": {"@type": "Manual"}});
        assert_eq!(remote_dns(&manual).unwrap(), RemoteDns::manual());
    }

    #[test]
    fn a_dns_server_keeps_its_string_fields_only() {
        let server = dns_server_from_wire(&json!({
            "id": "srv1",
            "@type": "Route53",
            "hostedZoneId": "Z1",
            "timeout": 30000,
            "secretKey": {"@type": "EnvironmentVariable"},
        }))
        .unwrap();
        assert_eq!(server.id, "srv1");
        assert_eq!(server.fields["@type"], "Route53");
        assert_eq!(server.fields["hostedZoneId"], "Z1");
        assert!(!server.fields.contains_key("timeout"));
        assert!(!server.fields.contains_key("secretKey"));
    }
}

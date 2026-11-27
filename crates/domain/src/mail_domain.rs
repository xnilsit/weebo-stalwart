//! A Stalwart `x:Domain`: the state the operator wants, the one it reads
//! back, and the PATCH between them — only the fields it owns, compared in
//! the form Stalwart stores them (RFC 0001, "Champs comparés et
//! normalisation"):
//!
//! | Field | Comparison |
//! | --- | --- |
//! | `name`, `catchAllAddress`, `allowRelaying` | equality, names lowercased |
//! | `aliases` | set, lowercased (Stalwart stores them as sent) |
//! | `subAddressing`, `certificateManagement` | variant (`@type`) |
//! | `dkimManagement` | variant only: `Automatic`'s parameters are the server's defaults, no opinion |
//! | `dnsManagement` | variant; `Automatic` also `dnsServerId` and the record types the CR names |
//!
//! `emailAddress`-like server-set fields, `description`, `isEnabled`,
//! `reportAddressUri` and the enterprise fields are never compared nor
//! written.

use std::collections::BTreeMap;

use crate::drift::{Drift, same_set};
use crate::mail::normalize_domain;

/// `@type` of the variant fields.
pub mod variant {
    pub const ENABLED: &str = "Enabled";
    pub const DISABLED: &str = "Disabled";
    pub const CUSTOM: &str = "Custom";
    pub const AUTOMATIC: &str = "Automatic";
    pub const MANUAL: &str = "Manual";
}

/// `subAddressing`, as the CR may set it (Stalwart's `Custom`, an
/// expression, is not exposed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubAddressing {
    Enabled,
    Disabled,
}

impl SubAddressing {
    pub const fn as_str(self) -> &'static str {
        match self {
            SubAddressing::Enabled => variant::ENABLED,
            SubAddressing::Disabled => variant::DISABLED,
        }
    }
}

/// `dkimManagement`: `Automatic` with the server's default parameters, or
/// `Manual`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DkimManagement {
    Automatic,
    Manual,
}

impl DkimManagement {
    pub const fn as_str(self) -> &'static str {
        match self {
            DkimManagement::Automatic => variant::AUTOMATIC,
            DkimManagement::Manual => variant::MANUAL,
        }
    }
}

/// The record types of `dnsManagement.publishRecords` Stalwart 1.x knows.
pub const DNS_RECORDS: &[&str] = &[
    "autoConfig",
    "autoConfigLegacy",
    "autoDiscover",
    "caa",
    "dkim",
    "dmarc",
    "mtaSts",
    "mx",
    "spf",
    "srv",
    "tlsRpt",
    "tlsa",
];

/// `dnsManagement`, resolved: `Automatic` names the `x:DnsServer` by id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsManagement {
    Manual,
    Automatic {
        server_id: String,
        /// Every type of [`DNS_RECORDS`], `true` unless the CR turned it
        /// off.
        records: BTreeMap<String, bool>,
    },
}

impl DnsManagement {
    /// `Automatic` on `server_id`, every record type published but those
    /// `records` sets to `false`.
    pub fn automatic(server_id: &str, records: &BTreeMap<String, bool>) -> Self {
        let records = DNS_RECORDS
            .iter()
            .map(|r| (r.to_string(), records.get(*r).copied().unwrap_or(true)))
            .collect();
        DnsManagement::Automatic {
            server_id: server_id.to_string(),
            records,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            DnsManagement::Manual => variant::MANUAL,
            DnsManagement::Automatic { .. } => variant::AUTOMATIC,
        }
    }

    /// Whether `remote` is this state: the variant, then for `Automatic`
    /// the server and every record type named here (a type the operator
    /// doesn't know is no opinion).
    pub fn matches(&self, remote: &RemoteDns) -> bool {
        match self {
            DnsManagement::Manual => remote.kind == variant::MANUAL,
            DnsManagement::Automatic { server_id, records } => {
                remote.kind == variant::AUTOMATIC
                    && remote.server_id.as_deref() == Some(server_id.as_str())
                    && records
                        .iter()
                        .all(|(r, on)| remote.records.get(r).copied().unwrap_or(false) == *on)
            }
        }
    }
}

/// `dnsManagement` as Stalwart returns it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteDns {
    /// The variant's `@type`.
    pub kind: String,
    /// `dnsServerId`, `Automatic` only.
    pub server_id: Option<String>,
    /// `publishRecords`, `Automatic` only.
    pub records: BTreeMap<String, bool>,
}

impl RemoteDns {
    pub fn manual() -> Self {
        RemoteDns {
            kind: variant::MANUAL.into(),
            ..Default::default()
        }
    }
}

/// The domain the operator wants. `certificateManagement` is always
/// `Manual`, `allowRelaying` always `false`: set at creation, put back on
/// drift, not exposed. `dnsManagement` is `Manual` unless
/// [`DesiredDomain::with_dns`] says otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredDomain {
    /// Normalized ([`normalize_domain`]).
    pub name: String,
    /// Normalized, deduplicated, sorted.
    pub aliases: Vec<String>,
    // RFC 0001 Q13: an unset `catchAll` is "no opinion" (RFC 0003's rule
    // for `None`): never cleared by the operator, never compared.
    /// The full catch-all address (`<local>@<name>`), `None`: no opinion.
    pub catch_all: Option<String>,
    pub sub_addressing: SubAddressing,
    pub dkim: DkimManagement,
    pub dns: DnsManagement,
}

impl DesiredDomain {
    pub fn new(
        name: &str,
        aliases: &[String],
        catch_all: Option<&str>,
        sub_addressing: SubAddressing,
        dkim: DkimManagement,
    ) -> Self {
        let name = normalize_domain(name);
        let mut aliases: Vec<String> = aliases.iter().map(|a| normalize_domain(a)).collect();
        aliases.sort();
        aliases.dedup();
        let catch_all = catch_all.map(|local| crate::mail::address(local, &name));
        Self {
            name,
            aliases,
            catch_all,
            sub_addressing,
            dkim,
            dns: DnsManagement::Manual,
        }
    }

    /// The same domain with `dnsManagement` set to `dns`.
    pub fn with_dns(mut self, dns: DnsManagement) -> Self {
        self.dns = dns;
        self
    }

    pub const ALLOW_RELAYING: bool = false;
    pub const CERTIFICATE_MANAGEMENT: &'static str = variant::MANUAL;
}

/// A domain as Stalwart returns it (the owned fields only). Variant fields
/// hold their `@type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDomain {
    pub name: String,
    pub aliases: Vec<String>,
    pub catch_all: Option<String>,
    pub allow_relaying: bool,
    pub sub_addressing: String,
    pub dkim: String,
    pub dns: RemoteDns,
    pub certificate: String,
}

/// The fields of an `x:Domain/set update`: `None` is not sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainPatch {
    pub name: Option<String>,
    pub aliases: Option<Vec<String>>,
    /// `Some(None)` would clear it; the comparison never produces it (an
    /// unset catch-all is no opinion).
    pub catch_all: Option<Option<String>>,
    pub allow_relaying: Option<bool>,
    pub sub_addressing: Option<SubAddressing>,
    pub dkim: Option<DkimManagement>,
    pub dns: Option<DnsManagement>,
    /// Always `Manual` when sent.
    pub certificate: Option<&'static str>,
}

impl DomainPatch {
    /// Changing the name moves every address of the domain: a disruptive
    /// update.
    pub fn renames(&self) -> bool {
        self.name.is_some()
    }
}

/// The update `remote` needs to reach `desired`: the fields already in
/// their desired state left out, the drifted ones named.
pub fn domain_patch(desired: &DesiredDomain, remote: &RemoteDomain) -> (DomainPatch, Drift) {
    let mut patch = DomainPatch {
        name: Some(desired.name.clone()),
        aliases: Some(desired.aliases.clone()),
        catch_all: desired.catch_all.clone().map(Some),
        allow_relaying: Some(DesiredDomain::ALLOW_RELAYING),
        sub_addressing: Some(desired.sub_addressing),
        dkim: Some(desired.dkim),
        dns: Some(desired.dns.clone()),
        certificate: Some(DesiredDomain::CERTIFICATE_MANAGEMENT),
    };
    let mut drift = Drift::default();
    drift.keep_with("name", &mut patch.name, &remote.name, |d, r| {
        *d == normalize_domain(r)
    });
    let remote_aliases: Vec<String> = remote.aliases.iter().map(|a| normalize_domain(a)).collect();
    drift.keep_with("aliases", &mut patch.aliases, &remote_aliases, |d, r| {
        same_set(d, r)
    });
    drift.keep_with(
        "catchAllAddress",
        &mut patch.catch_all,
        &remote.catch_all,
        |d, r| {
            d.as_deref().map(str::to_ascii_lowercase) == r.as_deref().map(str::to_ascii_lowercase)
        },
    );
    drift.keep(
        "allowRelaying",
        &mut patch.allow_relaying,
        &remote.allow_relaying,
    );
    drift.keep_with(
        "subAddressing",
        &mut patch.sub_addressing,
        &remote.sub_addressing,
        |d, r| d.as_str() == r,
    );
    drift.keep_with("dkimManagement", &mut patch.dkim, &remote.dkim, |d, r| {
        d.as_str() == r
    });
    drift.keep_with("dnsManagement", &mut patch.dns, &remote.dns, |d, r| {
        d.matches(r)
    });
    drift.keep_with(
        "certificateManagement",
        &mut patch.certificate,
        &remote.certificate,
        |d, r| d == r,
    );
    (patch, drift)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> DesiredDomain {
        DesiredDomain::new(
            "Weebo.Internal",
            &["Alias.Example".to_string(), "alias.example".to_string()],
            Some("All"),
            SubAddressing::Enabled,
            DkimManagement::Automatic,
        )
    }

    /// What Stalwart stores once `desired()` is created.
    fn stored() -> RemoteDomain {
        RemoteDomain {
            name: "weebo.internal".into(),
            aliases: vec!["alias.example".into()],
            catch_all: Some("all@weebo.internal".into()),
            allow_relaying: false,
            sub_addressing: "Enabled".into(),
            dkim: "Automatic".into(),
            dns: RemoteDns::manual(),
            certificate: "Manual".into(),
        }
    }

    #[test]
    fn the_desired_state_is_normalized() {
        let d = desired();
        assert_eq!(d.name, "weebo.internal");
        assert_eq!(d.aliases, ["alias.example"]);
        assert_eq!(d.catch_all.as_deref(), Some("all@weebo.internal"));
    }

    #[test]
    fn the_stored_form_is_in_sync() {
        let (patch, drift) = domain_patch(&desired(), &stored());
        assert!(drift.is_empty(), "{drift:?}");
        assert_eq!(patch, DomainPatch::default());
    }

    #[test]
    fn aliases_compare_as_a_set_whatever_their_case() {
        let mut remote = stored();
        remote.aliases = vec!["ALIAS.example".into()];
        assert!(domain_patch(&desired(), &remote).1.is_empty());
        remote.aliases.push("extra.example".into());
        let (patch, drift) = domain_patch(&desired(), &remote);
        assert_eq!(drift.fields(), ["aliases"]);
        assert_eq!(patch.aliases, Some(vec!["alias.example".to_string()]));
    }

    #[test]
    fn variants_are_compared_by_type_only() {
        let mut remote = stored();
        remote.sub_addressing = "Custom".into();
        remote.dkim = "Manual".into();
        remote.dns.kind = "Automatic".into();
        let (patch, drift) = domain_patch(&desired(), &remote);
        assert_eq!(
            drift.fields(),
            ["subAddressing", "dkimManagement", "dnsManagement"]
        );
        assert_eq!(patch.sub_addressing, Some(SubAddressing::Enabled));
        assert_eq!(patch.dkim, Some(DkimManagement::Automatic));
        assert_eq!(patch.dns, Some(DnsManagement::Manual));
        assert_eq!(patch.certificate, None);
    }

    fn automatic(records: &[(&str, bool)]) -> DnsManagement {
        let records = records.iter().map(|(r, on)| (r.to_string(), *on)).collect();
        DnsManagement::automatic("srv1", &records)
    }

    /// `remote` as Stalwart stores `dns` once sent.
    fn stored_dns(dns: &DnsManagement) -> RemoteDns {
        match dns {
            DnsManagement::Manual => RemoteDns::manual(),
            DnsManagement::Automatic { server_id, records } => RemoteDns {
                kind: "Automatic".into(),
                server_id: Some(server_id.clone()),
                records: records.clone(),
            },
        }
    }

    #[test]
    fn automatic_dns_publishes_every_type_but_those_turned_off() {
        let records = match automatic(&[("caa", false)]) {
            DnsManagement::Automatic { records, .. } => records,
            DnsManagement::Manual => BTreeMap::new(),
        };
        assert_eq!(records.len(), DNS_RECORDS.len());
        assert!(!records["caa"]);
        assert!(records["mx"]);
    }

    #[test]
    fn automatic_dns_in_sync_once_stored() {
        let dns = automatic(&[("tlsa", false)]);
        let desired = desired().with_dns(dns.clone());
        let mut remote = stored();
        remote.dns = stored_dns(&dns);
        // a record type the operator doesn't know is no opinion
        remote.dns.records.insert("future".into(), true);
        let (patch, drift) = domain_patch(&desired, &remote);
        assert!(drift.is_empty(), "{drift:?}");
        assert_eq!(patch, DomainPatch::default());
    }

    #[test]
    fn automatic_dns_drifts_on_the_server_the_records_and_the_variant() {
        let dns = automatic(&[]);
        let desired = desired().with_dns(dns.clone());
        for edit in [
            (|r: &mut RemoteDns| r.server_id = Some("other".into())) as fn(&mut RemoteDns),
            |r| {
                r.records.insert("mx".into(), false);
            },
            |r| {
                r.records.remove("dkim");
            },
            |r| *r = RemoteDns::manual(),
        ] {
            let mut remote = stored();
            remote.dns = stored_dns(&dns);
            edit(&mut remote.dns);
            let (patch, drift) = domain_patch(&desired, &remote);
            assert_eq!(drift.fields(), ["dnsManagement"]);
            assert_eq!(patch.dns, Some(dns.clone()));
        }
    }

    #[test]
    fn manual_dns_puts_back_an_automatic_one() {
        let mut remote = stored();
        remote.dns = stored_dns(&automatic(&[]));
        let (patch, drift) = domain_patch(&desired(), &remote);
        assert_eq!(drift.fields(), ["dnsManagement"]);
        assert_eq!(patch.dns, Some(DnsManagement::Manual));
    }

    #[test]
    fn an_unset_catch_all_is_no_opinion() {
        let mut desired = desired();
        desired.catch_all = None;
        let mut remote = stored();
        remote.catch_all = Some("by-hand@weebo.internal".into());
        assert!(domain_patch(&desired, &remote).1.is_empty());
    }

    #[test]
    fn a_rename_is_a_disruptive_patch_carrying_the_catch_all() {
        let desired = DesiredDomain::new(
            "new.internal",
            &[],
            Some("all"),
            SubAddressing::Enabled,
            DkimManagement::Automatic,
        );
        let mut remote = stored();
        remote.aliases.clear();
        let (patch, drift) = domain_patch(&desired, &remote);
        assert_eq!(drift.fields(), ["name", "catchAllAddress"]);
        assert!(patch.renames());
        assert_eq!(patch.catch_all, Some(Some("all@new.internal".into())));
    }
}

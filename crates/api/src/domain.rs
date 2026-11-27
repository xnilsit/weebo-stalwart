use std::collections::BTreeMap;

use kube::{CustomResource, ResourceExt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use crate::common::{DeletionPolicy, InstanceRef};
use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::StalwartDomain as Domain;
pub use self::StalwartDomainSpec as DomainSpec;

/// A mail domain of a Stalwart instance (`x:Domain`). Cluster-scoped: a
/// domain is shared by every namespace's accounts, which reference it by
/// name (`domainRef`). Created when missing, then compared on every
/// reconcile and written only when a field the operator owns drifted. Never
/// deleted by the operator: deleting the CR leaves the domain in Stalwart
/// (`deletionPolicy: Orphan`); a domain is removed by hand.
///
/// Stalwart also refuses a name whose top-level label it doesn't know: the
/// special-use ones (`.internal`, `.lan`, `.home.arpa`, `.test`) are
/// accepted, an arbitrary one is not.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "stalwart.weebo.io",
    version = "v1alpha1",
    kind = "StalwartDomain",
    plural = "stalwartdomains",
    status = "Status",
    printcolumn = r#"{"name":"Domain","type":"string","jsonPath":".status.address"}"#,
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct StalwartDomainSpec {
    /// The `StalwartInstance` (or shared `StalwartLocalInstance`) the
    /// domain lives on. Unset: the only `StalwartInstance`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_ref: Option<InstanceRef>,
    /// The domain name (lowercased by Stalwart). Defaults to the CR's
    /// `metadata.name`. Changing it moves every address of the domain: it
    /// is only applied with the annotation
    /// `stalwart.weebo.io/allow-disruptive-update: "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Other domain names delivering to the same mailboxes, compared as a
    /// set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 64))]
    // Drawn by the docs' CRD IDE (the kit's shared schematic kinds).
    #[schemars(extend("x-weebo-produces" = { "kind": { "group": "schematic.weebo.io", "kind": "DnsName" }, "name": ["."] }))]
    pub aliases: Vec<String>,
    /// Local-part receiving mail sent to an unknown address of the domain
    /// (`<catchAll>@<name>`). Unset: no opinion, the catch-all is left as
    /// it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catch_all: Option<String>,
    /// Plus-addressing (`name+tag@domain` delivered to `name@domain`).
    #[serde(default)]
    pub sub_addressing: SubAddressing,
    /// `Automatic`: Stalwart generates the domain's DKIM keys (Ed25519 and
    /// RSA, its default parameters) and signs with them; their DNS records
    /// are published by hand, or by Stalwart with `dns.management:
    /// Automatic`. `Manual`: keys are managed outside the operator.
    #[serde(default)]
    pub dkim: Dkim,
    /// Who publishes the domain's DNS records (`dnsManagement`). Unset:
    /// `Manual`, published by hand.
    #[serde(default)]
    pub dns: DomainDns,
    /// Only `Orphan`: the operator's API key may not destroy domains, and a
    /// domain is removed by hand.
    // RFC 0001 Q17 (D18): refused three times — the schema's CEL rule, the
    // webhook, the reconcile (`InvalidSpec`) — so it holds with the webhook
    // disabled too.
    #[serde(default = "DeletionPolicy::orphan")]
    #[schemars(extend("x-kubernetes-validations" = [
        {"rule": "self == 'Orphan'", "message": "a StalwartDomain is never deleted by the operator: deletionPolicy must be Orphan"}
    ]))]
    pub deletion_policy: DeletionPolicy,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum SubAddressing {
    #[default]
    Enabled,
    Disabled,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum Dkim {
    #[default]
    Automatic,
    Manual,
}

/// `dnsManagement`: `Automatic` has Stalwart publish and update the
/// domain's records (MX, SPF, DKIM, DMARC, MTA-STS, TLSA, …) through an
/// `x:DnsServer` that already exists in Stalwart: the operator selects it,
/// it never creates one.
#[derive(Serialize, Deserialize, Clone, Debug, Default, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.management != 'Automatic' || size(self.serverSelector) > 0", "message": "dns.serverSelector is required when dns.management is Automatic"}
]))]
pub struct DomainDns {
    #[serde(default)]
    pub management: DnsManagement,
    /// The `x:DnsServer` Stalwart publishes through, matched on its
    /// top-level string fields (`@type`, `description`, `hostedZoneId`,
    /// …): exactly one server must match them all. Required with
    /// `Automatic`.
    #[serde(default)]
    #[schemars(length(max = 16))]
    pub server_selector: BTreeMap<String, String>,
    /// Record types (`publishRecords`) set to `false` are not published;
    /// every other type is. Types: `autoConfig`, `autoConfigLegacy`,
    /// `autoDiscover`, `caa`, `dkim`, `dmarc`, `mtaSts`, `mx`, `spf`,
    /// `srv`, `tlsRpt`, `tlsa`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub records: BTreeMap<String, bool>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum DnsManagement {
    #[default]
    Manual,
    Automatic,
}

impl Domain {
    /// The domain name: `spec.name`, or the CR's own name — normalized.
    pub fn domain_name(&self) -> String {
        domain::mail::normalize_domain(&self.spec.name.clone().unwrap_or_else(|| self.name_any()))
    }

    /// `spec.dns` when its management is `Automatic`: the reconcile
    /// resolves `serverSelector` to the server's id, then sets it with
    /// [`domain::mail_domain::DesiredDomain::with_dns`].
    pub fn automatic_dns(&self) -> Option<&DomainDns> {
        let dns = &self.spec.dns;
        (dns.management == DnsManagement::Automatic).then_some(dns)
    }

    /// The state the operator wants in Stalwart, `dnsManagement` `Manual`
    /// (see [`Domain::automatic_dns`]).
    pub fn desired(&self) -> domain::mail_domain::DesiredDomain {
        use domain::mail_domain::{DesiredDomain, DkimManagement, SubAddressing as Sub};
        DesiredDomain::new(
            &self.domain_name(),
            &self.spec.aliases,
            self.spec.catch_all.as_deref(),
            match self.spec.sub_addressing {
                SubAddressing::Enabled => Sub::Enabled,
                SubAddressing::Disabled => Sub::Disabled,
            },
            match self.spec.dkim {
                Dkim::Automatic => DkimManagement::Automatic,
                Dkim::Manual => DkimManagement::Manual,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_fill_the_spec() {
        let spec: DomainSpec = serde_json::from_value(serde_json::json!({})).unwrap();
        assert_eq!(spec.sub_addressing, SubAddressing::Enabled);
        assert_eq!(spec.dkim, Dkim::Automatic);
        assert_eq!(spec.deletion_policy, DeletionPolicy::Orphan);
        assert!(spec.aliases.is_empty());
        assert_eq!(spec.dns, DomainDns::default());
    }

    #[test]
    fn automatic_dns_is_read_from_the_spec() {
        let d = Domain::new(
            "weebo.internal",
            serde_json::from_value(serde_json::json!({"dns": {
                "management": "Automatic",
                "serverSelector": {"@type": "Route53", "hostedZoneId": "Z1"},
                "records": {"caa": false}
            }}))
            .unwrap(),
        );
        let dns = d.automatic_dns().unwrap();
        assert_eq!(dns.server_selector["hostedZoneId"], "Z1");
        assert!(!dns.records["caa"]);
        let manual = Domain::new(
            "weebo.internal",
            serde_json::from_value(serde_json::json!({})).unwrap(),
        );
        assert!(manual.automatic_dns().is_none());
    }

    #[test]
    fn the_schema_requires_a_selector_with_automatic_dns() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(Domain::crd()).unwrap();
        let dns = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]
            ["dns"];
        assert!(
            dns["x-kubernetes-validations"][0]["rule"]
                .as_str()
                .unwrap()
                .contains("serverSelector")
        );
    }

    #[test]
    fn the_name_defaults_to_the_cr_name_normalized() {
        let mut d = Domain::new(
            "Weebo.Internal",
            serde_json::from_value(serde_json::json!({})).unwrap(),
        );
        assert_eq!(d.domain_name(), "weebo.internal");
        d.spec.name = Some("Other.Example.".into());
        d.spec.catch_all = Some("All".into());
        assert_eq!(d.desired().catch_all.as_deref(), Some("all@other.example"));
    }

    #[test]
    fn the_schema_only_admits_orphan() {
        use kube::CustomResourceExt;
        let crd = serde_json::to_value(Domain::crd()).unwrap();
        let policy = &crd["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]
            ["properties"]["deletionPolicy"];
        assert_eq!(
            policy["x-kubernetes-validations"][0]["rule"],
            "self == 'Orphan'"
        );
    }
}

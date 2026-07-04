/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

//! Reading the misfin identity out of a peer's certificate (specification
//! §3.1): mailbox from the USER_ID attribute, blurb from COMMON_NAME, and
//! host(s) from the SUBJECT_ALT_NAME DNS entries.

use x509_parser::prelude::*;

use super::MisfinAddress;

/// What a certificate claims to be, per the spec's identity layout. Any field
/// can be absent — a non-misfin certificate still fingerprints, it just
/// carries no identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateIdentity {
    /// The mailbox name (USER_ID attribute).
    pub mailbox: Option<String>,
    /// The DNS names in SUBJECT_ALT_NAME, lowercased. The first is the
    /// identity's host.
    pub hosts: Vec<String>,
    /// The human-readable blurb (COMMON_NAME).
    pub blurb: Option<String>,
    /// Whether the certificate's validity window excludes `now`.
    pub expired: bool,
}

/// Parse the misfin identity fields out of a DER certificate. Errors only on
/// undecodable DER; missing identity fields are `None`/empty instead.
pub fn parse_certificate_identity(
    certificate_der: &[u8],
    now_unix: u64,
) -> Result<CertificateIdentity, String> {
    let (_, certificate) = X509Certificate::from_der(certificate_der)
        .map_err(|error| format!("certificate DER did not parse: {error}"))?;

    let user_id_oid = x509_parser::der_parser::oid!(0.9.2342.19200300.100.1.1);
    let mut mailbox = None;
    let mut blurb = None;
    for attribute in certificate.subject().iter_attributes() {
        if *attribute.attr_type() == user_id_oid {
            if mailbox.is_none() {
                mailbox = attribute.as_str().ok().map(str::to_string);
            }
        } else if *attribute.attr_type() == oid_registry::OID_X509_COMMON_NAME
            && blurb.is_none()
        {
            blurb = attribute.as_str().ok().map(str::to_string);
        }
    }

    let mut hosts = Vec::new();
    if let Ok(Some(extension)) = certificate.subject_alternative_name() {
        for name in &extension.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                hosts.push(dns.to_ascii_lowercase());
            }
        }
    }

    let expired = ASN1Time::from_timestamp(now_unix as i64)
        .map(|now| !certificate.validity().is_valid_at(now))
        .unwrap_or(false);

    Ok(CertificateIdentity {
        mailbox,
        hosts,
        blurb,
        expired,
    })
}

/// The address a certificate claims (`USER_ID@first-SAN-host`), if it carries
/// both halves.
pub fn claimed_address(identity: &CertificateIdentity) -> Option<MisfinAddress> {
    let mailbox = identity.mailbox.as_deref()?;
    let host = identity.hosts.first()?;
    MisfinAddress::parse(&format!("{mailbox}@{host}")).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::identity_with_validity_years;
    use crate::{MisfinIdentitySpec, deterministic_identity};

    fn spec(addr: &str, blurb: &str) -> MisfinIdentitySpec {
        MisfinIdentitySpec {
            address: MisfinAddress::parse(addr).unwrap(),
            blurb: Some(blurb.to_string()),
        }
    }

    #[test]
    fn our_own_certificates_round_trip_their_identity() {
        let material =
            deterministic_identity(&[5u8; 32], &spec("ana@other.test", "Ana")).unwrap();
        let identity = parse_certificate_identity(&material.certificate_der, 1_800_000_000).unwrap();
        assert_eq!(identity.mailbox.as_deref(), Some("ana"));
        assert_eq!(identity.hosts, vec!["other.test".to_string()]);
        assert_eq!(identity.blurb.as_deref(), Some("Ana"));
        assert!(!identity.expired);

        let claimed = claimed_address(&identity).unwrap();
        assert_eq!(claimed.as_addr_spec(), "ana@other.test");
    }

    #[test]
    fn expiry_is_reported_against_now() {
        let material =
            identity_with_validity_years(&spec("old@stale.test", "Old"), 2001, 2003).unwrap();
        let identity = parse_certificate_identity(&material.certificate_der, 1_800_000_000).unwrap();
        assert!(identity.expired);
    }

    #[test]
    fn undecodable_der_is_an_error_not_a_panic() {
        assert!(parse_certificate_identity(&[0u8; 8], 0).is_err());
    }
}

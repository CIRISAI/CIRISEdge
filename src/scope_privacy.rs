//! Scope-native privacy substrate (CIRISEdge#175, v6.0.0).
//!
//! The CEWP `SCOPE_PRIVACY.md` substrate — realization of CIRIS
//! Constitution **CC 1.13.3.4** "anonymity-by-default at every scope
//! below federation". This module is the edge-side façade over
//! CIRISVerify v6.3.0's `ciris_crypto::scope_privacy` cross-impl
//! authority surface:
//!
//! - §2.2 — `k_record_id` / `k_symbol` group subkeys via bare
//!   `HKDF-SHA256-Expand` on the MLS group's raw `exporter_secret`.
//! - §2.4 — `derive_record_id` (HMAC-SHA3 over RFC 8949 deterministic
//!   CBOR `{v, epc, iid, typ}`) + `derive_symbol_key` (HKDF-SHA3 with
//!   `record_id` salt).
//! - §3.4 — `witness_cover_leaf` (HMAC-SHA3 cover leaf for the
//!   federation witness chain).
//!
//! Verify is the **first conformant impl** per FSD §9; edge MUST
//! reproduce the byte-for-byte vectors. The
//! [`tests::conformance_vectors`] module re-asserts verify's pinned
//! KAT vectors against THIS crate's call path so that any cross-impl
//! drift fires in edge's own CI.
//!
//! # What edge owns vs. what verify owns
//!
//! Verify owns:
//! - the derivation primitives (`hpke`, `xchacha`, `kdf`, `hmac`)
//! - the §2.2 / §2.4 / §3.4 helpers (this module re-exports them)
//! - the `HPKE_SUITE_ID` byte string
//! - the `RecordType` integer encoding
//!
//! Edge owns:
//! - the §3.2 default-cohort_scope flip (`Edge::resolve_default_scope`)
//! - the §3.3 Welcome wrap composition (`mls::welcome_wrap`)
//! - the §3.3 directory cache (`directory_cache`)
//! - the §3.5 per-community `archive_mode` config (`mls::archive_mode`)
//! - the openmls cold-state `StorageProvider` (`mls::scope_state`)
//! - the §3.1 Poisson emission discipline (DEFERRED → v6.1.0)
//! - the §3.4 per-community witness chain split (DEFERRED → v6.1.0)
//! - the §3.3 Leviculum announce-suppression patch (DEFERRED → v6.1.0)

// ─── §2.2 / §2.4 / §3.4 re-exports (verify v6.3.0 authority) ────────

pub use ciris_crypto::scope_privacy::{
    derive_record_id, derive_symbol_key, k_record_id, k_symbol, witness_cover_leaf, RecordType,
    LABEL_RECORD_ID, LABEL_SYMBOL,
};

// ─── §3.3 HPKE_SUITE_ID re-export (verify v6.3.0 pinned bytes) ──────

pub use ciris_crypto::hpke::HPKE_SUITE_ID;

#[cfg(test)]
mod tests {
    //! Cross-impl conformance vectors — edge reproduces verify's pinned
    //! §9 acceptance vectors via THIS crate's re-export call path. If
    //! verify and edge ever diverge on bytes, this module's KATs fire.

    use super::*;

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(s, "{b:02x}").unwrap();
        }
        s
    }

    /// §2.2 subkey KAT — exporter = [0x42; 32].
    #[test]
    fn subkey_kat_matches_verify_v6_3_0() {
        let exporter = [0x42u8; 32];
        assert_eq!(
            hex(&k_record_id(&exporter)),
            "49209926b0439f10d73d63317758b9ec19492429368c6aa67e33232da586af99",
            "k_record_id subkey (cross-impl)"
        );
        assert_eq!(
            hex(&k_symbol(&exporter)),
            "3c973c828a218053dc909c51337ae256164437353bde347ee4bac6874888450f",
            "k_symbol subkey (cross-impl)"
        );
    }

    /// §2.4 record_id KAT vector 1 — CommunityRecord (typ=3), epoch=7.
    #[test]
    fn record_id_vector_1_small() {
        let k = [0x11u8; 32];
        let rid = derive_record_id(&k, b"record-0001", RecordType::CommunityRecord, 7);
        assert_eq!(
            hex(&rid),
            "5428ddb514a8f8692cc4f254f3550ea75790f5069673e42afb6ef318517a0b21",
            "record_id (cross-impl)"
        );
    }

    /// §2.4 record_id KAT vector 2 — FederationRecord (typ=4), u16 epoch.
    #[test]
    fn record_id_vector_2_u16_epoch() {
        let k = [0x11u8; 32];
        let rid = derive_record_id(&k, b"record-0002", RecordType::FederationRecord, 300);
        assert_eq!(
            hex(&rid),
            "04eebeee4d5b83f2fdd0012a205781e6c05fe9a587377e6161b347629a189ff2",
            "record_id (cross-impl)"
        );
    }

    /// §2.4 record_id KAT vector 3 — SelfRecord (typ=1), u32 epoch.
    #[test]
    fn record_id_vector_3_u32_epoch() {
        let k = [0x11u8; 32];
        let rid = derive_record_id(&k, b"x", RecordType::SelfRecord, 16_909_060);
        assert_eq!(
            hex(&rid),
            "79bee8b3f1e815a1df03ca9d83427dc5ab474e184f34e3876d3ef3c36559d6a3",
            "record_id (cross-impl)"
        );
    }

    /// `RecordType` integer encoding (§2.4 pinned table).
    #[test]
    fn record_type_integer_encoding_pinned() {
        assert_eq!(RecordType::SelfRecord.as_cbor_uint(), 1);
        assert_eq!(RecordType::FamilyRecord.as_cbor_uint(), 2);
        assert_eq!(RecordType::CommunityRecord.as_cbor_uint(), 3);
        assert_eq!(RecordType::FederationRecord.as_cbor_uint(), 4);
    }

    /// §3.4 witness cover-leaf — exercise the 12-byte preimage layout.
    #[test]
    fn witness_cover_leaf_deterministic_and_sensitive() {
        let key = [0x55u8; 32];
        let base = witness_cover_leaf(&key, 7, 99);
        assert_eq!(base, witness_cover_leaf(&key, 7, 99));
        assert_ne!(base, witness_cover_leaf(&key, 8, 99));
        assert_ne!(base, witness_cover_leaf(&key, 7, 100));
    }

    /// `HPKE_SUITE_ID` pinned bytes — cross-impl invariant.
    #[test]
    fn hpke_suite_id_pinned() {
        assert_eq!(HPKE_SUITE_ID, b"HPKE-xwing-hkdf-sha256-aes256gcm-v1");
    }

    /// §2.2 labels pinned.
    #[test]
    fn labels_pinned() {
        assert_eq!(LABEL_RECORD_ID, "ciris-edge/scope-privacy/record-id/v1");
        assert_eq!(LABEL_SYMBOL, "ciris-edge/scope-privacy/symbol/v1");
    }

    /// §2.4 symbol_key — deterministic + sensitivity.
    #[test]
    fn symbol_key_deterministic_and_sensitive() {
        let ks = [0x22u8; 32];
        let rid = [0x33u8; 32];
        let base = derive_symbol_key(&ks, &rid, 0);
        assert_eq!(base, derive_symbol_key(&ks, &rid, 0));
        assert_ne!(base, derive_symbol_key(&ks, &rid, 1));
        let mut rid2 = rid;
        rid2[0] ^= 0x01;
        assert_ne!(base, derive_symbol_key(&ks, &rid2, 0));
    }
}

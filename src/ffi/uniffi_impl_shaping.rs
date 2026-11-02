// `needless_pass_by_value` — UDL-exported functions take records by value.
#![allow(clippy::needless_pass_by_value)]

//! v44 (CC 5.4.3 / 5.4.6) — the mobile host's shaping and Anonymous Tier
//! surface. The host reports its device facts whenever they change; the
//! shaping class and the relay policy follow, and the person's shaping
//! opt-in rides in the same record so a Wi-Fi ↔ cellular switch keeps it.

#[cfg(feature = "_reticulum-module")]
fn transport(
) -> Result<std::sync::Arc<crate::transport::reticulum::ReticulumTransport>, crate::EdgeBindingsError>
{
    crate::ffi::uniffi_impl::current_edge()?
        .reticulum_transport()
        .ok_or(crate::EdgeBindingsError::Unsupported)
}

#[cfg(feature = "_reticulum-module")]
fn block_on<F, T>(fut: F) -> Result<T, crate::EdgeBindingsError>
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        Ok(tokio::task::block_in_place(|| handle.block_on(fut)))
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| crate::EdgeBindingsError::Internal)?;
        Ok(rt.block_on(fut))
    }
}

/// The host's device facts changed. Returns how many shaped links closed to
/// renegotiate under the new class.
pub fn shaping_set_device_state(
    state: crate::EdgeDeviceState,
) -> Result<u32, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        use crate::transport::link_shaping::{DeviceKind, DeviceState};
        let kind = DeviceKind::parse(&state.device_kind)
            .ok_or(crate::EdgeBindingsError::InvalidArgument)?;
        let device = DeviceState {
            kind,
            unmetered: state.unmetered,
            charging: state.charging,
            shaping_opt_in: state.shaping_opt_in,
            relay_override: state.relay_override,
        };
        let t = transport()?;
        let closed = block_on(async move { t.set_device_state(device).await })?;
        Ok(u32::try_from(closed).unwrap_or(u32::MAX))
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = state;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

/// The shaping policy in force.
pub fn shaping_status() -> Result<crate::EdgeShapingStatus, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        use crate::transport::link_shaping::ShapingScope;
        let t = transport()?;
        let p = t.shaping_policy();
        Ok(crate::EdgeShapingStatus {
            budget_class: p.class.as_str().to_owned(),
            all_links: p.scope == ShapingScope::AllIdentityLinks,
            bytes_per_s: p.bytes_per_s,
            node_cap_bytes_per_s: p.node_cap_bytes_per_s,
            shaped_links: u32::try_from(t.shaped_link_count()).unwrap_or(u32::MAX),
            layer_reserve_links: p.layer_reserve_links,
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

/// The fleet-default table with each class's monthly cost.
pub fn shaping_class_table() -> Vec<crate::EdgeShapingClassInfo> {
    #[cfg(feature = "_reticulum-module")]
    {
        crate::transport::link_shaping::FLEET_DEFAULTS
            .iter()
            .map(|r| crate::EdgeShapingClassInfo {
                budget_class: r.class.as_str().to_owned(),
                on_by_default: r.on_by_default,
                bytes_per_s: r.class.default_bytes_per_s(),
                gb_month_per_link_each_way: r.gb_month_per_link_each_way,
                gb_month_at_cap_each_way: r.gb_month_at_cap_each_way,
            })
            .collect()
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Vec::new()
    }
}

/// The person opts this node into (or out of) the Anonymous Tier.
pub fn onion_set_enabled(enabled: bool) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let t = transport()?;
        let mut p = t.onion().policy();
        p.enabled = enabled;
        t.onion().set_policy(p);
        t.onion_refresh();
        Ok(())
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = enabled;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

/// The Anonymous Tier on this node, counts only.
pub fn onion_status() -> Result<crate::EdgeOnionStatus, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let s = transport()?.onion().status();
        let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
        Ok(crate::EdgeOnionStatus {
            enabled: s.enabled,
            active: s.active,
            reason: s.reason.map(str::to_owned),
            dealt: s.dealt.iter().map(|&v| n(v)).collect(),
            answering: s.answering.iter().map(|&v| n(v)).collect(),
            relaying: s.relaying,
            relay_reason: s.relay_reason.map(str::to_owned),
            small_set: s.small_set,
            hop_key_source: s.hop_key_source.to_owned(),
            confines_media: s.confines_media,
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

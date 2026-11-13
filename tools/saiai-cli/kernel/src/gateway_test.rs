//! The kernel's own test Gateway extension: the runtime fallback of unit
//! tests, so the kernel's Gateway contract is tested without any
//! distribution's extension.
//!
//! Its session signs every attempt that carries a Bearer with one header
//! whose value spells out the [`SignInput`] the kernel passed, so a test can
//! assert exactly what was signed. It declares one Chat relay and one state
//! file with test names.

use crate::gateway::{
    GatewayExtension, GatewaySession, GatewayStart, NativeChatProtocol, SignInput, StateFile,
};
use std::sync::Arc;

/// The reserved request header the test session adds.
pub(crate) const SIGNATURE_HEADER: &str = "x-test-gateway-signature";

/// The test extension's Chat relay.
pub(crate) const CHAT: NativeChatProtocol = NativeChatProtocol {
    updates_path: "/backend-api/test-gateway/chat-updates",
    preference_restored_header: "x-test-gateway-chat-preference-restored",
    rejected_device_proofs: &["test-gateway-placeholder"],
};

/// The extension's state file in every environment directory.
pub(crate) const STATE_FILE: StateFile = StateFile {
    name: "test-gateway-state.json",
    backups: true,
    atomic_temporaries: true,
};

pub(crate) static TEST_GATEWAY: TestGateway = TestGateway;

pub(crate) struct TestGateway;

impl GatewayExtension for TestGateway {
    fn signature_headers(&self) -> &'static [&'static str] {
        &[SIGNATURE_HEADER]
    }

    fn start(&self, _start: GatewayStart) -> Arc<dyn GatewaySession> {
        Arc::new(TestGatewaySession)
    }

    fn native_chat(&self) -> Option<NativeChatProtocol> {
        Some(CHAT)
    }

    fn owned_state_files(&self) -> &'static [StateFile] {
        &[STATE_FILE]
    }
}

pub(crate) struct TestGatewaySession;

impl GatewaySession for TestGatewaySession {
    fn sign(&self, input: &SignInput<'_>) -> Vec<(String, String)> {
        match input.bearer {
            Some(bearer) => vec![(SIGNATURE_HEADER.to_string(), signature(input, bearer))],
            None => Vec::new(),
        }
    }
}

/// `<transport> <method> <gateway> <target> <bearer>`: the value the test
/// session signs `input` with.
pub(crate) fn signature(input: &SignInput<'_>, bearer: &str) -> String {
    format!(
        "{:?} {} {} {} {bearer}",
        input.transport, input.method, input.gateway, input.target
    )
}

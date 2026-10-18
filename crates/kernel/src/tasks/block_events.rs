// Copyright (C) 2026 Ryan Daum <ryan.daum@gmail.com> This program is free
// software: you can redistribute it and/or modify it under the terms of the GNU
// Affero General Public License as published by the Free Software Foundation,
// version 3.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License along
// with this program. If not, see <https://www.gnu.org/licenses/>.

//! The canonical byte encoding of one event batch entry's `event` (RuneWorld block format v1,
//! `docs/spec/block-format-v0.md` §11, "Event encoding"), so that a replayer can recompute
//! `events_root` from re-executed events.
//!
//! The encoding is a single CBOR item in the state root's profile (`state-root-v0.md` §2: RFC 8949
//! §4.2.1 deterministic CBOR, no floats, no tags), and every MOO value inside it is a state-root
//! `Var` (§3.2). It lives in the kernel rather than in `moor-block` because it encodes the kernel's
//! [`BlockEventKind`] and reuses `moor_db`'s `Var` encoder; `moor-block` keeps treating the bytes as
//! opaque.
//!
//! ```text
//! event      = [0, narrative]                        ; Narrative (notify, present, ...)
//!            | [1, narrative]                        ; Logged (event_log only)
//!            | [2, text]                             ; System message (traceback, abort)
//!            | [3, kind | null, session, code, text] ; Rejected envelope
//!            | [4, admitted]                         ; Sessions (delegation, revocation)
//! narrative  = [event_id (bytes 16), secs, nanos, author (var), body]
//! body       = [0, value (var), content_type (text | null), no_flush (bool), no_newline (bool),
//!               metadata ([[key (text), value (var)]...] | null)]                  ; Notify
//!            | [1, id, content_type, content, target, [[name, value]...]]      ; Present (all text)
//!            | [2, id (text)]                                                    ; Unpresent
//!            | [3, error (var), [stack var...], [backtrace var...]]             ; Traceback
//!            | [4, namespace (text), kind (text), payload (var)]                 ; Data
//!            | [5, connection (obj), option (text), value (var)]                 ; SetConnectionOption
//! admitted   = [0, player, session] | [1, player, session]                     ; Command | Connect
//!            | [2, player, session, created (bool)]                              ; Delegated
//!            | [3, player, [session...]]                                       ; Revoked
//! ```
//!
//! Symbols are text in their stored case; objects are state-root object encodings (`#N` is `N`).
//! Lists keep their order (metadata and presentation attributes are ordered sequences).
//! `kind` is the envelope kind byte; `code` is [`rejection_code`]; `text` is the rejection's
//! display string. `event_id` and the timestamp are deterministic in deterministic mode (block
//! time; ids from `(height, command, counter)`), so they are part of the commitment.

use crate::tasks::{
    block_driver::{BlockEvent, BlockEventKind},
    envelope_admission::{AdmissionRejection, Admitted},
};
use moor_common::{
    envelope::EnvelopeKind,
    tasks::{Event, NarrativeEvent},
};
use moor_db::state_root::{
    cbor::{CborError, Encoder},
    values,
};
use moor_var::{Obj, Var, v_error};
use std::time::UNIX_EPOCH;

/// Tags of the outer `event` array.
pub mod event_tag {
    pub const NARRATIVE: u64 = 0;
    pub const LOGGED: u64 = 1;
    pub const SYSTEM: u64 = 2;
    pub const REJECTED: u64 = 3;
    pub const SESSIONS: u64 = 4;
}

/// Tags of a narrative `body`.
pub mod body_tag {
    pub const NOTIFY: u64 = 0;
    pub const PRESENT: u64 = 1;
    pub const UNPRESENT: u64 = 2;
    pub const TRACEBACK: u64 = 3;
    pub const DATA: u64 = 4;
    pub const SET_CONNECTION_OPTION: u64 = 5;
}

/// The stable number of an admission rejection reason in the event encoding.
#[must_use]
pub fn rejection_code(reason: &AdmissionRejection) -> u64 {
    match reason {
        AdmissionRejection::Malformed(_) => 0,
        AdmissionRejection::NotDeterministic => 1,
        AdmissionRejection::UnknownSession(_) => 2,
        AdmissionRejection::BadSignature => 3,
        AdmissionRejection::BadWalletSignature(_) => 4,
        AdmissionRejection::SessionRevoked(_) => 5,
        AdmissionRejection::SessionExpired { .. } => 6,
        AdmissionRejection::WrongScope { .. } => 7,
        AdmissionRejection::StaleNonce { .. } => 8,
        AdmissionRejection::Expired { .. } => 9,
        AdmissionRejection::BadRevokeTarget(_) => 10,
        AdmissionRejection::UnknownWallet(_) => 11,
        AdmissionRejection::WalletHasPlayer { .. } => 12,
        AdmissionRejection::StaleDelegationNonce { .. } => 13,
        AdmissionRejection::DelegationExpired { .. } => 14,
        AdmissionRejection::BadScope(_) => 15,
        AdmissionRejection::DuplicateSessionKey(_) => 16,
        AdmissionRejection::CreationFailed(_) => 17,
        AdmissionRejection::Storage(_) => 18,
    }
}

fn kind_code(kind: EnvelopeKind) -> u64 {
    match kind {
        EnvelopeKind::Command => 0,
        EnvelopeKind::Connect => 1,
        EnvelopeKind::Delegate => 2,
        EnvelopeKind::Revoke => 3,
        EnvelopeKind::RevokeAll => 4,
    }
}

/// Encode one event (the batch entry's `event` byte string).
pub fn encode_event(kind: &BlockEventKind) -> Result<Vec<u8>, CborError> {
    let mut e = Encoder::new();
    match kind {
        BlockEventKind::Narrative(event) => {
            e.array(2);
            e.uint(event_tag::NARRATIVE);
            narrative(&mut e, event)?;
        }
        BlockEventKind::Logged(event) => {
            e.array(2);
            e.uint(event_tag::LOGGED);
            narrative(&mut e, event)?;
        }
        BlockEventKind::System(text) => {
            e.array(2);
            e.uint(event_tag::SYSTEM);
            e.text(text);
        }
        BlockEventKind::Rejected {
            kind,
            session,
            reason,
        } => {
            e.array(5);
            e.uint(event_tag::REJECTED);
            match kind {
                Some(kind) => e.uint(kind_code(*kind)),
                None => e.null(),
            }
            e.uint(u64::from(*session));
            e.uint(rejection_code(reason));
            e.text(&reason.to_string());
        }
        BlockEventKind::Sessions(admitted) => {
            e.array(2);
            e.uint(event_tag::SESSIONS);
            admitted_into(&mut e, admitted);
        }
    }
    Ok(e.into_bytes())
}

/// The batch entry fields of `event`: `(seq, command_index, recipient, event bytes)`.
pub fn entry_parts(event: &BlockEvent) -> Result<(u64, u64, i32, Vec<u8>), CborError> {
    if !event.player.is_oid() {
        return Err(CborError::Invalid(format!(
            "recipient {} is not a numbered object",
            event.player
        )));
    }
    let recipient = event.player.id().0;
    Ok((
        event.seq,
        event.command_index,
        recipient,
        encode_event(&event.kind)?,
    ))
}

fn obj(e: &mut Encoder, o: &Obj) {
    values::obj(e, o);
}

fn var(e: &mut Encoder, v: &Var) -> Result<(), CborError> {
    values::var(e, v)
}

fn narrative(e: &mut Encoder, event: &NarrativeEvent) -> Result<(), CborError> {
    let since_epoch = event
        .timestamp
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CborError::Invalid("event timestamp before the epoch".into()))?;
    e.array(5);
    e.bytes(event.event_id.as_bytes());
    e.uint(since_epoch.as_secs());
    e.uint(u64::from(since_epoch.subsec_nanos()));
    var(e, &event.author)?;
    body(e, &event.event)
}

fn body(e: &mut Encoder, event: &Event) -> Result<(), CborError> {
    match event {
        Event::Notify {
            value,
            content_type,
            no_flush,
            no_newline,
            metadata,
        } => {
            e.array(6);
            e.uint(body_tag::NOTIFY);
            var(e, value)?;
            match content_type {
                Some(ct) => e.text(ct.as_str()),
                None => e.null(),
            }
            e.bool(*no_flush);
            e.bool(*no_newline);
            match metadata {
                Some(pairs) => {
                    e.array(pairs.len());
                    for (key, value) in pairs {
                        e.array(2);
                        e.text(key.as_str());
                        var(e, value)?;
                    }
                }
                None => e.null(),
            }
        }
        Event::Present(p) => {
            e.array(6);
            e.uint(body_tag::PRESENT);
            e.text(&p.id);
            e.text(&p.content_type);
            e.text(&p.content);
            e.text(&p.target);
            e.array(p.attributes.len());
            for (name, value) in &p.attributes {
                e.array(2);
                e.text(name);
                e.text(value);
            }
        }
        Event::Unpresent(id) => {
            e.array(2);
            e.uint(body_tag::UNPRESENT);
            e.text(id);
        }
        Event::Traceback(exception) => {
            e.array(4);
            e.uint(body_tag::TRACEBACK);
            var(e, &v_error(exception.error.clone()))?;
            e.array(exception.stack.len());
            for frame in &exception.stack {
                var(e, frame)?;
            }
            e.array(exception.backtrace.len());
            for line in &exception.backtrace {
                var(e, line)?;
            }
        }
        Event::Data {
            namespace,
            kind,
            payload,
        } => {
            e.array(4);
            e.uint(body_tag::DATA);
            e.text(namespace.as_str());
            e.text(kind.as_str());
            var(e, payload)?;
        }
        Event::SetConnectionOption {
            connection,
            option,
            value,
        } => {
            e.array(4);
            e.uint(body_tag::SET_CONNECTION_OPTION);
            obj(e, connection);
            e.text(option.as_str());
            var(e, value)?;
        }
    }
    Ok(())
}

fn admitted_into(e: &mut Encoder, admitted: &Admitted) {
    match admitted {
        Admitted::Command { player, session } => {
            e.array(3);
            e.uint(0);
            obj(e, player);
            e.uint(u64::from(*session));
        }
        Admitted::Connect { player, session } => {
            e.array(3);
            e.uint(1);
            obj(e, player);
            e.uint(u64::from(*session));
        }
        Admitted::Delegated {
            player,
            session,
            created,
        } => {
            e.array(4);
            e.uint(2);
            obj(e, player);
            e.uint(u64::from(*session));
            e.bool(*created);
        }
        Admitted::Revoked { player, sessions } => {
            e.array(3);
            e.uint(3);
            obj(e, player);
            e.array(sessions.len());
            for s in sessions {
                e.uint(u64::from(*s));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use moor_common::tasks::Presentation;
    use moor_db::state_root::hex;
    use moor_var::{E_PERM, Symbol, v_int, v_obj, v_str};
    use std::time::{Duration, SystemTime};
    use uuid::Uuid;

    fn narrative_event(event: Event) -> Box<NarrativeEvent> {
        Box::new(NarrativeEvent {
            event_id: Uuid::from_bytes([0x11; 16]),
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(1_760_000_000),
            author: v_obj(Obj::mk_id(4)),
            event,
        })
    }

    fn notify(text: &str) -> Event {
        Event::Notify {
            value: v_str(text),
            content_type: None,
            no_flush: false,
            no_newline: false,
            metadata: None,
        }
    }

    fn encoded(kind: &BlockEventKind) -> String {
        hex(&encode_event(kind).unwrap())
    }

    // Spec vectors (block-format-v0.md §11). Recomputed independently in Python from the grammar.

    #[test]
    fn notify_vector() {
        assert_eq!(
            encoded(&BlockEventKind::Narrative(narrative_event(notify(
                "You go west."
            )))),
            "82008550111111111111111111111111111111111a68e7780000820504\
             860082046c596f7520676f20776573742ef6f4f4f6"
        );
    }

    #[test]
    fn system_vector() {
        assert_eq!(
            encoded(&BlockEventKind::System("Task aborted".into())),
            "82026c5461736b2061626f72746564"
        );
    }

    #[test]
    fn rejected_vector() {
        assert_eq!(
            encoded(&BlockEventKind::Rejected {
                kind: Some(EnvelopeKind::Command),
                session: 1,
                reason: AdmissionRejection::StaleNonce { last: 5, got: 3 },
            }),
            "8503000108767374616c65206e6f6e6365203320286c617374203529"
        );
    }

    #[test]
    fn sessions_vector() {
        assert_eq!(
            encoded(&BlockEventKind::Sessions(Admitted::Delegated {
                player: Obj::mk_id(15),
                session: 2,
                created: true,
            })),
            "820484020f02f5"
        );
    }

    #[test]
    fn logged_differs_from_narrative_only_in_the_tag() {
        let n = encode_event(&BlockEventKind::Narrative(narrative_event(notify("x")))).unwrap();
        let l = encode_event(&BlockEventKind::Logged(narrative_event(notify("x")))).unwrap();
        assert_eq!((n[1], l[1], &n[2..]), (0x00, 0x01, &l[2..]));
    }

    #[test]
    fn notify_with_metadata_and_content_type_round_trips_through_diagnostic() {
        let event = Event::Notify {
            value: v_int(1),
            content_type: Some(Symbol::mk("text/djot")),
            no_flush: true,
            no_newline: false,
            metadata: Some(vec![(Symbol::mk("Actor"), v_obj(Obj::mk_id(2)))]),
        };
        let bytes = encode_event(&BlockEventKind::Narrative(narrative_event(event))).unwrap();
        let diag = moor_db::state_root::cbor::diagnostic(&bytes, false).unwrap();
        assert!(
            diag.contains("\"text/djot\"") && diag.contains("\"Actor\""),
            "{diag}"
        );
    }

    #[test]
    fn every_body_kind_encodes() {
        let bodies = [
            notify("a"),
            Event::Present(Presentation {
                id: "p".into(),
                content_type: "text/plain".into(),
                content: "c".into(),
                target: "inventory".into(),
                attributes: vec![("title".into(), "T".into())],
            }),
            Event::Unpresent("p".into()),
            Event::Traceback(moor_common::tasks::Exception {
                error: E_PERM.msg("no"),
                stack: vec![v_int(1)],
                backtrace: vec![v_str("line")],
            }),
            Event::Data {
                namespace: Symbol::mk("osrs"),
                kind: Symbol::mk("sync"),
                payload: v_int(3),
            },
            Event::SetConnectionOption {
                connection: Obj::mk_id(-5),
                option: Symbol::mk("binary"),
                value: v_int(1),
            },
        ];
        let tags: Vec<u8> = bodies
            .into_iter()
            .map(|b| {
                let bytes = encode_event(&BlockEventKind::Narrative(narrative_event(b))).unwrap();
                // [0, [id, secs, nanos, author, [tag, ...]]]: the body tag follows the author.
                bytes[2 + 1 + 17 + 5 + 1 + 3 + 1]
            })
            .collect();
        assert_eq!(tags, vec![0, 1, 2, 3, 4, 5]);
    }
}

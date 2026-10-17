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

//! Canonical encodings of the values stored in the world relations (state encoding v1). The
//! layouts are specified in RuneWorld `docs/spec/state-root-v0.md`; this file is the reference
//! implementation. Each encoder has a decoder so that the encoding is checked to be lossless.

use super::cbor::{CborError, Decoder, Encoder};
use moor_common::{
    model::{
        ArgSpec, HasUuid, Named, PrepSpec, PropDef, PropDefs, PropPerms, ValSet, VerbArgsSpec,
        VerbDef, VerbDefs,
    },
    util::BitEnum,
};
use moor_schema::{
    convert_program::{decode_stored_program_ref, encode_program_to_fb},
    program::{StoredMooRProgram, StoredProgram, StoredProgramLanguage, StoredProgramRef},
};
use moor_var::{
    Error, ErrorCode, Obj, Symbol, Var, Variant,
    program::{
        ProgramType,
        labels::Label,
        names::Name,
        opcode::{ScatterArgs, ScatterLabel},
        program::Program,
    },
    v_binary, v_bool, v_error, v_float, v_flyweight, v_int, v_list, v_map, v_none, v_obj, v_str,
    v_sym,
};
use planus::ReadAsRoot;
use uuid::Uuid;

/// Var type codes (first element of every encoded Var).
pub mod var_type {
    pub const NONE: u64 = 0;
    pub const BOOL: u64 = 1;
    pub const INT: u64 = 2;
    pub const FLOAT: u64 = 3;
    pub const STR: u64 = 4;
    pub const OBJ: u64 = 5;
    pub const ERR: u64 = 6;
    pub const LIST: u64 = 7;
    pub const MAP: u64 = 8;
    pub const SYM: u64 = 9;
    pub const BINARY: u64 = 10;
    pub const FLYWEIGHT: u64 = 11;
    pub const LAMBDA: u64 = 12;
}

const MAJOR_ARRAY: u8 = 4;
const MAJOR_TEXT: u8 = 3;

const OBJ_TYPE_SHIFT: u32 = 62;
const OBJ_ID_MASK: u64 = (1 << OBJ_TYPE_SHIFT) - 1;

/// Deepest nesting of Vars the encoder accepts. MOO values are acyclic; this guards the stack.
const MAX_DEPTH: usize = 512;

fn invalid(msg: impl Into<String>) -> CborError {
    CborError::Invalid(msg.into())
}

// ---------------------------------------------------------------------------------------------
// Objects and identifiers

/// `#N` is the integer N. A UUID object id is `[1, id]`, an anonymous object `[2, id]`, where `id`
/// is the 62-bit identifier below the type bits.
pub fn obj(e: &mut Encoder, o: &Obj) {
    let code = o.as_u64() >> OBJ_TYPE_SHIFT;
    if code == 0 {
        e.int(i64::from(o.id().0));
    } else {
        e.array(2);
        e.uint(code);
        e.uint(o.as_u64() & OBJ_ID_MASK);
    }
}

pub fn decode_obj(d: &mut Decoder<'_>) -> Result<Obj, CborError> {
    let at = d.position();
    if d.peek_major()? != MAJOR_ARRAY {
        let id = i32::try_from(d.int()?).map_err(|_| invalid("object number out of range"))?;
        return Ok(Obj::mk_id(id));
    }
    d.array_of(2)?;
    let code = d.uint()?;
    let id = d.uint()?;
    if !(1..=2).contains(&code) || id > OBJ_ID_MASK {
        return Err(invalid(format!("bad object id at byte {at}")));
    }
    Obj::try_read((code << OBJ_TYPE_SHIFT) | id).map_err(|e| invalid(e.to_string()))
}

pub fn uuid(e: &mut Encoder, u: &Uuid) {
    e.bytes(u.as_bytes());
}

pub fn decode_uuid(d: &mut Decoder<'_>) -> Result<Uuid, CborError> {
    let b = d.bytes()?;
    Uuid::from_slice(b).map_err(|_| invalid("uuid must be 16 bytes"))
}

/// Symbols keep their stored case; equality and ordering are the engine's business, the encoding
/// only has to be a function of the stored value.
fn symbol(e: &mut Encoder, s: &Symbol) {
    e.text(s.as_arc_str().as_str());
}

// ---------------------------------------------------------------------------------------------
// Var

/// Encode a Var as `[type, payload...]`. Maps and flyweight slots are CBOR maps whose keys sort
/// bytewise (RFC 8949 §4.2.1), so the encoding never depends on the engine's `Var` ordering (which
/// for symbols depends on interning order before S0-6).
pub fn var(e: &mut Encoder, v: &Var) -> Result<(), CborError> {
    var_at(e, v, 0)
}

fn encoded_var(v: &Var, depth: usize) -> Result<Vec<u8>, CborError> {
    let mut e = Encoder::new();
    var_at(&mut e, v, depth)?;
    Ok(e.into_bytes())
}

fn var_at(e: &mut Encoder, v: &Var, depth: usize) -> Result<(), CborError> {
    use var_type as t;
    if depth > MAX_DEPTH {
        return Err(invalid("value nesting too deep"));
    }
    let next = depth + 1;
    match v.variant() {
        Variant::None => {
            e.array(1);
            e.uint(t::NONE);
        }
        Variant::Bool(b) => {
            e.array(2);
            e.uint(t::BOOL);
            e.bool(b);
        }
        Variant::Int(i) => {
            e.array(2);
            e.uint(t::INT);
            e.int(i);
        }
        Variant::Float(f) => {
            e.array(2);
            e.uint(t::FLOAT);
            e.uint(f.to_bits());
        }
        Variant::Str(s) => {
            e.array(2);
            e.uint(t::STR);
            e.text(s.as_str());
        }
        Variant::Obj(o) => {
            e.array(2);
            e.uint(t::OBJ);
            obj(e, &o);
        }
        Variant::Err(err) => {
            e.array(4);
            e.uint(t::ERR);
            match err.err_type() {
                ErrorCode::ErrCustom(sym) => symbol(e, &sym),
                _ => e.uint(u64::from(
                    err.to_int()
                        .ok_or_else(|| invalid("error code has no number"))?,
                )),
            }
            match err.msg() {
                Some(m) => e.text(m),
                None => e.null(),
            }
            match err.value() {
                Some(inner) => var_at(e, inner, next)?,
                None => e.null(),
            }
        }
        Variant::List(l) => {
            e.array(2);
            e.uint(t::LIST);
            e.array(l.len());
            for item in l.iter_ref() {
                var_at(e, item, next)?;
            }
        }
        Variant::Map(m) => {
            e.array(2);
            e.uint(t::MAP);
            let pairs = m
                .iter_ref()
                .map(|(k, v)| Ok((encoded_var(k, next)?, encoded_var(v, next)?)))
                .collect::<Result<Vec<_>, CborError>>()?;
            e.map_of_encoded(pairs)?;
        }
        Variant::Sym(s) => {
            e.array(2);
            e.uint(t::SYM);
            symbol(e, &s);
        }
        Variant::Binary(b) => {
            e.array(2);
            e.uint(t::BINARY);
            e.bytes(b.as_bytes());
        }
        Variant::Flyweight(f) => {
            e.array(4);
            e.uint(t::FLYWEIGHT);
            obj(e, f.delegate());
            let slots = f
                .slots_storage()
                .iter()
                .map(|(name, value)| {
                    let mut k = Encoder::new();
                    symbol(&mut k, name);
                    Ok((k.into_bytes(), encoded_var(value, next)?))
                })
                .collect::<Result<Vec<_>, CborError>>()?;
            e.map_of_encoded(slots)?;
            e.array(f.contents().len());
            for item in f.contents().iter_ref() {
                var_at(e, item, next)?;
            }
        }
        Variant::Lambda(l) => {
            e.array(5);
            e.uint(t::LAMBDA);
            scatter_args(e, &l.0.params);
            e.bytes(&program_bytes(&l.0.body)?);
            e.array(l.0.captured_env.len());
            for frame in &l.0.captured_env {
                e.array(frame.len());
                for item in frame {
                    var_at(e, item, next)?;
                }
            }
            match &l.0.self_var {
                Some(n) => name(e, n),
                None => e.null(),
            }
        }
    }
    Ok(())
}

pub fn decode_var(d: &mut Decoder<'_>) -> Result<Var, CborError> {
    decode_var_at(d, 0)
}

fn decode_var_at(d: &mut Decoder<'_>, depth: usize) -> Result<Var, CborError> {
    use var_type as t;
    if depth > MAX_DEPTH {
        return Err(invalid("value nesting too deep"));
    }
    let next = depth + 1;
    let at = d.position();
    let len = d.array()?;
    let code = d.uint()?;
    let want = match code {
        t::NONE => 1,
        t::ERR | t::FLYWEIGHT => 4,
        t::LAMBDA => 5,
        t::BOOL..=t::BINARY => 2,
        _ => return Err(invalid(format!("unknown Var type {code} at byte {at}"))),
    };
    if len != want {
        return Err(invalid(format!(
            "Var type {code} needs {want} elements at byte {at}"
        )));
    }
    Ok(match code {
        t::NONE => v_none(),
        t::BOOL => v_bool(d.bool()?),
        t::INT => v_int(d.int()?),
        t::FLOAT => {
            let f = f64::from_bits(d.uint()?);
            if !f.is_finite() {
                return Err(invalid("MOO floats are finite"));
            }
            v_float(f)
        }
        t::STR => v_str(d.text()?),
        t::OBJ => v_obj(decode_obj(d)?),
        t::ERR => {
            let code = if d.peek_major()? == MAJOR_TEXT {
                ErrorCode::ErrCustom(Symbol::mk(d.text()?))
            } else {
                let n = u8::try_from(d.uint()?).map_err(|_| invalid("error code out of range"))?;
                Error::from_repr(n)
                    .ok_or_else(|| invalid(format!("unknown error code {n}")))?
                    .err_type()
            };
            let msg = if d.null()? {
                None
            } else {
                Some(d.text()?.to_string())
            };
            let value = if d.null()? {
                None
            } else {
                Some(decode_var_at(d, next)?)
            };
            v_error(Error::new(code, msg, value))
        }
        t::LIST => {
            let n = d.array()?;
            let items = (0..n)
                .map(|_| decode_var_at(d, next))
                .collect::<Result<Vec<_>, _>>()?;
            v_list(&items)
        }
        t::MAP => {
            check_canonical_map(d)?;
            let n = d.map()?;
            let pairs = (0..n)
                .map(|_| Ok((decode_var_at(d, next)?, decode_var_at(d, next)?)))
                .collect::<Result<Vec<_>, CborError>>()?;
            v_map(&pairs)
        }
        t::SYM => v_sym(Symbol::mk(d.text()?)),
        t::BINARY => v_binary(d.bytes()?.to_vec()),
        t::FLYWEIGHT => {
            let delegate = decode_obj(d)?;
            check_canonical_map(d)?;
            let n = d.map()?;
            let slots = (0..n)
                .map(|_| Ok((Symbol::mk(d.text()?), decode_var_at(d, next)?)))
                .collect::<Result<Vec<_>, CborError>>()?;
            let n = d.array()?;
            let contents = (0..n)
                .map(|_| decode_var_at(d, next))
                .collect::<Result<Vec<_>, _>>()?;
            let contents = v_list(&contents)
                .as_list()
                .ok_or_else(|| invalid("flyweight contents"))?
                .clone();
            v_flyweight(delegate, &slots, contents)
        }
        t::LAMBDA => {
            let params = decode_scatter_args(d)?;
            let body = decode_program_bytes(d.bytes()?)?;
            let frames = d.array()?;
            let captured_env = (0..frames)
                .map(|_| {
                    let n = d.array()?;
                    (0..n)
                        .map(|_| decode_var_at(d, next))
                        .collect::<Result<Vec<_>, _>>()
                })
                .collect::<Result<Vec<_>, CborError>>()?;
            let self_var = if d.null()? {
                None
            } else {
                Some(decode_name(d)?)
            };
            Var::mk_lambda(params, body, captured_env, self_var)
        }
        _ => unreachable!("type checked above"),
    })
}

/// Check that the map at the cursor has canonical key order, without consuming it.
fn check_canonical_map(d: &Decoder<'_>) -> Result<(), CborError> {
    d.clone().item().map(|_| ())
}

// ---------------------------------------------------------------------------------------------
// Programs

/// The fork's stored program encoding (the moor-schema `StoredProgram` FlatBuffer), with one
/// normalisation: the variable declarations, which the engine keeps in a `std` `HashMap` and so
/// emits in a per-process random order, are sorted by `(offset, scope depth, scope id)`. Lambda
/// programs nested in the program are normalised the same way.
pub fn program_bytes(p: &Program) -> Result<Vec<u8>, CborError> {
    let mut stored: StoredProgram =
        encode_program_to_fb(p).map_err(|e| invalid(format!("program: {e}")))?;
    let StoredProgramLanguage::StoredMooRProgram(moo) = &mut stored.language;
    normalise_program(moo);
    let mut builder = planus::Builder::new();
    Ok(builder.finish(stored, None).to_vec())
}

fn normalise_program(p: &mut StoredMooRProgram) {
    p.var_names
        .decls
        .sort_unstable_by_key(|pair| (pair.name.offset, pair.name.scope_depth, pair.name.scope_id));
    for lambda in &mut p.lambda_programs {
        normalise_program(lambda);
    }
}

pub fn decode_program_bytes(bytes: &[u8]) -> Result<Program, CborError> {
    let stored = StoredProgramRef::read_as_root(bytes).map_err(|e| invalid(e.to_string()))?;
    decode_stored_program_ref(stored).map_err(|e| invalid(e.to_string()))
}

/// `object_verbs` value: `[0, program]` (0 = the MooR language).
pub fn program_type(e: &mut Encoder, p: &ProgramType) -> Result<(), CborError> {
    let ProgramType::MooR(p) = p;
    e.array(2);
    e.uint(0);
    e.bytes(&program_bytes(p)?);
    Ok(())
}

pub fn decode_program_type(d: &mut Decoder<'_>) -> Result<ProgramType, CborError> {
    d.array_of(2)?;
    if d.uint()? != 0 {
        return Err(invalid("unknown program language"));
    }
    Ok(ProgramType::MooR(decode_program_bytes(d.bytes()?)?))
}

fn name(e: &mut Encoder, n: &Name) {
    e.array(3);
    e.uint(u64::from(n.0));
    e.uint(u64::from(n.1));
    e.uint(u64::from(n.2));
}

fn decode_name(d: &mut Decoder<'_>) -> Result<Name, CborError> {
    d.array_of(3)?;
    let range = || invalid("name component out of range");
    Ok(Name(
        u16::try_from(d.uint()?).map_err(|_| range())?,
        u8::try_from(d.uint()?).map_err(|_| range())?,
        u16::try_from(d.uint()?).map_err(|_| range())?,
    ))
}

/// Lambda parameters: `[[label...], done]`; a label is `[0, name, default-label | null]`
/// (optional), `[1, name]` (required) or `[2, name]` (rest).
fn scatter_args(e: &mut Encoder, a: &ScatterArgs) {
    e.array(2);
    e.array(a.labels.len());
    for label in &a.labels {
        match label {
            ScatterLabel::Optional(n, default) => {
                e.array(3);
                e.uint(0);
                name(e, n);
                match default {
                    Some(l) => e.uint(u64::from(l.0)),
                    None => e.null(),
                }
            }
            ScatterLabel::Required(n) => {
                e.array(2);
                e.uint(1);
                name(e, n);
            }
            ScatterLabel::Rest(n) => {
                e.array(2);
                e.uint(2);
                name(e, n);
            }
        }
    }
    e.uint(u64::from(a.done.0));
}

fn decode_label(d: &mut Decoder<'_>) -> Result<Label, CborError> {
    Ok(Label(
        u16::try_from(d.uint()?).map_err(|_| invalid("label out of range"))?,
    ))
}

fn decode_scatter_args(d: &mut Decoder<'_>) -> Result<ScatterArgs, CborError> {
    d.array_of(2)?;
    let n = d.array()?;
    let labels = (0..n)
        .map(|_| {
            let len = d.array()?;
            match (d.uint()?, len) {
                (0, 3) => {
                    let n = decode_name(d)?;
                    let default = if d.null()? {
                        None
                    } else {
                        Some(decode_label(d)?)
                    };
                    Ok(ScatterLabel::Optional(n, default))
                }
                (1, 2) => Ok(ScatterLabel::Required(decode_name(d)?)),
                (2, 2) => Ok(ScatterLabel::Rest(decode_name(d)?)),
                _ => Err(invalid("bad scatter label")),
            }
        })
        .collect::<Result<Vec<_>, CborError>>()?;
    Ok(ScatterArgs {
        labels,
        done: decode_label(d)?,
    })
}

// ---------------------------------------------------------------------------------------------
// Definitions and permissions

/// `object_flags` value: the flag bits as an unsigned integer.
pub fn flags<T: moor_common::util::BitFlag>(e: &mut Encoder, f: &BitEnum<T>) {
    e.uint(u64::from(f.to_u16()));
}

pub fn decode_flags<T: moor_common::util::BitFlag>(
    d: &mut Decoder<'_>,
) -> Result<BitEnum<T>, CborError> {
    Ok(BitEnum::from_u16(
        u16::try_from(d.uint()?).map_err(|_| invalid("flags out of range"))?,
    ))
}

/// One verb definition: `[uuid, location, owner, [name...], flags, [dobj, prep, iobj]]`, with
/// `dobj`/`iobj` as 0 none, 1 any, 2 this and `prep` as -2 any, -1 none, else the preposition
/// number.
pub fn verbdef(e: &mut Encoder, v: &VerbDef) -> Result<(), CborError> {
    e.array(6);
    uuid(e, &v.uuid());
    obj(e, &v.location());
    obj(e, &v.owner());
    e.array(v.names().len());
    for n in v.names() {
        symbol(e, n);
    }
    flags(e, &v.flags());
    let args = v.args();
    e.array(3);
    e.uint(u64::from(
        ArgSpec::try_write(args.dobj).map_err(|e| invalid(e.to_string()))?,
    ));
    e.int(i64::from(
        PrepSpec::try_write(args.prep).map_err(|e| invalid(e.to_string()))?,
    ));
    e.uint(u64::from(
        ArgSpec::try_write(args.iobj).map_err(|e| invalid(e.to_string()))?,
    ));
    Ok(())
}

pub fn decode_verbdef(d: &mut Decoder<'_>) -> Result<VerbDef, CborError> {
    d.array_of(6)?;
    let id = decode_uuid(d)?;
    let location = decode_obj(d)?;
    let owner = decode_obj(d)?;
    let n = d.array()?;
    let names = (0..n)
        .map(|_| d.text().map(Symbol::mk))
        .collect::<Result<Vec<_>, _>>()?;
    let flags = decode_flags(d)?;
    d.array_of(3)?;
    let arg = |n: u64| {
        u8::try_from(n)
            .ok()
            .and_then(|n| ArgSpec::try_read(n).ok())
            .ok_or_else(|| invalid("bad argspec"))
    };
    let dobj = arg(d.uint()?)?;
    let prep = i16::try_from(d.int()?)
        .ok()
        .and_then(|p| PrepSpec::try_read(p).ok())
        .ok_or_else(|| invalid("bad prepspec"))?;
    let iobj = arg(d.uint()?)?;
    Ok(VerbDef::new(
        id,
        location,
        owner,
        &names,
        flags,
        VerbArgsSpec { dobj, prep, iobj },
    ))
}

/// `object_verbdefs` value: the object's verb definitions in their stored order (verb order is
/// observable: `verbs()` and dispatch both follow it).
pub fn verbdefs(e: &mut Encoder, v: &VerbDefs) -> Result<(), CborError> {
    e.array(v.len());
    for def in v.iter() {
        verbdef(e, &def)?;
    }
    Ok(())
}

pub fn decode_verbdefs(d: &mut Decoder<'_>) -> Result<VerbDefs, CborError> {
    let n = d.array()?;
    (0..n).map(|_| decode_verbdef(d)).collect()
}

/// One property definition: `[uuid, definer, location, name]`.
pub fn propdef(e: &mut Encoder, p: &PropDef) {
    e.array(4);
    uuid(e, &p.uuid());
    obj(e, &p.definer());
    obj(e, &p.location());
    symbol(e, &p.name());
}

pub fn decode_propdef(d: &mut Decoder<'_>) -> Result<PropDef, CborError> {
    d.array_of(4)?;
    let id = decode_uuid(d)?;
    let definer = decode_obj(d)?;
    let location = decode_obj(d)?;
    let name = Symbol::mk(d.text()?);
    Ok(PropDef::new(id, definer, location, name))
}

/// `object_propdefs` value: the definitions in stored order (observable through `properties()`).
pub fn propdefs(e: &mut Encoder, p: &PropDefs) {
    e.array(p.len());
    for def in p.iter() {
        propdef(e, &def);
    }
}

pub fn decode_propdefs(d: &mut Decoder<'_>) -> Result<PropDefs, CborError> {
    let n = d.array()?;
    (0..n).map(|_| decode_propdef(d)).collect()
}

/// `object_propflags` value: `[owner, flags]`.
pub fn propperms(e: &mut Encoder, p: &PropPerms) {
    e.array(2);
    obj(e, &p.owner());
    flags(e, &p.flags());
}

pub fn decode_propperms(d: &mut Decoder<'_>) -> Result<PropPerms, CborError> {
    d.array_of(2)?;
    let owner = decode_obj(d)?;
    Ok(PropPerms::new(owner, decode_flags(d)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_root::cbor;
    use moor_common::model::{ObjFlag, PropFlag, VerbFlag};
    use moor_var::{AnonymousObjid, E_INVARG, E_PERM, UuObjid, v_empty_list};

    fn encode(v: &Var) -> Vec<u8> {
        let mut e = Encoder::new();
        var(&mut e, v).unwrap();
        e.into_bytes()
    }

    fn decode(bytes: &[u8]) -> Var {
        let mut d = Decoder::new(bytes);
        let v = decode_var(&mut d).unwrap();
        d.finish().unwrap();
        v
    }

    /// Decoding gives back an equal value whose encoding is byte-identical.
    fn round_trip(v: Var) {
        let bytes = encode(&v);
        let back = decode(&bytes);
        assert_eq!(back, v, "{}", cbor::diagnostic(&bytes, false).unwrap());
        assert_eq!(encode(&back), bytes);
    }

    #[test]
    fn every_var_type_round_trips() {
        let contents = v_empty_list().as_list().unwrap().clone();
        for v in [
            v_none(),
            v_bool(true),
            v_bool(false),
            v_int(0),
            v_int(i64::MIN),
            v_int(i64::MAX),
            v_float(1.5),
            v_float(-0.0),
            v_str(""),
            v_str("Mixed Case ünïcode"),
            v_obj(Obj::mk_id(-1)),
            v_obj(Obj::mk_id(i32::MAX)),
            v_obj(Obj::mk_uuobjid(UuObjid::new(7, 3, 1_700_000_000_000))),
            v_obj(Obj::mk_anonymous(AnonymousObjid(123))),
            v_error(E_PERM.into()),
            v_error(E_INVARG.with_msg_and_value(|| "bad".to_string(), v_list(&[v_int(1)]))),
            v_error(Error::new(
                ErrorCode::ErrCustom(Symbol::mk("E_Custom")),
                None,
                None,
            )),
            v_list(&[v_int(1), v_str("two"), v_list(&[])]),
            v_map(&[
                (v_str("b"), v_int(2)),
                (v_int(1), v_str("one")),
                (v_sym(Symbol::mk("Zeta")), v_int(3)),
            ]),
            v_sym(Symbol::mk("CamelSym")),
            v_binary(vec![0, 1, 2, 255]),
            v_flyweight(
                Obj::mk_id(7),
                &[(Symbol::mk("b"), v_int(2)), (Symbol::mk("a"), v_int(1))],
                contents,
            ),
        ] {
            round_trip(v);
        }
    }

    #[test]
    fn float_is_carried_as_its_bits() {
        assert_ne!(encode(&v_float(0.0)), encode(&v_float(-0.0)));
        assert_eq!(
            cbor::diagnostic(&encode(&v_float(1.0)), false).unwrap(),
            format!("[3, {}]", 1.0f64.to_bits())
        );
    }

    #[test]
    fn map_encoding_ignores_insertion_order() {
        let a = v_map(&[(v_str("x"), v_int(1)), (v_str("y"), v_int(2))]);
        let b = v_map(&[(v_str("y"), v_int(2)), (v_str("x"), v_int(1))]);
        assert_eq!(encode(&a), encode(&b));
    }

    #[test]
    fn decoder_rejects_a_map_with_unsorted_keys() {
        // [8, {"b": [0], "a": [0]}] with keys swapped.
        let mut e = Encoder::new();
        e.array(2);
        e.uint(var_type::MAP);
        e.map(2);
        for k in ["b", "a"] {
            var(&mut e, &v_str(k)).unwrap();
            var(&mut e, &v_none()).unwrap();
        }
        let bytes = e.into_bytes();
        assert!(decode_var(&mut Decoder::new(&bytes)).is_err());
    }

    #[test]
    fn verbdefs_propdefs_and_perms_round_trip() {
        let verb = VerbDef::new(
            Uuid::from_u128(1),
            Obj::mk_id(2),
            Obj::mk_id(3),
            &[Symbol::mk("look"), Symbol::mk("l*")],
            BitEnum::new_with(VerbFlag::Read) | VerbFlag::Exec,
            VerbArgsSpec::this_none_this(),
        );
        let defs: VerbDefs = [verb].into_iter().collect();
        let mut e = Encoder::new();
        verbdefs(&mut e, &defs).unwrap();
        let bytes = e.into_bytes();
        let back = decode_verbdefs(&mut Decoder::new(&bytes)).unwrap();
        assert_eq!(back, defs);

        let props: PropDefs = [PropDef::new(
            Uuid::from_u128(9),
            Obj::mk_id(1),
            Obj::mk_id(4),
            Symbol::mk("Description"),
        )]
        .into_iter()
        .collect();
        let mut e = Encoder::new();
        propdefs(&mut e, &props);
        let bytes = e.into_bytes();
        assert_eq!(decode_propdefs(&mut Decoder::new(&bytes)).unwrap(), props);

        let perms = PropPerms::new(Obj::mk_id(3), BitEnum::new_with(PropFlag::Read));
        let mut e = Encoder::new();
        propperms(&mut e, &perms);
        let bytes = e.into_bytes();
        assert_eq!(decode_propperms(&mut Decoder::new(&bytes)).unwrap(), perms);

        let f: BitEnum<ObjFlag> = BitEnum::new_with(ObjFlag::Wizard) | ObjFlag::Programmer;
        let mut e = Encoder::new();
        flags(&mut e, &f);
        let bytes = e.into_bytes();
        assert_eq!(
            decode_flags::<ObjFlag>(&mut Decoder::new(&bytes)).unwrap(),
            f
        );
    }
}

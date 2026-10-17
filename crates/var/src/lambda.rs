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

use crate::{
    Var,
    program::{opcode::ScatterArgs, program::Program},
};
use std::cmp::Ordering;
use triomphe::Arc;

/// Lambda function value containing parameter specification, compiled body, and captured environment
#[derive(Clone, Debug, PartialEq)]
#[repr(transparent)]
pub struct Lambda(pub Arc<LambdaInner>);

#[derive(Clone, Debug, PartialEq)]
pub struct LambdaInner {
    /// Parameter specification (reuses scatter assignment structure)
    pub params: ScatterArgs,
    /// The lambda body as standalone executable program
    /// Compiled at compile-time into a complete, self-contained Program
    pub body: Program,
    /// Captured variable environment from lambda creation site
    pub captured_env: Vec<Vec<Var>>,
    /// Optional self-reference variable name for recursive lambdas
    pub self_var: Option<crate::program::names::Name>,
}

impl Lambda {
    /// Create a new lambda value
    pub fn new(
        params: ScatterArgs,
        body: Program,
        captured_env: Vec<Vec<Var>>,
        self_var: Option<crate::program::names::Name>,
    ) -> Self {
        Self(Arc::new(LambdaInner {
            params,
            body,
            captured_env,
            self_var,
        }))
    }

    /// Create a deep copy of this lambda for self-reference to avoid cycles.
    ///
    /// TODO: If we ever get a cycle-collecting or full tracing GC, we can safely back this out
    ///   and allow true cycles since they would be properly collected.
    pub fn for_self_reference(&self) -> Self {
        Self(Arc::new(LambdaInner {
            params: self.0.params.clone(),
            body: self.0.body.clone(),
            captured_env: self.0.captured_env.clone(),
            self_var: self.0.self_var,
        }))
    }
}

impl Lambda {
    /// A total order over lambda values that depends only on their content: parameters, bytecode,
    /// literals, variable names, nested lambdas and the captured environment. It never looks at an
    /// address, so it is the same in every process (audit H3). Lambdas that compare `Equal` are
    /// interchangeable for ordering purposes.
    pub fn canonical_cmp(&self, other: &Self) -> Ordering {
        if Arc::ptr_eq(&self.0, &other.0) {
            return Ordering::Equal;
        }
        let (l, r) = (&*self.0, &*other.0);
        l.params
            .cmp(&r.params)
            .then_with(|| program_cmp(&l.body, &r.body))
            .then_with(|| l.captured_env.cmp(&r.captured_env))
            .then_with(|| l.self_var.cmp(&r.self_var))
    }
}

fn program_cmp(l: &Program, r: &Program) -> Ordering {
    if Arc::ptr_eq(&l.0, &r.0) {
        return Ordering::Equal;
    }
    // `Op` is only PartialOrd (it can carry floats); incomparable values are treated as equal,
    // which falls through to the remaining fields.
    let ops = l
        .main_vector()
        .partial_cmp(r.main_vector())
        .unwrap_or(Ordering::Equal);
    ops.then_with(|| l.literals().cmp(r.literals()))
        .then_with(|| names_key(l).cmp(&names_key(r)))
        .then_with(|| l.0.lambda_programs.len().cmp(&r.0.lambda_programs.len()))
        .then_with(|| {
            l.0.lambda_programs
                .iter()
                .zip(r.0.lambda_programs.iter())
                .map(|(a, b)| program_cmp(a, b))
                .find(|o| o.is_ne())
                .unwrap_or(Ordering::Equal)
        })
}

/// The program's variable declarations as a sorted, address-free key. `Names::decls` is a std
/// `HashMap` with a per-process seed, so it must not be iterated in map order.
fn names_key(p: &Program) -> Vec<(crate::program::names::Name, String)> {
    let names = p.var_names();
    let mut key: Vec<_> = names
        .decls
        .iter()
        .map(|(n, d)| (*n, format!("{:?}", d.identifier.nr)))
        .collect();
    key.sort();
    key
}

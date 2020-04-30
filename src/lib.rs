// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Utilites for graphql query depth analysis
//!
//! graphql_depth_limit provide utilities for easy identification of possible malicious queries (high depth).
//!
//! # Quick Start
//!
//! example
//! ```
//! use graphql_depth_limit::QueryDepthAnalyzer;
//!
//! let query = r#"
//!     query {
//!         hello {
//!             world
//!         }
//!     }
//! "#;
//! let analyzer : QueryDepthAnalyzer = QueryDepthAnalyzer::new(query, vec![], None).unwrap();
//! let verify_result = analyzer.verify(5);
//!
//! ```
use graphql_parser::parse_query;
pub use graphql_parser::query::*;
use std::collections::HashMap;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::slice::Iter;

#[derive(Debug, PartialEq)]
pub struct ExceedMaxDepth {
    limit: usize,
}

impl ExceedMaxDepth {
    pub fn new(limit: usize) -> Self {
        Self { limit }
    }

    pub fn limit(&self) -> usize {
        self.limit
    }
}

impl Display for ExceedMaxDepth {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "your query exceeded the depth limit: {}", self.limit)
    }
}

type DefaultCallback = Box<dyn Fn(OperationDefinition, usize) -> (bool, usize)>;

impl Error for ExceedMaxDepth {}

pub struct QueryDepthAnalyzer<T = DefaultCallback>
where
    T: Fn(OperationDefinition, usize) -> (bool, usize),
{
    /// Fragments declared on a query
    fragments: HashMap<String, FragmentDefinition>,
    /// Operation to be called on a OperationDefinition with the related depth
    callback_on_op_definition: Option<T>,
    /// The query Document
    document: Document,
    /// Vec of names to ignore Fields
    fields_name_to_ignore: Vec<String>,
}

/// Map the FragmentDefinition with the name from a Iter Definition
fn fragments_from_definitions(
    definitions: Iter<'_, Definition>,
) -> HashMap<String, FragmentDefinition> {
    definitions.fold(HashMap::new(), |mut acc, val| {
        if let Definition::Fragment(def) = val {
            acc.insert(def.name.clone(), def.clone());
        }
        acc
    })
}

impl<T> QueryDepthAnalyzer<T>
where
    T: Fn(OperationDefinition, usize) -> (bool, usize),
{
    pub fn fragments(&self) -> &HashMap<String, FragmentDefinition> {
        &self.fragments
    }

    pub fn document(&self) -> &Document {
        &self.document
    }

    pub fn fields_name_to_ignore(&self) -> &Vec<String> {
        &self.fields_name_to_ignore
    }

    /// Constructor
    /// # Example
    ///
    /// ```
    ///     use graphql_depth_limit::QueryDepthAnalyzer;
    ///
    ///     let query = r#"
    ///         query {
    ///             hello {
    ///                 world
    ///             }
    ///         }
    ///     "#;
    ///     let new : QueryDepthAnalyzer = QueryDepthAnalyzer::new(query, vec![], None).unwrap();
    /// ```
    ///
    /// # Errors
    ///
    pub fn new(
        query: &str,
        fields_name_to_ignore: Vec<String>,
        callback: Option<T>,
    ) -> Result<Self, ParseError> {
        let document = parse_query(query)?;
        let fragments = fragments_from_definitions(document.definitions.iter());
        Ok(Self {
            fragments,
            document,
            callback_on_op_definition: callback,
            fields_name_to_ignore,
        })
    }

    /// Computes the greatest depth from a SelectionSet with initial depth and depth limit
    /// if the limit does not exceed
    fn determine_depth_of_selection_set(
        &self,
        selection_set: &SelectionSet,
        depth: usize,
        limit: usize,
    ) -> Result<usize, ExceedMaxDepth> {
        let mut greater_depth: usize = depth;
        for item in selection_set.items.iter() {
            let depth = self.determine_depth_of_selection(item, depth, limit);
            match depth {
                Ok(val) => {
                    if val > limit {
                        return Err(ExceedMaxDepth::new(limit));
                    }
                    if val > greater_depth {
                        greater_depth = val;
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(greater_depth)
    }

    /// Computes the depth of a Selection with a initial depth and depth limit
    /// if the limit does not exceed
    fn determine_depth_of_selection(
        &self,
        selection: &Selection,
        depth: usize,
        limit: usize,
    ) -> Result<usize, ExceedMaxDepth> {
        match selection {
            Selection::Field(f) => {
                let should_ignore: bool =
                    f.name.starts_with("__") || self.fields_name_to_ignore.contains(&f.name);
                if should_ignore {
                    return Ok(0);
                }
                self.determine_depth_of_selection_set(&f.selection_set, depth + 1, limit)
            }
            Selection::FragmentSpread(fs) => {
                if let Some(f_def) = self.fragments.get(&fs.fragment_name) {
                    self.determine_depth_of_selection_set(&f_def.selection_set, depth, limit)
                } else {
                    Ok(0)
                }
            }
            Selection::InlineFragment(inf) => {
                self.determine_depth_of_selection_set(&inf.selection_set, depth, limit)
            }
        }
    }

    /// Computes the depth of a Query with a initial depth and depth limit
    /// if the limit does not exceed
    fn determine_depth_of_query(
        &self,
        query: &Query,
        depth: usize,
        limit: usize,
    ) -> Result<usize, ExceedMaxDepth> {
        self.determine_depth_of_selection_set(&query.selection_set, depth, limit)
    }

    /// Computes the depth of a Mutation with a initial depth and depth limit
    /// if the limit does not exceed
    fn determine_depth_of_mutation(
        &self,
        mutation: &Mutation,
        depth: usize,
        limit: usize,
    ) -> Result<usize, ExceedMaxDepth> {
        self.determine_depth_of_selection_set(&mutation.selection_set, depth, limit)
    }

    /// Computes the depth of a Subscription with a initial depth and depth limit
    /// if the limit does not exceed
    fn determine_depth_of_subscription(
        &self,
        subscription: &Subscription,
        depth: usize,
        limit: usize,
    ) -> Result<usize, ExceedMaxDepth> {
        self.determine_depth_of_selection_set(&subscription.selection_set, depth, limit)
    }

    /// Computes the depth of the query Document
    /// considering a limit
    pub fn verify(&self, limit: usize) -> Result<usize, ExceedMaxDepth> {
        let mut depth: Result<usize, ExceedMaxDepth> = Ok(0);
        for definition in self.document.definitions.iter() {
            let depth_result = if let Definition::Operation(def) = definition {
                let result = match def {
                    OperationDefinition::Query(q) => self.determine_depth_of_query(&q, 0, limit),
                    OperationDefinition::Mutation(m) => {
                        self.determine_depth_of_mutation(&m, 0, limit)
                    }
                    OperationDefinition::Subscription(s) => {
                        self.determine_depth_of_subscription(&s, 0, limit)
                    }
                    OperationDefinition::SelectionSet(ss) => {
                        self.determine_depth_of_selection_set(&ss, 0, limit)
                    }
                };
                if let Ok(depth) = result {
                    match &self.callback_on_op_definition {
                        Some(callback) => {
                            let (is_ok, cb_limit) = callback(def.clone(), depth);
                            if !is_ok {
                                return Err(ExceedMaxDepth::new(cb_limit));
                            }
                        }
                        None => (),
                    }
                }
                result
            } else {
                Ok(0)
            };
            match depth_result {
                Ok(val) => {
                    if let Ok(d) = depth {
                        if val > d {
                            depth = Ok(val)
                        };
                    }
                }
                Err(err) => return Err(err),
            }
        }
        depth
    }
}

#[cfg(test)]
mod tests {
    use crate::{ExceedMaxDepth, QueryDepthAnalyzer};
    use graphql_parser::query::{OperationDefinition, ParseError};

    fn default_analyzer(query: &str) -> Result<QueryDepthAnalyzer, ParseError> {
        QueryDepthAnalyzer::new(query, vec![], None)
    }

    fn analyze_def(query: &str) -> Result<QueryDepthAnalyzer, ParseError> {
        QueryDepthAnalyzer::new(query, vec![], Some(Box::new(definition_analyzer)))
    }

    fn definition_analyzer(op: OperationDefinition, depth: usize) -> (bool, usize) {
        match op {
            OperationDefinition::Query(_) => (depth <= 2, 2),
            OperationDefinition::Mutation(_) => (depth <= 3, 3),
            OperationDefinition::Subscription(_) => (depth <= 4, 4),
            OperationDefinition::SelectionSet(_) => (depth <= 1, 1),
        }
    }

    #[test]
    fn verify_ok() {
        let query = r#"
            query {
              a {
                b {
                  c
                }
              }
            }
        "#;
        let analyzer = default_analyzer(query);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        assert_eq!(verify_result.is_ok(), true)
    }

    #[test]
    fn verify_ok_value() {
        let query = r#"
            query {
              a {
                b {
                  c
                }
              }
            }
        "#;
        let analyzer = default_analyzer(query);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(depth) => assert_eq!(depth, 3),
            Err(_err) => assert!(false),
        }
    }

    #[test]
    fn verify_err() {
        let query = r#"
            query {
              a {
                b {
                  c {
                    d {
                      e {
                        f
                      }
                    }
                  }
                }
              }
            }
        "#;
        let analyzer = default_analyzer(query);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(_) => assert!(false),
            Err(err) => assert_eq!(err, ExceedMaxDepth::new(5)),
        }
    }

    #[test]
    fn verify_query_ok() {
        let query = r#"
            query {
                a {
                    b
                }
            }
        "#;
        let analyzer = analyze_def(query);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(depth) => assert_eq!(depth, 2),
            Err(_err) => assert!(false),
        }
    }

    #[test]
    fn verify_query_error() {
        let query = r#"
            query {
                a {
                    b {
                        c
                    }
                }
            }
        "#;
        let analyzer = analyze_def(query);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(_) => assert!(false),
            Err(err) => assert_eq!(err, ExceedMaxDepth::new(2)),
        }
    }

    #[test]
    fn verify_mutation_ok() {
        let mutation = r#"
            mutation {
                a {
                    b {
                        c 
                    }
                }
            }
        "#;
        let analyzer = analyze_def(mutation);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(depth) => assert_eq!(depth, 3),
            Err(_err) => assert!(false),
        }
    }

    #[test]
    fn verify_mutation_error() {
        let mutation = r#"
            mutation {
                a {
                    b {
                        c {
                            d
                        }
                    }
                }
            }
        "#;
        let analyzer = analyze_def(mutation);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(_) => assert!(false),
            Err(err) => assert_eq!(err, ExceedMaxDepth::new(3)),
        }
    }

    #[test]
    fn verify_subscription_ok() {
        let subscription = r#"
            subscription {
                a {
                    b {
                        c {
                            d 
                        }
                    }
                }
            }
        "#;
        let analyzer = analyze_def(subscription);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(depth) => assert_eq!(depth, 4),
            Err(_err) => assert!(false),
        }
    }

    #[test]
    fn verify_subscription_error() {
        let subscription = r#"
            subscription {
                a {
                    b {
                        c {
                            d {
                                e
                            }
                        }
                    }
                }
            }
        "#;
        let analyzer = analyze_def(subscription);
        assert!(analyzer.is_ok());
        let analyzer = analyzer.unwrap();
        let verify_result = analyzer.verify(5);
        match verify_result {
            Ok(_) => assert!(false),
            Err(err) => assert_eq!(err, ExceedMaxDepth::new(4)),
        }
    }
}

use std::collections::HashMap;
use graphql_parser::parse_query;
use graphql_parser::query::*;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::slice::Iter;

#[derive(Debug)]
pub struct ExceedMaxDepth {
    limit: usize,
    depth: usize,
}

#[derive(Debug)]
pub enum DepthLimitError {
    Parse(ParseError),
    Exceed(ExceedMaxDepth),
}

impl Display for DepthLimitError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            DepthLimitError::Parse(parse_error) => write!(f, "{}", parse_error),
            DepthLimitError::Exceed(exceed_error) => write!(f, "{}", exceed_error)
        }
    }
}
impl Display for ExceedMaxDepth {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "your query exceeded the maximum depth, depth: {}, limit: {}", self.depth, self.limit)
    }
}

impl Error for ExceedMaxDepth {}

pub struct QueryDepthAnalyzer<T> where T: Fn(OperationDefinition, usize) -> bool {
    fragments: HashMap<String, FragmentDefinition>,
    callback_on_op_definition: T,
    document: Document,
    fields_name_to_ignore: Vec<String>,
}

/// Map the FragmentDefinition with the name
fn fragments_from_definitions(definitions: Iter<'_, Definition>) -> HashMap<String, FragmentDefinition> {
    definitions
        .fold(HashMap::new(), |mut acc, val| {
            if let Definition::Fragment(def) = val {
                acc.insert(def.name.clone(), def.clone());
            }
            acc
        })
}


impl<T> QueryDepthAnalyzer<T> where T: Fn(OperationDefinition, usize) -> bool {
    pub fn new(query: &str, fields_name_to_ignore: Vec<String>, callback: T) -> Result<Self, ParseError> {
        let document = parse_query(query)?;
        let fragments = fragments_from_definitions(document.definitions.iter());
        Ok(Self {
            fragments,
            document,
            callback_on_op_definition: callback,
            fields_name_to_ignore,
        })
    }

    fn determine_depth_of_selection_set(&self, selection_set: &SelectionSet, depth: usize, limit: usize) -> Result<usize, DepthLimitError> {
        let mut greater_depth: usize = depth;
        for item in selection_set.items.iter() {
            let depth = self.determine_depth_of_selection(item, depth, limit);
            match depth {
                Ok(val) => {
                    if val > limit { return Err(DepthLimitError::Exceed(ExceedMaxDepth { limit, depth: val })); }
                    if val > greater_depth { greater_depth = val; }
                }
                Err(err) => return Err(err)
            }
        };
        Ok(greater_depth)
    }

    fn determine_depth_of_selection(&self, selection: &Selection, depth: usize, limit: usize) -> Result<usize, DepthLimitError> {
        match selection {
            Selection::Field(f) => {
                let should_ignore: bool = f.name.starts_with("__") || self.fields_name_to_ignore.contains(&f.name);
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
            Selection::InlineFragment(inf) => { self.determine_depth_of_selection_set(&inf.selection_set, depth, limit) }
        }
    }

    fn determine_depth_of_query(&self, query: &Query, depth: usize, limit: usize) -> Result<usize, DepthLimitError> {
        self.determine_depth_of_selection_set(&query.selection_set, depth, limit)
    }

    fn determine_depth_of_mutation(&self, mutation: &Mutation, depth: usize, limit: usize) -> Result<usize, DepthLimitError> {
        self.determine_depth_of_selection_set(&mutation.selection_set, depth, limit)
    }

    fn determine_depth_of_subscription(&self, subscription: &Subscription, depth: usize, limit: usize) -> Result<usize, DepthLimitError> {
        self.determine_depth_of_selection_set(&subscription.selection_set, depth, limit)
    }

    pub fn verify(&self, limit: usize) -> Result<usize, DepthLimitError> {
        let mut depth: Result<usize, DepthLimitError> = Ok(0);
        for definition in self.document.definitions.iter() {
            let depth_result = if let Definition::Operation(def) = definition {
                let result = match def {
                    OperationDefinition::Query(q) => self.determine_depth_of_query(&q, 0, limit),
                    OperationDefinition::Mutation(m) => self.determine_depth_of_mutation(&m, 0, limit),
                    OperationDefinition::Subscription(s) => self.determine_depth_of_subscription(&s, 0, limit),
                    OperationDefinition::SelectionSet(ss) => self.determine_depth_of_selection_set(&ss, 0, limit)
                };
                if let Ok(depth) = result {
                    (self.callback_on_op_definition)(def.clone(), depth);
                }
                result
            } else { Ok(0) };
            match depth_result {
                Ok(val) => {
                    if let Ok(d) = depth {
                        if val > d { depth = Ok(val) };
                    }
                }
                Err(err) => return Err(err)
            }
        };
        depth
    }
}

#[cfg(test)]
mod tests {
    use crate::{QueryDepthAnalyzer, DepthLimitError};
    

    fn verify_result_from_analyzer(query: &str, limit: usize) -> Result<usize, DepthLimitError>{
        match QueryDepthAnalyzer::new(query, vec![], |_a, _b| true) {
            Ok(validator) => validator.verify(limit),
            Err(val) => Err(DepthLimitError::Parse(val))
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
        let verify_result = verify_result_from_analyzer(query, 5);
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
        let depth = verify_result_from_analyzer(query, 5);
        match depth {
            Ok(val) => assert_eq!(val, 3),
            Err(_err) => assert!(false)
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
        let verify_result = verify_result_from_analyzer(query, 5);
        assert_eq!(verify_result.is_err(), true)
    }
}

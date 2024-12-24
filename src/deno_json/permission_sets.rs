use indexmap::IndexMap;
use serde::Deserialize;

#[derive(Default, Clone, Debug, PartialEq, Eq)]

pub enum Permission {
  All,
  Some(Vec<String>),
  #[default]
  None,
}

impl<'de> serde::Deserialize<'de> for Permission {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct Visitor;
    impl<'d> serde::de::Visitor<'d> for Visitor {
      type Value = Permission;

      fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "either an array or bool")
      }

      fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        if v {
          Ok(Permission::All)
        } else {
          Ok(Permission::None)
        }
      }

      fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
      where
        A: serde::de::SeqAccess<'d>,
      {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(8));
        while let Some(element) = seq.next_element::<String>()? {
          out.push(element);
        }

        if out.is_empty() {
          Ok(Permission::None)
        } else {
          Ok(Permission::Some(out))
        }
      }

      fn visit_none<E>(self) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        Ok(Permission::None)
      }

      fn visit_unit<E>(self) -> Result<Self::Value, E>
      where
        E: serde::de::Error,
      {
        Ok(Permission::None)
      }
    }
    deserializer.deserialize_any(Visitor)
  }
}

#[derive(Deserialize, Default, Clone, Debug, PartialEq, Eq)]

pub struct AllowDeny {
  pub allow: Permission,
  pub deny: Permission,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum AllowDenyJson {
  Boolean(bool),
  AllowList(Vec<String>),
  Object(AllowDeny),
}

fn deserialize_allow_deny<'de, D: serde::Deserializer<'de>>(
  de: D,
) -> Result<AllowDeny, D::Error> {
  AllowDenyJson::deserialize(de).map(|value| match value {
    AllowDenyJson::Boolean(b) => {
      if b {
        AllowDeny {
          allow: Permission::All,
          deny: Permission::None,
        }
      } else {
        AllowDeny {
          allow: Permission::None,
          deny: Permission::None,
        }
      }
    }
    AllowDenyJson::AllowList(allow) => AllowDeny {
      allow: Permission::Some(allow),
      deny: Permission::None,
    },
    AllowDenyJson::Object(allow_deny) => allow_deny,
  })
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Default)]
pub struct PermissionsObject {
  #[serde(default)]
  all: bool,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  read: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  write: AllowDeny,
  #[serde(default)]
  import: Permission,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  env: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  net: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  run: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  ffi: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  sys: AllowDeny,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(untagged)]
pub enum PermissionSet {
  Flags(String),
  Object(PermissionsObject),
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PermissionSets {
  pub sets: IndexMap<String, PermissionSet>,
}

#[derive(thiserror::Error, Debug)]
#[error("failed to parse permission sets: {0}")]
pub enum PermissionSetsParseError {
  Serde(#[from] serde_json::Error),
  #[error("only string or object values are accepted")]
  InvalidType,
}

fn parse_set(
  value: serde_json::Value,
) -> Result<PermissionSet, PermissionSetsParseError> {
  match value {
    serde_json::Value::String(flags) => Ok(PermissionSet::Flags(flags)),
    obj @ serde_json::Value::Object(_) => {
      Ok(PermissionSet::Object(serde_json::from_value(obj)?))
    }
    _ => Err(PermissionSetsParseError::InvalidType),
  }
}

// pub struct PermissionSetsJson {
//   read
// }

pub fn to_permission_sets(
  value: serde_json::Value,
) -> Result<PermissionSets, PermissionSetsParseError> {
  let serde_json::Value::Object(map) = value else {
    return Err(PermissionSetsParseError::InvalidType);
  };
  let mut sets = IndexMap::with_capacity(map.len());
  for (key, value) in map {
    sets.insert(key, parse_set(value)?);
  }
  Ok(PermissionSets { sets })
}

/*
 *
 * {
 *    "permissionSets": {
 *      "default": {
 *         "read": true,
 *         "write": {
 *            "allow": ["./temp", "./export"]
 *         }
 *      },
 *      "test": "--allow-read --allow-env --allow-write=./temp,./export --allow-run=deno --allow-net=127.0.0.1"
 *    },
 *    "tasks": {
 *      "dev": "deno run -P ./foo.ts"
 *      "tests": "deno run -P=test ./foo.ts"
 *    }
 * }
 *
 */

// --allow-read --allow-env --allow-write=./temp,./export --allow-run=deno --allow-net=127.0.0.1

#[cfg(test)]
mod test {
  use super::*;
  use serde_json::json;

  fn permission_sets(
    entries: impl IntoIterator<Item = (&'static str, PermissionSet)>,
  ) -> PermissionSets {
    PermissionSets {
      sets: entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect(),
    }
  }

  #[test]
  fn do_thing() {
    let j = json!({
      "default": {
        "read": true,
        "write": {
          "allow": ["./temp", "./export"],
          "deny": ["/Secrets"]
        }
      },
      "test": "--allow-read --allow-env --allow-write=./temp,./export --allow-run=deno --allow-net=127.0.0.1"
    });

    let sets = to_permission_sets(j).unwrap();

    assert_eq!(
      sets,
      permission_sets([(
        "default",
        PermissionSet::Object(PermissionsObject {
          read: AllowDeny {
            allow: Permission::All,
            ..Default::default()
          },
          write: AllowDeny {
            allow: Permission::Some(vec!["./temp".into(), "./export".into()]),
            deny: Permission::Some(vec!["/Secrets".into()]),
          },
          ..Default::default()
        })
      ), ("test", PermissionSet::Flags("--allow-read --allow-env --allow-write=./temp,./export --allow-run=deno --allow-net=127.0.0.1".into()))])
    )
  }
}

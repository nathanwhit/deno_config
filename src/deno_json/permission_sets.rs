use indexmap::IndexMap;
use serde::Deserialize;

#[derive(Default, Clone, Debug, PartialEq, Eq)]

pub enum Permission {
  All,
  Some(Vec<String>),
  None,
  #[default]
  NotPresent,
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

impl Permission {
  pub fn merge(self, other: Self) -> Self {
    match (self, other) {
      (Permission::NotPresent, other) => other,
      (this, Permission::NotPresent) => this,
      (_, other) => other,
    }
  }
}

impl AllowDeny {
  pub fn merge(self, other: Self) -> Self {
    AllowDeny {
      allow: self.allow.merge(other.allow),
      deny: self.deny.merge(other.deny),
    }
  }
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
  pub all: Option<bool>,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub read: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub write: AllowDeny,
  #[serde(default)]
  pub import: Permission,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub env: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub net: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub run: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub ffi: AllowDeny,
  #[serde(default, deserialize_with = "deserialize_allow_deny")]
  pub sys: AllowDeny,
  #[serde(default)]
  pub prompt: Option<bool>,
}

impl PermissionsObject {
  pub fn merge(self, other: Self) -> Self {
    PermissionsObject {
      all: match (self.all, other.all) {
        (Some(_), Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
      },
      read: self.read.merge(other.read),
      write: self.write.merge(other.write),
      import: self.import.merge(other.import),
      env: self.env.merge(other.env),
      net: self.net.merge(other.net),
      run: self.run.merge(other.run),
      ffi: self.ffi.merge(other.ffi),
      sys: self.sys.merge(other.sys),
      prompt: match (self.prompt, other.prompt) {
        (Some(_), Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
      },
    }
  }
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

impl PermissionSets {
  pub fn merge(self, other: Self) -> Self {
    let mut sets = self.sets;

    for (key, value) in other.sets {
      if let Some(existing) = sets.swap_remove(key.as_str()) {
        match (existing, value) {
          (PermissionSet::Object(existing), PermissionSet::Object(value)) => {
            sets.insert(key, PermissionSet::Object(existing.merge(value)));
          }
          (_, new) => {
            sets.insert(key, new);
          }
        }
      } else {
        sets.insert(key, value);
      }
    }
    Self { sets }
  }
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

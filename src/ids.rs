#[macro_export]
macro_rules! uuid_id_type {
    ($name:ident, $tag:expr) => {
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
            Default,
        )]
        pub struct $name(pub ::uuid::Uuid);

        impl $crate::typed_uuid::TypeTag for $name {
            fn tag() -> &'static str {
                $tag
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl ::core::str::FromStr for $name {
            type Err = ::uuid::Error;

            fn from_str(s: &str) -> ::core::result::Result<Self, Self::Err> {
                ::uuid::Uuid::parse_str(s).map(Self)
            }
        }

        impl From<::uuid::Uuid> for $name {
            fn from(uuid: ::uuid::Uuid) -> Self {
                Self(uuid)
            }
        }

        $crate::impl_typed_uuid_path_extractor!($name);
    };
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use axum::extract::FromRequestParts;
    use uuid::Uuid;

    use crate::typed_uuid::{FromTypedUuid, TypeTag, TypedUuid};

    crate::uuid_id_type!(UserId, "user");

    fn fixture_uuid() -> Uuid {
        Uuid::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8").expect("fixture uuid should parse")
    }

    #[test]
    fn macro_applies_type_tag() {
        assert_eq!(UserId::tag(), "user");
    }

    #[test]
    fn macro_parses_untyped_uuid() {
        let value = UserId::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8")
            .expect("from_str should parse untyped uuid");

        assert_eq!(value.0, fixture_uuid());
    }

    #[test]
    fn macro_supports_typed_uuid_conversion_chain() {
        let typed = TypedUuid::<UserId>::from_str("user_a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8")
            .expect("typed uuid should parse");
        let user_id = UserId::from_typed_uuid(typed);

        assert_eq!(user_id.0, fixture_uuid());
    }

    #[test]
    fn macro_implements_axum_extractor_for_base_type() {
        fn assert_from_request_parts_impl<T>()
        where
            T: FromRequestParts<()>,
        {
        }

        assert_from_request_parts_impl::<UserId>();
    }
}

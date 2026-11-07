//! `typed_id!`: a `uuid_id_type!` newtype plus constructors, the typed wire form, and
//! (behind the `sqlx` and `schemars` features) Postgres and JSON-schema impls.


/// A `uuid_id_type!` newtype with `new_v4()`, `nil()`, `wire()` and `From<Name> for Uuid`. With
/// the `sqlx` feature it also gets Postgres `Type`/`Encode`/`Decode`/`PgHasArrayType` (stored as
/// `uuid`); with `schemars`, a `JsonSchema` describing a string of format `typed-uuid`.
#[macro_export]
macro_rules! typed_id {
    ($name:ident, $tag:expr) => {
        $crate::uuid_id_type!($name, $tag);

        impl $name {
            pub fn new_v4() -> Self {
                Self(::uuid::Uuid::new_v4())
            }

            pub fn nil() -> Self {
                Self(::uuid::Uuid::nil())
            }

            /// Typed wire form: `{tag}_{uuid simple hex}`.
            pub fn wire(&self) -> String {
                $crate::typed_uuid::wire::<$name>(self.0)
            }
        }

        impl From<$name> for ::uuid::Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        $crate::__typed_id_sqlx!($name);
        $crate::__typed_id_schemars!($name);
    };
}

#[cfg(feature = "sqlx")]
#[doc(hidden)]
#[macro_export]
macro_rules! __typed_id_sqlx {
    ($name:ident) => {
        impl $crate::__sqlx::Type<$crate::__sqlx::Postgres> for $name {
            fn type_info() -> $crate::__sqlx::postgres::PgTypeInfo {
                <::uuid::Uuid as $crate::__sqlx::Type<$crate::__sqlx::Postgres>>::type_info()
            }

            fn compatible(ty: &$crate::__sqlx::postgres::PgTypeInfo) -> bool {
                <::uuid::Uuid as $crate::__sqlx::Type<$crate::__sqlx::Postgres>>::compatible(ty)
            }
        }

        impl $crate::__sqlx::postgres::PgHasArrayType for $name {
            fn array_type_info() -> $crate::__sqlx::postgres::PgTypeInfo {
                <::uuid::Uuid as $crate::__sqlx::postgres::PgHasArrayType>::array_type_info()
            }
        }

        impl<'q> $crate::__sqlx::Encode<'q, $crate::__sqlx::Postgres> for $name {
            fn encode_by_ref(
                &self,
                buf: &mut $crate::__sqlx::postgres::PgArgumentBuffer,
            ) -> ::core::result::Result<
                $crate::__sqlx::encode::IsNull,
                $crate::__sqlx::error::BoxDynError,
            > {
                <::uuid::Uuid as $crate::__sqlx::Encode<$crate::__sqlx::Postgres>>::encode_by_ref(
                    &self.0, buf,
                )
            }

            fn size_hint(&self) -> usize {
                <::uuid::Uuid as $crate::__sqlx::Encode<$crate::__sqlx::Postgres>>::size_hint(
                    &self.0,
                )
            }
        }

        impl<'r> $crate::__sqlx::Decode<'r, $crate::__sqlx::Postgres> for $name {
            fn decode(
                value: $crate::__sqlx::postgres::PgValueRef<'r>,
            ) -> ::core::result::Result<Self, $crate::__sqlx::error::BoxDynError> {
                <::uuid::Uuid as $crate::__sqlx::Decode<$crate::__sqlx::Postgres>>::decode(value)
                    .map(Self)
            }
        }
    };
}

#[cfg(not(feature = "sqlx"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __typed_id_sqlx {
    ($name:ident) => {};
}

#[cfg(feature = "schemars")]
#[doc(hidden)]
#[macro_export]
macro_rules! __typed_id_schemars {
    ($name:ident) => {
        impl $crate::__schemars::JsonSchema for $name {
            fn schema_name() -> ::std::string::String {
                ::std::stringify!($name).to_string()
            }

            fn json_schema(
                _gen: &mut $crate::__schemars::r#gen::SchemaGenerator,
            ) -> $crate::__schemars::schema::Schema {
                $crate::__schemars::schema::SchemaObject {
                    instance_type: Some($crate::__schemars::schema::InstanceType::String.into()),
                    format: Some("typed-uuid".to_string()),
                    ..::core::default::Default::default()
                }
                .into()
            }
        }
    };
}

#[cfg(not(feature = "schemars"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __typed_id_schemars {
    ($name:ident) => {};
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use uuid::Uuid;

    use crate::typed_uuid::{parse_external_id, wire, TypeTag};

    crate::typed_id!(WidgetId, "widget");
    crate::typed_id!(GadgetId, "gadget");

    fn fixture() -> Uuid {
        Uuid::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8").expect("fixture")
    }

    #[test]
    fn wire_is_tag_and_simple_hex() {
        assert_eq!(
            WidgetId(fixture()).wire(),
            "widget_a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8"
        );
        assert_eq!(wire::<WidgetId>(fixture()), WidgetId(fixture()).wire());
        assert_eq!(
            serde_json::to_string(&WidgetId(fixture())).expect("json"),
            format!("\"{}\"", WidgetId(fixture()).wire())
        );
    }

    #[test]
    fn constructors_and_uuid_conversion() {
        assert_eq!(WidgetId::nil().0, Uuid::nil());
        assert_ne!(WidgetId::new_v4(), WidgetId::new_v4());
        assert_eq!(Uuid::from(WidgetId(fixture())), fixture());
        assert_eq!(WidgetId::tag(), "widget");
    }

    #[test]
    fn parse_external_id_accepts_typed_and_bare_and_rejects_other_tags() {
        let typed: WidgetId =
            parse_external_id("widget_a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8").expect("typed");
        let bare: WidgetId =
            parse_external_id("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8").expect("bare");
        assert_eq!(typed, bare);
        assert!(parse_external_id::<GadgetId>("widget_a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8").is_err());
    }

    #[cfg(feature = "sqlx")]
    #[test]
    fn sqlx_type_matches_uuid() {
        use crate::__sqlx::{postgres::PgHasArrayType, Postgres, Type};
        assert_eq!(
            <WidgetId as Type<Postgres>>::type_info(),
            <Uuid as Type<Postgres>>::type_info()
        );
        assert_eq!(
            <WidgetId as PgHasArrayType>::array_type_info(),
            <Uuid as PgHasArrayType>::array_type_info()
        );
        assert!(<WidgetId as Type<Postgres>>::compatible(
            &<Uuid as Type<Postgres>>::type_info()
        ));
    }

    #[cfg(feature = "schemars")]
    #[test]
    fn json_schema_is_typed_uuid_string() {
        let schema = serde_json::to_value(crate::__schemars::schema_for!(WidgetId)).expect("json");
        assert_eq!(schema["type"], "string");
        assert_eq!(schema["format"], "typed-uuid");
        assert_eq!(schema["title"], "WidgetId");
    }
}

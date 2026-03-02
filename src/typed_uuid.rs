use axum::{
    extract::{rejection::PathRejection, FromRequestParts, Path},
    http::request::Parts,
};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

pub trait TypeTag {
    fn tag() -> &'static str;
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypedUuid<T>
where
    T: TypeTag,
{
    pub uuid: uuid::Uuid,
    _marker: std::marker::PhantomData<T>,
}

impl<T> TypedUuid<T>
where
    T: TypeTag,
{
    pub fn new(uuid: uuid::Uuid) -> Self {
        Self {
            uuid,
            _marker: std::marker::PhantomData,
        }
    }

    pub fn from_str(s: &str) -> Result<Self, uuid::Error> {
        let typed_segment = s
            .strip_prefix(T::tag())
            .and_then(|rest| rest.strip_prefix('_'));
        let uuid_str = typed_segment.unwrap_or(s);
        let uuid = uuid::Uuid::parse_str(uuid_str)?;
        Ok(Self::new(uuid))
    }

    pub fn to_string(&self) -> String {
        format!("{}_{}", T::tag(), self.uuid.simple().to_string())
    }
}

impl<T> Serialize for TypedUuid<T>
where
    T: TypeTag,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de, T> Deserialize<'de> for TypedUuid<T>
where
    T: TypeTag,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = String::deserialize(deserializer)?;
        Self::from_str(&input).map_err(de::Error::custom)
    }
}

impl<S, T> FromRequestParts<S> for TypedUuid<T>
where
    S: Send + Sync,
    T: TypeTag + Send,
{
    type Rejection = PathRejection;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Path(value) = Path::<Self>::from_request_parts(parts, state).await?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        str::FromStr,
        sync::Arc,
        task::{Context, Poll, Wake, Waker},
    };

    use axum::{
        extract::{rejection::PathRejection, FromRequestParts},
        http::Request,
    };
    use uuid::Uuid;

    use super::{TypeTag, TypedUuid};

    #[derive(Debug)]
    struct TaskId(pub Uuid);

    impl TypeTag for TaskId {
        fn tag() -> &'static str {
            "task"
        }
    }

    impl From<TypedUuid<TaskId>> for TaskId {
        fn from(value: TypedUuid<TaskId>) -> Self {
            Self(value.uuid)
        }
    }

    fn fixture_uuid() -> Uuid {
        Uuid::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8").expect("fixture uuid should parse")
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker: Waker = Waker::from(Arc::new(NoopWake));
        let mut context = Context::from_waker(&waker);
        let mut future = Box::pin(future);

        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(value) => return value,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }

    #[test]
    fn from_str_accepts_tagged_uuid() {
        let expected = fixture_uuid();
        let tagged = format!("task_{}", expected.simple());
        let parsed = TypedUuid::<TaskId>::from_str(&tagged).expect("typed uuid should parse");

        assert_eq!(parsed.uuid, expected);
    }

    #[test]
    fn from_str_falls_back_to_untyped_uuid() {
        let expected = fixture_uuid();
        let parsed = TypedUuid::<TaskId>::from_str("a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8")
            .expect("untagged uuid should parse");

        assert_eq!(parsed.uuid, expected);
    }

    #[test]
    fn serde_serializes_with_tag_and_deserializes_with_from_str() {
        let expected = fixture_uuid();
        let typed = TypedUuid::<TaskId>::new(expected);

        let json = serde_json::to_string(&typed).expect("serialization should succeed");
        assert_eq!(
            json,
            format!("\"task_{}\"", expected.simple()),
            "serialization should use typed string output"
        );

        let roundtrip: TypedUuid<TaskId> =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(roundtrip.uuid, expected);
    }

    #[test]
    fn serde_deserializes_untyped_uuid() {
        let typed: TypedUuid<TaskId> =
            serde_json::from_str("\"a1a2a3a4-b1b2-c1c2-d1d2-d3d4d5d6d7d8\"")
                .expect("untyped uuid should deserialize");

        assert_eq!(typed.uuid, fixture_uuid());
    }

    #[test]
    fn chain_from_typed_uuid_to_task_id() {
        let tagged = "task_a1a2a3a4b1b2c1c2d1d2d3d4d5d6d7d8";

        let task_id: TaskId = TypedUuid::<TaskId>::from_str(tagged)
            .expect("typed uuid should parse")
            .into();

        assert_eq!(task_id.0, fixture_uuid());
    }

    #[test]
    fn extractor_impl_exists_for_typed_uuid() {
        fn assert_from_request_parts_impl<T>()
        where
            T: TypeTag + Send,
            TypedUuid<T>: FromRequestParts<()>,
        {
        }

        assert_from_request_parts_impl::<TaskId>();
    }

    #[test]
    fn extractor_uses_axum_path_rejection_contract() {
        let request = Request::builder()
            .uri("/tasks/anything")
            .body(())
            .expect("request should build");
        let (mut parts, _) = request.into_parts();

        let rejection = block_on(TypedUuid::<TaskId>::from_request_parts(&mut parts, &()))
            .expect_err("missing path params should reject");

        assert!(
            matches!(rejection, PathRejection::MissingPathParams(_)),
            "extractor should forward axum Path rejection behavior"
        );
    }
}

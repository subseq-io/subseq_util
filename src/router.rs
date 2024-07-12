use anymap::{Map, any::Any};
use std::sync::{Arc, Mutex};
use tokio::sync::{broadcast, mpsc};

pub const ROUTER_MESSAGE_LIMIT: usize = 1024;
type AnyMap = Map<dyn Any + Send + Sync>;

/// Stores handles to channels for better management of pipe ends.
///
/// Everything is typed by the struct being sent through the channel, so use
/// custom types to clarify the rx/tx relationship.
#[derive(Clone)]
pub struct ChannelRouter {
    broadcast_map: Arc<Mutex<AnyMap>>,
    mpsc_map: Arc<Mutex<AnyMap>>,
}

impl Default for ChannelRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[deprecated(
    since = "0.5.0",
    note = "Use the `ChannelRouter` struct instead of the `Router` struct."
)]
pub type Router = ChannelRouter;

impl ChannelRouter {
    pub fn new() -> Self {
        Self {
            broadcast_map: Arc::new(Mutex::new(AnyMap::new())),
            mpsc_map: Arc::new(Mutex::new(AnyMap::new())),
        }
    }

    pub fn subscribe<M: Send + Sync + Clone + 'static>(&self) -> broadcast::Receiver<M> {
        self.announce().subscribe()
    }

    pub fn announce<M: Send + Sync + Clone + 'static>(&self) -> broadcast::Sender<M> {
        self.broadcast_map
            .lock()
            .unwrap()
            .entry::<broadcast::Sender<M>>()
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(ROUTER_MESSAGE_LIMIT);
                tx
            })
            .clone()
    }

    pub fn create_channel<M: Send + Sync + 'static>(&mut self) -> mpsc::Receiver<M> {
        let (tx, rx) = mpsc::channel(ROUTER_MESSAGE_LIMIT);
        self.mpsc_map.lock().unwrap().insert::<mpsc::Sender<M>>(tx);
        rx
    }

    pub fn get_address<M: Send + Sync + 'static>(&self) -> Option<mpsc::Sender<M>> {
        self.mpsc_map
            .lock()
            .unwrap()
            .get::<mpsc::Sender<M>>()
            .cloned()
    }

    pub fn create_unbounded_channel<M: Send + Sync + 'static>(
        &mut self,
    ) -> mpsc::UnboundedReceiver<M> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.mpsc_map
            .lock()
            .unwrap()
            .insert::<mpsc::UnboundedSender<M>>(tx);
        rx
    }

    pub fn get_unbounded_address<M: Send + Sync + 'static>(
        &self,
    ) -> Option<mpsc::UnboundedSender<M>> {
        self.mpsc_map
            .lock()
            .unwrap()
            .get::<mpsc::UnboundedSender<M>>()
            .cloned()
    }
}

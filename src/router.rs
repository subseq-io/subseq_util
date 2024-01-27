use anymap::AnyMap;
use tokio::sync::{broadcast, mpsc};

pub const ROUTER_MESSAGE_LIMIT: usize = 1024;

/// Stores handles to channels for better management of pipe ends.
///
/// Everything is typed by the struct being sent through the channel, so use
/// custom types to clarify the rx/tx relationship.
pub struct Router {
    broadcast_map: AnyMap,
    mpsc_map: AnyMap
}

impl Router {
    pub fn new() -> Self {
        Self { broadcast_map: AnyMap::new(), mpsc_map: AnyMap::new() }
    }

    pub fn subscribe<M: Send + Sync + Clone + 'static>(&mut self) -> broadcast::Receiver<M> {
        self.announce().subscribe()
    }

    pub fn announce<M: Send + Sync + Clone + 'static>(&mut self) -> broadcast::Sender<M> {
        self.broadcast_map
            .entry::<broadcast::Sender<M>>()
            .or_insert_with(|| {
                let (tx, _) = broadcast::channel(ROUTER_MESSAGE_LIMIT);
                tx
            })
            .clone()
    }

    pub fn create_channel<M: Send + Sync + 'static>(&mut self) -> mpsc::Receiver<M> {
        let (tx, rx) = mpsc::channel(ROUTER_MESSAGE_LIMIT);
        self.mpsc_map.insert::<mpsc::Sender<M>>(tx);
        rx
    }

    pub fn get_address<M: Send + Sync + 'static>(&self) -> Option<&mpsc::Sender<M>> {
        self.mpsc_map.get::<mpsc::Sender<M>>()
    }

    pub fn create_unbounded_channel<M: Send + Sync + 'static>(&mut self) -> mpsc::UnboundedReceiver<M> {
        let (tx, rx) = mpsc::unbounded_channel();
        self.mpsc_map.insert::<mpsc::UnboundedSender<M>>(tx);
        rx
    }

    pub fn get_unbounded_address<M: Send + Sync + 'static>(&self) -> Option<&mpsc::UnboundedSender<M>> {
        self.mpsc_map.get::<mpsc::UnboundedSender<M>>()
    }
}

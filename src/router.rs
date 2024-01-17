use anymap::AnyMap;
use tokio::sync::{broadcast, mpsc};

pub const ROUTER_MESSAGE_SIZE: usize = 1024;

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
                let (tx, _) = broadcast::channel(ROUTER_MESSAGE_SIZE);
                tx
            })
            .clone()
    }

    pub fn create_channel<M: Send + Sync + 'static>(&mut self) -> mpsc::Receiver<M> {
        let (tx, rx) = mpsc::channel(ROUTER_MESSAGE_SIZE);
        self.mpsc_map.insert::<mpsc::Sender<M>>(tx);
        rx
    }

    pub fn get_address<M: Send + Sync + 'static>(&self) -> Option<&mpsc::Sender<M>> {
        self.mpsc_map.get::<mpsc::Sender<M>>()
    }
}
